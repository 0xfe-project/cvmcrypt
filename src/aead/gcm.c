/*
 * src/aead/gcm.c
 *
 * AES-GCM per NIST SP 800-38D. One-shot API: the TLS 1.3 use case
 * feeds the whole message at a time, so the incremental state machine
 * ltc carries is not needed here.
 *
 * GHASH multiplication in GF(2^128) (poly x^128+x^7+x^2+x+1):
 *   aarch64: PMULL/PMULL2 (dedicated instruction, cannot be expressed
 *            with compiler vector extensions)
 *   other:   scalar bit-by-bit shift-and-XOR
 */

#include "cvmcrypt/cvmcrypt.h"
#include "aead/gcm.h"

#include "base/mem.h"
#include "base/secure.h"

#if defined(__aarch64__)
#include <arm_neon.h>

/* Adopted from BoringSSL, vendored via ring 0.17.14 pregenerated/.
 * Sources: src/aead/asm/{aes_gcm,ghash}_arm64_{apple,elf}.S */
extern void gcm_init_clmul(u8 htable[256], u8 const h[16]);
extern void gcm_gmult_clmul(u8 xi[16], u8 const htable[256]);
extern void aes_gcm_enc_kernel(u8 const* in, u64 in_len, u8* out, u8* xi, u8* ivec,
                               u32 const* key, u8 const* htable);
extern void aes_gcm_dec_kernel(u8 const* in, u64 in_len, u8* out, u8* xi, u8* ivec,
                               u32 const* key, u8 const* htable);
#endif

/* ------------------------------------------------------------------ */
/* GF(2^128) multiplication                                             */
/* ------------------------------------------------------------------ */

/* Scalar GHASH multiply: right-to-left shift-and-XOR.
 * Operates on 16-byte arrays in GCM bit order (MSB first). */
void gf128_mul_scalar(u8 const* a, u8 const* b, u8* out) {
    /* Z = 0, V = B */
    u8 Z[16] = {0};
    u8 V[16];
    memcpy(V, b, 16);

    for (usize i = 0; i < 128; i++) {
        /* If bit i of A is set, Z ^= V */
        if ((a[i / 8] >> (7 - (i % 8))) & 1) {
            for (usize j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }
        /* V = V · x (right shift with reduction) */
        u8 lsb = V[15] & 1;
        for (usize j = 15; j > 0; j--) {
            V[j] = (V[j] >> 1) | (V[j - 1] << 7);
        }
        V[0] >>= 1;
        if (lsb) {
            /* Reduce by x^128 + x^7 + x^2 + x + 1 → XOR with 0x87 */
            V[0] ^= 0xE1;
        }
    }
    memcpy(out, Z, 16);
}

/* Single-block GHASH multiply by H. The arm64 path goes through the
 * adopted BoringSSL gmult (~10 ns); the portable path below is the
 * reference oracle (bit-by-bit, ~150 ns). */
static void gf128_mul(CvmcryptGcm* g, u8 const* a, u8 const* b, u8* out) {
#if defined(__aarch64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
        (void)b; /* GCM only ever multiplies by g->H */
        memcpy(out, a, 16);
        gcm_gmult_clmul(out, g->htable);
        return;
    }
#else
    (void)g;
    (void)b;
#endif
    gf128_mul_scalar(a, b, out);
}

/* ------------------------------------------------------------------ */
/* GCM internals                                                       */
/* ------------------------------------------------------------------ */

static void increment_counter(u8* counter) {
    /* Increment the last 32 bits (big-endian), per SP 800-38D §6.2. */
    for (i32 i = 15; i >= 12; i--) {
        if (++counter[i] != 0)
            break;
    }
}

static void ghash_update(CvmcryptGcm* g, u8 const* data, usize len, u64* total_bits) {
    /* Absorb data into the GHASH accumulator, buffering partial blocks. */
    *total_bits += len * 8;

    while (len > 0) {
        usize n = 16 - g->buflen;
        if (n > len)
            n = len;
        memcpy(g->buf + g->buflen, data, n);
        g->buflen += n;
        data += n;
        len -= n;

        if (g->buflen == 16) {
            /* X = (X XOR buf) · H */
            for (usize i = 0; i < 16; i++) {
                g->X[i] ^= g->buf[i];
            }
            gf128_mul(g, g->X, g->H, g->X);
            /* Sync reflected accumulator for the fast path. */
            g->buflen = 0;
        }
    }
}

static void ghash_flush(CvmcryptGcm* g, u64 aad_bits, u64 pt_bits) {
    /* Pad the last partial block, then absorb the length block. */
    if (g->buflen > 0) {
        memset(g->buf + g->buflen, 0, 16 - g->buflen);
        for (usize i = 0; i < 16; i++) {
            g->X[i] ^= g->buf[i];
        }
        gf128_mul(g, g->X, g->H, g->X);
        g->buflen = 0;
    }

    /* Length block: [len(A)]_64 || [len(C)]_64 */
    u8 lenblk[16];
    for (usize i = 0; i < 8; i++) {
        lenblk[i] = (u8)(aad_bits >> (56 - 8 * i));
        lenblk[8 + i] = (u8)(pt_bits >> (56 - 8 * i));
    }
    for (usize i = 0; i < 16; i++) {
        g->X[i] ^= lenblk[i];
    }
    gf128_mul(g, g->X, g->H, g->X);
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

/* Build BoringSSL's AES_KEY layout + GHASH table once per key.
 * The table must come from VREV64(H): ring passes H as [u64; 2] via
 * u64::from_be_bytes, i.e. a byte swap within each 8-byte half. Feeding
 * raw H yields a table that silently produces wrong GHASH while the
 * ciphertext stays correct. */
static void gcm_asm_setup(CvmcryptGcm* g, usize keylen) {
#if defined(__aarch64__)
    /* AES-128/192/256 -> 10/12/14 rounds = keylen/4 + 6. */
    int rounds = (int)(keylen / 4) + 6;
    u8* dst = (u8*)g->aes_rk;
    for (int r = 0; r <= rounds; r++) {
        for (int j = 0; j < 4; j++) {
            u32 w = g->aes.enc[4 * r + j];
            usize o = (usize)(16 * r + 4 * j);
            dst[o + 0] = (u8)(w >> 24);
            dst[o + 1] = (u8)(w >> 16);
            dst[o + 2] = (u8)(w >> 8);
            dst[o + 3] = (u8)w;
        }
    }
    g->aes_rk[60] = (u32)rounds;

    u8 hrev[16];
    vst1q_u8(hrev, vrev64q_u8(vld1q_u8(g->H)));
    gcm_init_clmul(g->htable, hrev);
#else
    (void)g;
#endif
}

/* Key-derived state. Built once per key; the message state is reset per
 * message by gcm_msg_reset(). This split is what lets a TLS connection
 * pay the key schedule once instead of once per record. */
static bool gcm_key_setup(CvmcryptGcm* g, u8 const* key, usize keylen) {
    if (!cvmcrypt_aes_setup(&g->aes, key, keylen)) {
        return false;
    }

    /* H = AES_K(0^128) */
    u8 zero[16] = {0};
    cvmcrypt_aes_encrypt_block(&g->aes, zero, g->H);

#if defined(__aarch64__)
    g->impl = CVMCRYPT_GCM_IMPL_PMULL;
    gcm_asm_setup(g, keylen);
    g->asm_ok = true; /* AES-128/192/256 all verified */
#else
    g->impl = CVMCRYPT_GCM_IMPL_SCALAR;
#endif
    return true;
}

/* Per-message state. */
static void gcm_msg_reset(CvmcryptGcm* g, u8 const iv[12]) {
    /* J0 = IV || 0^31 || 1 (for 96-bit IV, the TLS 1.3 case) */
    memset(g->counter, 0, 16);
    memcpy(g->counter, iv, 12);
    g->counter[15] = 1;

    memset(g->X, 0, 16);
    g->buflen = 0;
    g->aadlen = 0;
    g->ptlen = 0;
}

static bool gcm_setup(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12]) {
    if (!gcm_key_setup(g, key, keylen)) {
        return false;
    }
    gcm_msg_reset(g, iv);
    return true;
}

static void gcm_crypt(CvmcryptGcm* g, u8 const* in, usize len, u8* out) {
    /* Per-block GCTR: the arm64 bulk path is the adopted aesv8-gcm kernel,
     * so this covers only the tail and the AES-192/256 fallback. */
    /* GCTR per SP 800-38D: the first block uses the counter as-is
     * (already set to ICB), subsequent blocks increment. */
    u8 block[16];
    while (len >= 16) {
        cvmcrypt_aes_encrypt_block(&g->aes, g->counter, block);
        for (usize i = 0; i < 16; i++) {
            out[i] = in[i] ^ block[i];
        }
        increment_counter(g->counter);
        in += 16;
        out += 16;
        len -= 16;
    }
    if (len > 0) {
        cvmcrypt_aes_encrypt_block(&g->aes, g->counter, block);
        for (usize i = 0; i < len; i++) {
            out[i] = in[i] ^ block[i];
        }
    }
}

/* Message body: assumes key-derived state is in place and the message
 * state has been reset. */
static void gcm_seal_body(CvmcryptGcm* g, u8 const* aad, usize aadlen, u8 const* pt,
                          usize ptlen, u8* ct, u8 tag[16]) {
    /* Absorb AAD. */
    if (aad && aadlen > 0) {
        ghash_update(g, aad, aadlen, &g->aadlen);
    }

    /* Pad AAD to block boundary before ciphertext. */
    if (g->buflen > 0) {
        memset(g->buf + g->buflen, 0, 16 - g->buflen);
        for (usize i = 0; i < 16; i++) {
            g->X[i] ^= g->buf[i];
        }
        gf128_mul(g, g->X, g->H, g->X);
        g->buflen = 0;
    }

    /* Save J0 for the tag. */
    u8 j0[16];
    memcpy(j0, g->counter, 16);

    /* Set counter to ICB = inc32(J0) for GCTR. gcm_crypt uses the
     * counter as-is for the first block (no pre-increment). */
    increment_counter(g->counter);

    /* Bulk: the adopted aesv8-gcm kernel does AES-CTR + GHASH in one pass.
     * in_len is in BITS and only whole blocks are handled; the tail goes
     * through the portable path. */
#if defined(__aarch64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->asm_ok) {
        usize nblk = ptlen & ~(usize)15;
        if (nblk > 0) {
            aes_gcm_enc_kernel(pt, (u64)nblk * 8, ct, g->X, g->counter, g->aes_rk,
                               g->htable);
            g->ptlen += (u64)nblk * 8;
        }
        if (ptlen > nblk) {
            gcm_crypt(g, pt + nblk, ptlen - nblk, ct + nblk);
            ghash_update(g, ct + nblk, ptlen - nblk, &g->ptlen);
        }
    } else
#endif
    {
        gcm_crypt(g, pt, ptlen, ct);
        if (ct && ptlen > 0) {
            ghash_update(g, ct, ptlen, &g->ptlen);
        }
    }

    /* Finalise. */
    ghash_flush(g, g->aadlen, g->ptlen);

    /* Tag = AES_K(J0) XOR S. */
    u8 ekJ0[16];
    cvmcrypt_aes_encrypt_block(&g->aes, j0, ekJ0);
    for (usize i = 0; i < 16; i++) {
        tag[i] = ekJ0[i] ^ g->X[i];
    }
}

bool cvmcrypt_gcm_setup(CvmcryptGcm* g, u8 const* key, usize keylen) {
    return gcm_key_setup(g, key, keylen);
}

bool cvmcrypt_gcm_seal(CvmcryptGcm* g, u8 const iv[12], u8 const* aad, usize aadlen,
                       u8 const* pt, usize ptlen, u8* ct, u8 tag[16]) {
    gcm_msg_reset(g, iv);
    gcm_seal_body(g, aad, aadlen, pt, ptlen, ct, tag);
    return true;
}

void cvmcrypt_gcm_clear(CvmcryptGcm* g) {
    volatile u8* p = (volatile u8*)g;
    for (usize i = 0; i < sizeof(*g); i++) {
        p[i] = 0;
    }
}

bool cvmcrypt_gcm_encrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* pt, usize ptlen,
                          u8* ct, u8 tag[16]) {
    if (!gcm_setup(g, key, keylen, iv)) {
        return false;
    }
    gcm_seal_body(g, aad, aadlen, pt, ptlen, ct, tag);
    memset(g, 0, sizeof(*g));
    return true;
}

/* Message body: assumes key-derived state is in place and the message
 * state has been reset. */
static bool gcm_open_body(CvmcryptGcm* g, u8 const* aad, usize aadlen, u8 const* ct,
                          usize ctlen, u8* pt, u8 const tag[16]) {
    /* Absorb AAD. */
    if (aad && aadlen > 0) {
        ghash_update(g, aad, aadlen, &g->aadlen);
    }

    /* Pad AAD to block boundary before ciphertext (per SP 800-38D:
     * GHASH input = A || 0^v || C || 0^u || lengths). */
    if (g->buflen > 0) {
        memset(g->buf + g->buflen, 0, 16 - g->buflen);
        for (usize i = 0; i < 16; i++) {
            g->X[i] ^= g->buf[i];
        }
        gf128_mul(g, g->X, g->H, g->X);
        g->buflen = 0;
    }

    /* Absorb the ciphertext into GHASH (before decrypting). */
    if (ct && ctlen > 0) {
        ghash_update(g, ct, ctlen, &g->ptlen);
    }

    /* Finalise GHASH. */
    ghash_flush(g, g->aadlen, g->ptlen);

    /* Compute the expected tag. */
    u8 j0[16];
    memcpy(j0, g->counter, 16);
    u8 ekJ0[16];
    cvmcrypt_aes_encrypt_block(&g->aes, j0, ekJ0);
    u8 expected[16];
    for (usize i = 0; i < 16; i++) {
        expected[i] = ekJ0[i] ^ g->X[i];
    }

    /* Constant-time tag comparison. */
    if (!cvmcrypt_ct_eq(expected, tag, 16)) {
        if (pt && ctlen > 0) {
            memset(pt, 0, ctlen);
        }
        return false;
    }

    /* Decrypt (same GCTR as encrypt). */
    u8 ctr[16];
    memcpy(ctr, g->counter, 16);
    increment_counter(ctr);

    memcpy(g->counter, ctr, 16);
    gcm_crypt(g, ct, ctlen, pt);
    return true;
}

bool cvmcrypt_gcm_open(CvmcryptGcm* g, u8 const iv[12], u8 const* aad, usize aadlen,
                       u8 const* ct, usize ctlen, u8* pt, u8 const tag[16]) {
    gcm_msg_reset(g, iv);
    return gcm_open_body(g, aad, aadlen, ct, ctlen, pt, tag);
}

bool cvmcrypt_gcm_decrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* ct, usize ctlen,
                          u8* pt, u8 const tag[16]) {
    if (!gcm_setup(g, key, keylen, iv)) {
        return false;
    }
    bool ok = gcm_open_body(g, aad, aadlen, ct, ctlen, pt, tag);
    memset(g, 0, sizeof(*g));
    return ok;
}
