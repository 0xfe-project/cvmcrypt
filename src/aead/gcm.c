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

/* ------------------------------------------------------------------ */
/* GF(2^128) multiplication                                             */
/* ------------------------------------------------------------------ */

/* Scalar GHASH multiply: right-to-left shift-and-XOR.
 * Operates on 16-byte arrays in GCM bit order (MSB first). */
static void gf128_mul_scalar(u8 const* a, u8 const* b, u8* out) {
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

#if defined(__aarch64__)
#include <arm_neon.h>

/* GHASH multiply using PMULL, following the algorithm in
 * "Intel Carry-Less Multiplication Instruction and Its Usage for
 * Computing the GCM Mode" (Rev 2.0), Section 6.1, adapted for ARM. */
__attribute__((target("crypto"))) static void gf128_mul_pmull(u8 const* a, u8 const* b,
                                                              u8* out) {
    /* PMULL path not yet implemented — the 256→128 bit reduction is
     * subtle. Fall back to scalar; PMULL will replace this for throughput. */
    gf128_mul_scalar(a, b, out);
}
#endif

/* Dispatch: use PMULL on aarch64, scalar elsewhere. */
static void gf128_mul(u8 const* a, u8 const* b, u8* out, u8 impl) {
#if defined(__aarch64__)
    if (impl == CVMCRYPT_GCM_IMPL_PMULL) {
        gf128_mul_pmull(a, b, out);
        return;
    }
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
            gf128_mul(g->X, g->H, g->X, g->impl);
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
        gf128_mul(g->X, g->H, g->X, g->impl);
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
    gf128_mul(g->X, g->H, g->X, g->impl);
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

static bool gcm_setup(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12]) {
    if (!cvmcrypt_aes_setup(&g->aes, key, keylen)) {
        return false;
    }

    /* H = AES_K(0^128) */
    u8 zero[16] = {0};
    cvmcrypt_aes_encrypt_block(&g->aes, zero, g->H);

    /* J0 = IV || 0^31 || 1 (for 96-bit IV, the TLS 1.3 case) */
    memset(g->counter, 0, 16);
    memcpy(g->counter, iv, 12);
    g->counter[15] = 1;

    /* Reset the accumulator. */
    memset(g->X, 0, 16);
    g->buflen = 0;
    g->aadlen = 0;
    g->ptlen = 0;

#if defined(__aarch64__)
    g->impl = CVMCRYPT_GCM_IMPL_PMULL;
#else
    g->impl = CVMCRYPT_GCM_IMPL_SCALAR;
#endif
    return true;
}

static void gcm_crypt(CvmcryptGcm* g, u8 const* in, usize len, u8* out) {
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

bool cvmcrypt_gcm_encrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* pt, usize ptlen,
                          u8* ct, u8 tag[16]) {
    if (!gcm_setup(g, key, keylen, iv)) {
        return false;
    }

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
        gf128_mul(g->X, g->H, g->X, g->impl);
        g->buflen = 0;
    }

    /* Save J0 for the tag. */
    u8 j0[16];
    memcpy(j0, g->counter, 16);

    /* Set counter to ICB = inc32(J0) for GCTR. gcm_crypt uses the
     * counter as-is for the first block (no pre-increment). */
    increment_counter(g->counter);

    /* Encrypt. */
    gcm_crypt(g, pt, ptlen, ct);

    /* Absorb the ciphertext into GHASH. */
    if (ct && ptlen > 0) {
        ghash_update(g, ct, ptlen, &g->ptlen);
    }

    /* Finalise. */
    ghash_flush(g, g->aadlen, g->ptlen);

    /* Tag = AES_K(J0) XOR S. */
    u8 ekJ0[16];
    cvmcrypt_aes_encrypt_block(&g->aes, j0, ekJ0);
    for (usize i = 0; i < 16; i++) {
        tag[i] = ekJ0[i] ^ g->X[i];
    }

    memset(g, 0, sizeof(*g));
    return true;
}

bool cvmcrypt_gcm_decrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* ct, usize ctlen,
                          u8* pt, u8 const tag[16]) {
    if (!gcm_setup(g, key, keylen, iv)) {
        return false;
    }

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
        gf128_mul(g->X, g->H, g->X, g->impl);
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
        memset(g, 0, sizeof(*g));
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

    memset(g, 0, sizeof(*g));
    return true;
}
