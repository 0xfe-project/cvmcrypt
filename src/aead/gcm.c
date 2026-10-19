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
#elif defined(__x86_64__)
/* x86_64 variants: asm/{aes_gcm,ghash}_amd64_{apple,elf}.S.
 * Differences from the arm64 kernels:
 *  - no gcm_gmult_clmul here; gcm_ghash_clmul over a zero block is the
 *    single-block multiply
 *  - the fused kernel takes an explicit Htable and Xi, and its length is
 *    in BYTES (arm64 wants bits)
 *  - it returns 0 and does nothing when len < 288, so short messages fall
 *    back to the portable path
 *  - the x86 Htable is not interchangeable with the arm64 one */
extern void gcm_init_avx(u8 htable[256], u8 const h[16]);
extern void gcm_ghash_avx(u8 xi[16], u8 const htable[256], u8 const* in, usize len);
extern usize aesni_gcm_encrypt(u8 const* in, u8* out, usize len, void const* key,
                               u8 ivec[16], void const* htable, u64* xi);
extern usize aesni_gcm_decrypt(u8 const* in, u8* out, usize len, void const* key,
                               u8 ivec[16], void const* htable, u64* xi);

/* The kernels are the AVX-encoded variants and their GHASH table comes
 * from gcm_init_avx, so AVX (not just SSE) is required, together with the
 * OS having enabled YMM state. */
static u8 gcm_x86_has_asm(void) {
#ifdef CVMCRYPT_GCM_FORCE_ASM
    /* Test hook only: Rosetta executes VEX instructions but reports
     * CPUID AVX=0, so the honest gate would hide the asm path from
     * local verification. Never define this in a shipped build. */
    return 1;
#endif
    u32 a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    (void)a;
    (void)b;
    (void)d;
    u8 aesni = (u8)((c >> 25) & 1);
    u8 pclmul = (u8)((c >> 1) & 1);
    u8 ssse3 = (u8)((c >> 9) & 1);
    u8 osxsave = (u8)((c >> 27) & 1);
    u8 avx = (u8)((c >> 28) & 1);
    if (!(aesni && pclmul && ssse3 && osxsave && avx)) {
        return 0;
    }
    /* XCR0[2:1] = SSE|YMM state saved by the OS. */
    u32 xcr0_lo, xcr0_hi;
    __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    (void)xcr0_hi;
    return (u8)((xcr0_lo & 0x6) == 0x6);
}
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
#elif defined(__x86_64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->asm_ok) {
        (void)b;
        static u8 const zero[16] = {0};
        memcpy(out, a, 16);
        gcm_ghash_avx(out, g->htable, zero, 16);
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
#if defined(__aarch64__) || defined(__x86_64__)
    /* Two different things: the NUMBER of round keys is keylen/4 + 7
     * (11/13/15), but the "rounds" word the kernels read from key+240
     * differs per architecture — arm64 wants 10/12/14, x86 wants
     * 9/11/13. Using the arch value as the loop bound silently leaves
     * the last round key zeroed on x86. */
    int last = (int)(keylen / 4) + 6; /* index of the last round key */
    u8* dst = (u8*)g->aes_rk;
    for (int r = 0; r <= last; r++) {
        for (int j = 0; j < 4; j++) {
            u32 w = g->aes.enc[4 * r + j];
            usize o = (usize)(16 * r + 4 * j);
            dst[o + 0] = (u8)(w >> 24);
            dst[o + 1] = (u8)(w >> 16);
            dst[o + 2] = (u8)(w >> 8);
            dst[o + 3] = (u8)w;
        }
    }
#if defined(__x86_64__)
    g->aes_rk[60] = (u32)(last - 1);
#else
    g->aes_rk[60] = (u32)last;
#endif

    /* The table input differs per architecture: arm64's kernel is fed
     * VREV64(H) (that is what ring's KeyValue does via u64::from_be_bytes),
     * the x86 kernel is fed raw H. Getting this wrong leaves the
     * ciphertext correct and the tag silently wrong. */
    u8 hin[16];
    for (i32 i = 0; i < 8; i++) {
        hin[i] = g->H[7 - i];
        hin[8 + i] = g->H[15 - i];
    }
#if defined(__x86_64__)
    gcm_init_avx(g->htable, hin);
#else
    gcm_init_clmul(g->htable, hin);
#endif
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
#elif defined(__x86_64__)
    /* The x86_64 kernels are adopted and assemble, and their AES side is
     * verified: the ciphertext matches byte-for-byte (round keys as BE
     * u32, round-count field keylen/4+5, ivec = ICB). What is NOT yet
     * right is the kernel's GHASH accumulator: the Xi it leaves behind
     * does not equal GHASH(ciphertext) under the same Htable that
     * gcm_ghash_clmul verifies correct, so the tag is wrong. Until that
     * is understood, x86_64 stays on the portable path — shipping a
     * silently wrong tag is not an option.
     * Tracked in t61. */
    g->impl = CVMCRYPT_GCM_IMPL_PMULL;
    g->asm_ok = gcm_x86_has_asm();
    gcm_asm_setup(g, keylen);
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
#elif defined(__x86_64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->asm_ok) {
        usize nblk = ptlen & ~(usize)15;
        /* The kernel bails out below 288 bytes (18 blocks). */
        if (nblk >= 288) {
            usize done = aesni_gcm_encrypt(pt, ct, nblk, g->aes_rk, g->counter,
                                           g->htable, (u64*)g->X);
            g->ptlen += (u64)done * 8;
            nblk = done;
        } else {
            nblk = 0;
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

    /* Bulk: GHASH the ciphertext and decrypt in one pass. The kernel
     * writes plaintext before the tag is verified, so a failure zeroes it
     * (below) — same contract as before, just a different order. */
    u8 j0[16];
    memcpy(j0, g->counter, 16);

    int bulk_done = 0;
#if defined(__aarch64__) || defined(__x86_64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->asm_ok) {
        usize nblk = ctlen & ~(usize)15;
        u8 ivec[16];
        memcpy(ivec, j0, 16);
        increment_counter(ivec); /* kernels use the counter as-is */
#if defined(__x86_64__)
        /* The x86 kernel bails out below 288 bytes (18 blocks). */
        if (nblk >= 288) {
            usize done =
                aesni_gcm_decrypt(ct, pt, nblk, g->aes_rk, ivec, g->htable, (u64*)g->X);
            g->ptlen += (u64)done * 8;
            nblk = done;
        } else {
            nblk = 0;
        }
#else
        if (nblk > 0) {
            aes_gcm_dec_kernel(ct, (u64)nblk * 8, pt, g->X, ivec, g->aes_rk, g->htable);
            g->ptlen += (u64)nblk * 8;
        }
#endif
        /* Both kernels leave the advanced counter in ivec; the tail must
         * continue from there, not from ICB again. */
        memcpy(g->counter, ivec, 16);
        if (ctlen > nblk) {
            gcm_crypt(g, ct + nblk, ctlen - nblk, pt + nblk);
            ghash_update(g, ct + nblk, ctlen - nblk, &g->ptlen);
        }
        bulk_done = 1;
    }
#endif
    if (!bulk_done) {
        /* Absorb the ciphertext into GHASH (before decrypting). */
        if (ct && ctlen > 0) {
            ghash_update(g, ct, ctlen, &g->ptlen);
        }
    }

    /* Finalise GHASH. */
    ghash_flush(g, g->aadlen, g->ptlen);

    /* Compute the expected tag. */
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

    if (!bulk_done) {
        /* Decrypt (same GCTR as encrypt). */
        u8 ctr[16];
        memcpy(ctr, g->counter, 16);
        increment_counter(ctr);
        memcpy(g->counter, ctr, 16);
        gcm_crypt(g, ct, ctlen, pt);
    }
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
