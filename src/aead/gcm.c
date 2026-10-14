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

#if defined(__aarch64__)
#include <arm_neon.h>

/* NEON-native 128-bit bit reversal (no NEON↔ARM transfers).
 * Converts GHASH reflected order to PMULL natural order. */
__attribute__((target("crypto"))) static inline uint64x2_t
bitrev128_neon(uint64x2_t v) {
    uint64x2_t m1 = vdupq_n_u64(0x5555555555555555ULL);
    uint64x2_t m2 = vdupq_n_u64(0x3333333333333333ULL);
    uint64x2_t m3 = vdupq_n_u64(0x0F0F0F0F0F0F0F0FULL);
    /* Reverse bits within each byte (3 shift-mask rounds). */
    v = vorrq_u64(vshlq_n_u64(vandq_u64(v, m1), 1), vandq_u64(vshrq_n_u64(v, 1), m1));
    v = vorrq_u64(vshlq_n_u64(vandq_u64(v, m2), 2), vandq_u64(vshrq_n_u64(v, 2), m2));
    v = vorrq_u64(vshlq_n_u64(vandq_u64(v, m3), 4), vandq_u64(vshrq_n_u64(v, 4), m3));
    /* Reverse bytes + swap halves = full 128-bit reversal. */
    uint8x16_t vb = vreinterpretq_u8_u64(v);
    vb = vrev64q_u8(vb);
    vb = vextq_u8(vb, vb, 8);
    return vreinterpretq_u64_u8(vb);
}

/* Load a GHASH block (big-endian bytes) and convert to natural PMULL order. */
__attribute__((target("crypto"))) static inline uint64x2_t nat_load(u8 const* p) {
    uint8x16_t v = vld1q_u8(p);
    v = vrev64q_u8(v);
    v = vextq_u8(v, v, 8);
    return bitrev128_neon(vreinterpretq_u64_u8(v));
}

/* Store natural order result back to GHASH big-endian bytes. */
__attribute__((target("crypto"))) static inline void nat_store(u8* p, uint64x2_t v) {
    uint64x2_t rv = bitrev128_neon(v);
    uint8x16_t vb = vreinterpretq_u8_u64(rv);
    vb = vextq_u8(vb, vb, 8);
    vb = vrev64q_u8(vb);
    vst1q_u8(p, vb);
}

/* 128×128 carry-less multiplication (Karatsuba, 3 PMULLs).
 * Output: 256-bit product as (lo, hi). */
__attribute__((target("crypto"))) static inline void
pmull_128(uint64x2_t a, uint64x2_t b, uint64x2_t* lo, uint64x2_t* hi) {
    uint64_t a0 = vgetq_lane_u64(a, 0), a1 = vgetq_lane_u64(a, 1);
    uint64_t b0 = vgetq_lane_u64(b, 0), b1 = vgetq_lane_u64(b, 1);
    poly128_t pl = vmull_p64(a0, b0);
    poly128_t ph = vmull_p64(a1, b1);
    poly128_t pm = vmull_p64(a0 ^ a1, b0 ^ b1);
    uint64x2_t vl = vreinterpretq_u64_p128(pl);
    uint64x2_t vh = vreinterpretq_u64_p128(ph);
    uint64x2_t vm = vreinterpretq_u64_p128(pm);
    vm = veorq_u64(vm, vl);
    vm = veorq_u64(vm, vh);
    uint64_t d0 = vgetq_lane_u64(vl, 0);
    uint64_t d1 = vgetq_lane_u64(vl, 1) ^ vgetq_lane_u64(vm, 0);
    uint64_t d2 = vgetq_lane_u64(vh, 0) ^ vgetq_lane_u64(vm, 1);
    uint64_t d3 = vgetq_lane_u64(vh, 1);
    uint64x2_t r0 = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
    uint64x2_t r1 = vcombine_u64(vcreate_u64(d2), vcreate_u64(d3));
    *lo = r0;
    *hi = r1;
}

/* Reduce 256-bit product to 128 bits (natural order, R = 0x87). */
__attribute__((target("crypto"))) static inline uint64x2_t pmull_reduce(uint64x2_t lo,
                                                                        uint64x2_t hi) {
    uint64_t d0 = vgetq_lane_u64(lo, 0), d1 = vgetq_lane_u64(lo, 1);
    uint64_t d2 = vgetq_lane_u64(hi, 0), d3 = vgetq_lane_u64(hi, 1);
    { /* fold d3 */
        poly128_t t = vmull_p64(d3, 0x87);
        uint64x2_t vt = vreinterpretq_u64_p128(t);
        d1 ^= vgetq_lane_u64(vt, 0);
        d2 ^= vgetq_lane_u64(vt, 1);
    }
    { /* fold d2 */
        poly128_t t = vmull_p64(d2, 0x87);
        uint64x2_t vt = vreinterpretq_u64_p128(t);
        d0 ^= vgetq_lane_u64(vt, 0);
        d1 ^= vgetq_lane_u64(vt, 1);
    }
    return vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
}

/* Single gf128 multiply (for compatibility + H power computation). */
__attribute__((target("crypto"))) void gf128_mul_pmull(u8 const* a, u8 const* b,
                                                       u8* out) {
    uint64x2_t av = nat_load(a);
    uint64x2_t bv = nat_load(b);
    uint64x2_t lo, hi;
    pmull_128(av, bv, &lo, &hi);
    uint64x2_t result = pmull_reduce(lo, hi);
    nat_store(out, result);
}

#if defined(__aarch64__)
/* 4-block aggregated GHASH (the hot path).
 * Precomputed H^1..H^4 allow processing 4 blocks with 12 PMULLs
 * and a single reduction (vs 20 PMULLs for sequential). */
__attribute__((target("crypto"))) static void ghash_4blocks(CvmcryptGcm* g,
                                                            u8 const* data) {
    uint64x2_t h1 = vld1q_u64((uint64_t const*)g->H_nat[0]);
    uint64x2_t h2 = vld1q_u64((uint64_t const*)g->H_nat[1]);
    uint64x2_t h3 = vld1q_u64((uint64_t const*)g->H_nat[2]);
    uint64x2_t h4 = vld1q_u64((uint64_t const*)g->H_nat[3]);
    uint64x2_t x1 = nat_load(data);
    uint64x2_t x2 = nat_load(data + 16);
    uint64x2_t x3 = nat_load(data + 32);
    uint64x2_t x4 = nat_load(data + 48);
    uint64x2_t acc = vld1q_u64((uint64_t const*)g->X_nat);
    acc = veorq_u64(acc, x1);

    uint64x2_t lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4;
    pmull_128(acc, h4, &lo1, &hi1); /* (Y⊕X1)·H^4 */
    pmull_128(x2, h3, &lo2, &hi2);  /* X2·H^3 */
    pmull_128(x3, h2, &lo3, &hi3);  /* X3·H^2 */
    pmull_128(x4, h1, &lo4, &hi4);  /* X4·H^1 */

    uint64x2_t lo_s = veorq_u64(veorq_u64(lo1, lo2), veorq_u64(lo3, lo4));
    uint64x2_t hi_s = veorq_u64(veorq_u64(hi1, hi2), veorq_u64(hi3, hi4));

    uint64x2_t result = pmull_reduce(lo_s, hi_s);
    vst1q_u64((uint64_t*)g->X_nat, result);
}
#endif
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

#if defined(__aarch64__)
    /* Fast path: 4-block aggregated GHASH with precomputed H powers. */
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->buflen == 0 && len >= 64) {
        /* Sync X_nat from g->X before fast path (in case slow path ran first). */
        uint64x2_t xn = nat_load(g->X);
        vst1q_u64((uint64_t*)g->X_nat, xn);
        usize num4 = len / 64;
        for (usize i = 0; i < num4; i++) {
            ghash_4blocks(g, data);
            data += 64;
            len -= 64;
        }
        /* Always sync g->X from X_nat after fast path. */
        nat_store(g->X, vld1q_u64((uint64_t const*)g->X_nat));
    }
#endif

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
            /* Sync natural-order accumulator. */
#if defined(__aarch64__)
            if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
                uint64x2_t xn = nat_load(g->X);
                vst1q_u64((uint64_t*)g->X_nat, xn);
            }
#endif
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
    memset(g->X_nat, 0, 16);
    g->buflen = 0;
    g->aadlen = 0;
    g->ptlen = 0;

#if defined(__aarch64__)
    g->impl = CVMCRYPT_GCM_IMPL_PMULL;
#else
    g->impl = CVMCRYPT_GCM_IMPL_SCALAR;
#endif

#if defined(__aarch64__)
    /* Precompute H^1..H^4 in natural polynomial order for 4-block GHASH. */
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
        u8 hp2[16], hp3[16], hp4[16];
        gf128_mul_pmull(g->H, g->H, hp2); /* hp2 = H^2 */
        gf128_mul_pmull(hp2, g->H, hp3);  /* hp3 = H^3 */
        gf128_mul_pmull(hp2, hp2, hp4);   /* hp4 = H^4 */
        uint64x2_t h1v = nat_load(g->H);
        uint64x2_t h2v = nat_load(hp2);
        uint64x2_t h3v = nat_load(hp3);
        uint64x2_t h4v = nat_load(hp4);
        vst1q_u64((uint64_t*)g->H_nat[0], h1v);
        vst1q_u64((uint64_t*)g->H_nat[1], h2v);
        vst1q_u64((uint64_t*)g->H_nat[2], h3v);
        vst1q_u64((uint64_t*)g->H_nat[3], h4v);
    }
#endif

    return true;
}

/* Batched AES-CTR: encrypt 4 blocks in parallel.
 * Pre-computes 4 counters, AES-encrypts them simultaneously (pipelined),
 * then XORs with input. Amortizes counter increment over 4 blocks. */
__attribute__((target("crypto"))) static void gcm_crypt_4(CvmcryptGcm* g, u8 const* in,
                                                          u8* out) {
    /* Load AES round keys. */
    uint8x16_t rk[11];
    for (int r = 0; r <= 10; r++) {
        rk[r] = vld1q_u8((u8 const*)&g->aes.enc[4 * r]);
    }

    /* Generate 4 counters (ctr, ctr+1, ctr+2, ctr+3). */
    uint8x16_t c0 = vld1q_u8(g->counter);
    uint8x16_t c1 = c0, c2 = c0, c3 = c0;

    /* Increment last 32 bits (big-endian) for c1, c2, c3. */
    /* Use scalar: read last 4 bytes, add 1/2/3, write back. */
    {
        u32 be;
        memcpy(&be, g->counter + 12, 4);
        be = __builtin_bswap32(be); /* to host order */
        u32 b1 = __builtin_bswap32(be + 1);
        u32 b2 = __builtin_bswap32(be + 2);
        u32 b3 = __builtin_bswap32(be + 3);
        u32 b4 = __builtin_bswap32(be + 4);
        memcpy((u8*)&c1 + 12, &b1, 4);
        memcpy((u8*)&c2 + 12, &b2, 4);
        memcpy((u8*)&c3 + 12, &b3, 4);
        memcpy(g->counter + 12, &b4, 4); /* update for next batch */
    }

    /* AES-encrypt all 4 counters (interleaved for pipeline). */
    uint8x16_t s0 = c0, s1 = c1, s2 = c2, s3 = c3;
    for (int r = 0; r < 9; r++) {
        s0 = vaesmcq_u8(vaeseq_u8(s0, rk[r]));
        s1 = vaesmcq_u8(vaeseq_u8(s1, rk[r]));
        s2 = vaesmcq_u8(vaeseq_u8(s2, rk[r]));
        s3 = vaesmcq_u8(vaeseq_u8(s3, rk[r]));
    }
    s0 = veorq_u8(vaeseq_u8(s0, rk[9]), rk[10]);
    s1 = veorq_u8(vaeseq_u8(s1, rk[9]), rk[10]);
    s2 = veorq_u8(vaeseq_u8(s2, rk[9]), rk[10]);
    s3 = veorq_u8(vaeseq_u8(s3, rk[9]), rk[10]);

    /* XOR with input, store output. */
    uint8x16_t p0 = vld1q_u8(in);
    uint8x16_t p1 = vld1q_u8(in + 16);
    uint8x16_t p2 = vld1q_u8(in + 32);
    uint8x16_t p3 = vld1q_u8(in + 48);
    vst1q_u8(out, veorq_u8(p0, s0));
    vst1q_u8(out + 16, veorq_u8(p1, s1));
    vst1q_u8(out + 32, veorq_u8(p2, s2));
    vst1q_u8(out + 48, veorq_u8(p3, s3));
}

static void gcm_crypt(CvmcryptGcm* g, u8 const* in, usize len, u8* out) {
#if defined(__aarch64__)
    /* Fast path: 4 blocks with parallel AES (pipelined vaeseq). */
    while (len >= 64) {
        gcm_crypt_4(g, in, out);
        in += 64;
        out += 64;
        len -= 64;
    }
#endif
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
