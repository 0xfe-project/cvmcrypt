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

/* ==================================================================
 * Reflected-domain GHASH — exact translation of Go's gcm_arm64.s.
 *
 * Key insight (verified by disassembly): Go's VEXT $8, A, B, D
 * compiles to EXT D, B, A, #8, i.e. D = B[8:15] || A[0:7].
 * The SOURCE OPERANDS ARE REVERSED from ARM64 EXT convention.
 *
 * The reflected domain uses VREV64 (byte swap within each u64,
 * NO half-swap) to transform data. No bit reversal needed at all.
 * ================================================================== */

/* swap64: exchange the two 64-bit lanes */
__attribute__((target("crypto"))) static inline uint64x2_t swap64(uint64x2_t v) {
    return vreinterpretq_u64_u8(
        vextq_u8(vreinterpretq_u8_u64(v), vreinterpretq_u8_u64(v), 8));
}

/* VREV64: byte swap within each 8-byte group (the data transform) */
__attribute__((target("crypto"))) static inline uint64x2_t vrev64_ld(u8 const* p) {
    return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p)));
}

/* mulRound: accumulate one block's product into (acc0, acc1, accm).
 * t1 = H^i (from table), t2 = H^i ⊕ swap(H^i) (Karatsuba precompute).
 * x must already be VREV64'd and XORed with accumulator. */
__attribute__((target("crypto"))) static inline void
mul_round(uint64x2_t x, uint64x2_t t1, uint64x2_t t2, uint64x2_t* acc0,
          uint64x2_t* acc1, uint64x2_t* accm) {
    uint64x2_t t0 = veorq_u64(x, swap64(x)); /* Karatsuba mid */
    *acc1 = veorq_u64(
        *acc1, vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x, 0),
                                                (poly64_t)vgetq_lane_u64(t1, 0))));
    *acc0 = veorq_u64(
        *acc0, vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x, 1),
                                                (poly64_t)vgetq_lane_u64(t1, 1))));
    *accm = veorq_u64(
        *accm, vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(t0, 0),
                                                (poly64_t)vgetq_lane_u64(t2, 0))));
}

/* reduce: fold the 256-bit accumulator to 128 bits.
 * Result in acc0. Follows Go's reduce() macro exactly. */
__attribute__((target("crypto"))) static inline void
reduce_go(uint64x2_t* acc0_p, uint64x2_t* acc1_p, uint64x2_t accm) {
    uint64x2_t poly = {0xC200000000000000ULL, 1};
    uint64x2_t zero = vdupq_n_u64(0);
    uint64x2_t acc0 = *acc0_p, acc1 = *acc1_p;

    accm = veorq_u64(veorq_u64(accm, acc0), acc1);

    /* VEXT $8, ZERO, ACCM, T0 → T0 = ACCM[8:] || ZERO[:8] = {ACCM_hi, 0} */
    uint64x2_t t0 = vreinterpretq_u64_u8(
        vextq_u8(vreinterpretq_u8_u64(accm), vreinterpretq_u8_u64(zero), 8));
    /* VEXT $8, ACCM, ZERO, ACCM → ACCM = ZERO[8:] || ACCM[:8] = {0, ACCM_lo} */
    accm = vreinterpretq_u64_u8(
        vextq_u8(vreinterpretq_u8_u64(zero), vreinterpretq_u8_u64(accm), 8));

    acc0 = veorq_u64(acc0, accm); /* ACC0 ^= {0, ACCM_lo} */
    acc1 = veorq_u64(acc1, t0);   /* ACC1 ^= {ACCM_hi, 0} */

    t0 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(poly, 0),
                                          (poly64_t)vgetq_lane_u64(acc0, 0)));
    acc0 = veorq_u64(swap64(acc0), t0);

    t0 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(poly, 0),
                                          (poly64_t)vgetq_lane_u64(acc0, 0)));
    acc1 = veorq_u64(acc1, t0);

    acc1 = swap64(acc1); /* IN PLACE — per Go's reduce() */
    acc0 = veorq_u64(acc0, acc1);

    *acc0_p = acc0;
    *acc1_p = acc1;
}

/* Build the reflected-domain power table.
 * entry[7] = {2H, 2H⊕swap(2H)} (initial, NOT swapped first element)
 * entry[6..0] = {swap(P), P⊕swap(P)} (P = next power via P×2H) */
__attribute__((target("crypto"))) static void ghash_init_refl(CvmcryptGcm* g) {
    uint64x2_t poly = {0xC200000000000000ULL, 1};
    uint64x2_t zero = vdupq_n_u64(0);

    /* H_reflected = VREV64(H_be) */
    uint64x2_t B0 = vrev64_ld(g->H);

    /* Multiply by 2 mod P (reflected domain) — Go's exact sequence */
    {
        int64_t low = (int64_t)vgetq_lane_u64(B0, 0);
        int64_t sign = low >> 63;
        uint64x2_t T1 = vdupq_n_u64((uint64_t)sign);
        T1 = vandq_u64(poly, T1);
        uint64x2_t T2 = vshrq_n_u64(B0, 63);
        /* VEXT $8, ZERO, T2, T2 → T2 = T2[8:]||ZERO[:8] = {T2_hi, 0} */
        T2 = vreinterpretq_u64_u8(
            vextq_u8(vreinterpretq_u8_u64(T2), vreinterpretq_u8_u64(zero), 8));
        B0 = vshlq_n_u64(B0, 1);
        B0 = veorq_u64(veorq_u64(B0, T1), T2);
    }
    uint64x2_t B1 = veorq_u64(B0, swap64(B0));

    /* Store entry 7 = {2H, 2H⊕swap(2H)} */
    vst1q_u64((uint64_t*)g->H_refl[7], B0);
    vst1q_u64((uint64_t*)(g->H_refl[7] + 16), B1);

    /* Loop: compute entries 6 down to 0 */
    uint64x2_t B2 = B0, B3 = B1;
    for (int entry = 6; entry >= 0; entry--) {
        /* new_power = B2 × B0 (Karatsuba via B3 × B1) */
        uint64x2_t t1 = vreinterpretq_u64_p128(vmull_p64(
            (poly64_t)vgetq_lane_u64(B2, 0), (poly64_t)vgetq_lane_u64(B0, 0)));
        uint64x2_t t0 = vreinterpretq_u64_p128(vmull_p64(
            (poly64_t)vgetq_lane_u64(B2, 1), (poly64_t)vgetq_lane_u64(B0, 1)));
        uint64x2_t t2 = vreinterpretq_u64_p128(vmull_p64(
            (poly64_t)vgetq_lane_u64(B3, 0), (poly64_t)vgetq_lane_u64(B1, 0)));

        /* Fold + reduce (initLoop variant: EXTRA swap round) */
        t2 = veorq_u64(veorq_u64(t2, t0), t1);
        uint64x2_t t3 = vreinterpretq_u64_u8(
            vextq_u8(vreinterpretq_u8_u64(t2), vreinterpretq_u8_u64(zero), 8));
        t2 = vreinterpretq_u64_u8(
            vextq_u8(vreinterpretq_u8_u64(zero), vreinterpretq_u8_u64(t2), 8));
        t0 = veorq_u64(t0, t2);
        t1 = veorq_u64(t1, t3);

        t2 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(poly, 0),
                                              (poly64_t)vgetq_lane_u64(t0, 0)));
        t0 = veorq_u64(swap64(t0), t2);

        t2 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(poly, 0),
                                              (poly64_t)vgetq_lane_u64(t0, 0)));
        t0 = veorq_u64(swap64(t0), t2); /* EXTRA swap round (initLoop) */

        B2 = veorq_u64(t1, t0); /* new power = T1 ⊕ T0 */

        /* Karatsuba precompute: B3 = P ⊕ swap(P), B2 = swap(P) */
        B3 = B2;
        B2 = swap64(B2);
        B3 = veorq_u64(B3, B2);

        vst1q_u64((uint64_t*)g->H_refl[entry], B2);
        vst1q_u64((uint64_t*)(g->H_refl[entry] + 16), B3);
    }
}

/* 8-block aggregated reflected-domain GHASH.
 * 24 PMULLs + 1 reduction per 128 bytes. Zero bit reversal. */
__attribute__((target("crypto"))) static void ghash_8blocks_refl(CvmcryptGcm* g,
                                                                 u8 const* data) {
    uint64x2_t acc0 = vdupq_n_u64(0), acc1 = vdupq_n_u64(0), accm = vdupq_n_u64(0);

    /* First block: XOR with running accumulator */
    uint64x2_t acc_prev = vld1q_u64((uint64_t const*)g->X_refl);
    uint64x2_t x0 = veorq_u64(vrev64_ld(data), acc_prev);

    /* Table: entry[0] = highest power (block 1), entry[7] = 2H (block 8). */
    uint64x2_t t1 = vld1q_u64((uint64_t const*)g->H_refl[0]);
    uint64x2_t t2 = vld1q_u64((uint64_t const*)(g->H_refl[0] + 16));
    {
        uint64x2_t t0 = veorq_u64(x0, swap64(x0));
        acc1 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x0, 0),
                                                (poly64_t)vgetq_lane_u64(t1, 0)));
        acc0 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x0, 1),
                                                (poly64_t)vgetq_lane_u64(t1, 1)));
        accm = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(t0, 0),
                                                (poly64_t)vgetq_lane_u64(t2, 0)));
    }

    /* Blocks 2-8: entries 1-7 (decreasing power) */
    for (int i = 1; i <= 7; i++) {
        t1 = vld1q_u64((uint64_t const*)g->H_refl[i]);
        t2 = vld1q_u64((uint64_t const*)(g->H_refl[i] + 16));
        mul_round(vrev64_ld(data + i * 16), t1, t2, &acc0, &acc1, &accm);
    }

    reduce_go(&acc0, &acc1, accm);
    vst1q_u64((uint64_t*)g->X_refl, acc0);
}

#endif

/* Single-block GHASH multiply (slow path for partial blocks).
 * On aarch64, uses the reflected-domain single-block path;
 * elsewhere, scalar bit-by-bit. */
static void gf128_mul(u8 const* a, u8 const* b, u8* out, u8 impl) {
    gf128_mul_scalar(a, b, out);
    (void)impl;
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
    /* Fast path: 8-block reflected-domain GHASH (zero bit reversal). */
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->buflen == 0 && len >= 128) {
        /* Enter fast path: sync X_refl from g->X (in case slow path ran). */
        vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
        usize num8 = len / 128;
        for (usize i = 0; i < num8; i++) {
            ghash_8blocks_refl(g, data);
            data += 128;
            len -= 128;
        }
        /* Exit fast path: sync g->X from X_refl. */
        vst1q_u8(g->X, vrev64q_u8(vreinterpretq_u8_u64(
                           vld1q_u64((uint64_t const*)g->X_refl))));
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
            /* Sync reflected accumulator for the fast path. */
#if defined(__aarch64__)
            if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
                vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
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
#if defined(__aarch64__)
        if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
            vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
        }
#endif
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
#if defined(__aarch64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
        vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
    }
#endif
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
    memset(g->X_refl, 0, 16);
    g->buflen = 0;
    g->aadlen = 0;
    g->ptlen = 0;

#if defined(__aarch64__)
    g->impl = CVMCRYPT_GCM_IMPL_PMULL;
#else
    g->impl = CVMCRYPT_GCM_IMPL_SCALAR;
#endif

#if defined(__aarch64__)
    /* Build reflected-domain power table for 8-block GHASH. */
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
        ghash_init_refl(g);
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
        rk[r] = vrev32q_u8(vld1q_u8((u8 const*)&g->aes.enc[4 * r]));
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

#if defined(__aarch64__)
/* Fused 8-block AES-CTR + GHASH (Go's octetsLoop structure).
 * For each 128-byte chunk: AES-encrypt 8 counters, XOR with input,
 * then immediately GHASH the 8 ciphertext blocks. Data stays in
 * registers/L1 — no second pass over the ciphertext. */
#if defined(__aarch64__)
/* Pure-assembly fused AES-GCM kernel (gcm_arm64.S).
 * Processes 64 bytes per iteration, all state in NEON registers. */
extern void cvmcrypt_gcm_enc_kernel(u32 const* rk, u8 const* in, u8* out, usize nbytes,
                                    u8 const* tbl_e4, u8 const* ctr, u8* xrefl);

__attribute__((target("crypto"), unused)) static void
gcm_crypt_hash_asm64(CvmcryptGcm* g, u8 const* in, u8* out, usize nbytes) {
    cvmcrypt_gcm_enc_kernel(g->aes.enc, in, out, nbytes, &g->H_refl[0][0], g->counter,
                            g->X_refl);
}
#endif

__attribute__((target("crypto"), unused)) static void
gcm_crypt_hash_loop(CvmcryptGcm* g, u8 const* in, u8* out, usize nbytes) {
    /* Load AES round keys ONCE — hoisted out of the chunk loop. */
    uint8x16_t rk[11];
    for (int r = 0; r <= 10; r++) {
        rk[r] = vrev32q_u8(vld1q_u8((u8 const*)&g->aes.enc[4 * r]));
    }

    /* Running GHASH accumulator — stays in a register across iterations. */
    uint64x2_t acc_run = vld1q_u64((uint64_t const*)g->X_refl);

    while (nbytes >= 128) {
        nbytes -= 128;

        /* Generate 8 counters via NEON VADD chain (Go's approach).
         * CTR in native u32; VREV32 converts to/from BE bytes. */
        uint32x4_t inc = vdupq_n_u32(0);
        inc = vsetq_lane_u32(1, inc, 3);
        uint32x4_t cn = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(g->counter)));
        uint32x4_t c[8];
        c[0] = cn;
        for (int i = 1; i < 8; i++)
            c[i] = vaddq_u32(c[i - 1], inc);
        cn = vaddq_u32(c[7], inc); /* for next iteration */
        vst1q_u8(g->counter, vrev32q_u8(vreinterpretq_u8_u32(cn)));
        uint8x16_t ctr[8];
        for (int i = 0; i < 8; i++)
            ctr[i] = vrev32q_u8(vreinterpretq_u8_u32(c[i]));

        /* AES-encrypt all 8 counters (interleaved). */
        uint8x16_t s[8];
        for (int i = 0; i < 8; i++)
            s[i] = ctr[i];
        for (int r = 0; r < 9; r++) {
            for (int i = 0; i < 8; i++)
                s[i] = vaesmcq_u8(vaeseq_u8(s[i], rk[r]));
        }
        for (int i = 0; i < 8; i++)
            s[i] = veorq_u8(vaeseq_u8(s[i], rk[9]), rk[10]);

        /* XOR with input, store ciphertext, convert to reflected domain.
         * REUSE s[] as xb[] — saves 8 NEON registers (no spill). */
        for (int i = 0; i < 8; i++) {
            uint8x16_t p = vld1q_u8(in + i * 16);
            s[i] = veorq_u8(p, s[i]);
            vst1q_u8(out + i * 16, s[i]);
            s[i] = vrev64q_u8(s[i]); /* now holds reflected ciphertext */
        }

        /* GHASH 8 blocks (reflected domain).
         * Accumulator stays in a register across iterations. */
        uint64x2_t acc0 = vdupq_n_u64(0), acc1 = vdupq_n_u64(0), accm = vdupq_n_u64(0);
        {
            uint64x2_t x0 = veorq_u64(vreinterpretq_u64_u8(s[0]), acc_run);

            uint64x2_t t1 = vld1q_u64((uint64_t const*)g->H_refl[0]);
            uint64x2_t t2 = vld1q_u64((uint64_t const*)(g->H_refl[0] + 16));
            uint64x2_t t0 = veorq_u64(x0, swap64(x0));
            acc1 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x0, 0),
                                                    (poly64_t)vgetq_lane_u64(t1, 0)));
            acc0 = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x0, 1),
                                                    (poly64_t)vgetq_lane_u64(t1, 1)));
            accm = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(t0, 0),
                                                    (poly64_t)vgetq_lane_u64(t2, 0)));
        }

        for (int i = 1; i <= 7; i++) {
            uint64x2_t t1 = vld1q_u64((uint64_t const*)g->H_refl[i]);
            uint64x2_t t2 = vld1q_u64((uint64_t const*)(g->H_refl[i] + 16));
            mul_round(vreinterpretq_u64_u8(s[i]), t1, t2, &acc0, &acc1, &accm);
        }

        reduce_go(&acc0, &acc1, accm);
        acc_run = acc0; /* keep in register for next iteration */

        in += 128;
        out += 128;
    } /* while */
    vst1q_u64((uint64_t*)g->X_refl, acc_run); /* store once after loop */
}
#endif

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
#if defined(__aarch64__)
        if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
            vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
        }
#endif
        g->buflen = 0;
    }

    /* Save J0 for the tag. */
    u8 j0[16];
    memcpy(j0, g->counter, 16);

    /* Set counter to ICB = inc32(J0) for GCTR. gcm_crypt uses the
     * counter as-is for the first block (no pre-increment). */
    increment_counter(g->counter);

    /* Encrypt + GHASH: fused 128-byte chunks, then remainder. */
#if defined(__aarch64__)
    if (g->impl == CVMCRYPT_GCM_IMPL_PMULL && g->buflen == 0 && ptlen >= 128) {
        /* Sync X → X_refl for the fused loop. */
        vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
        usize n128 = ptlen & ~(usize)127;
        gcm_crypt_hash_asm64(g, pt, ct, n128);
        g->ptlen += n128 * 8;
        /* Sync X_refl → X for the slow path and ghash_flush. */
        vst1q_u8(g->X, vrev64q_u8(vreinterpretq_u8_u64(
                           vld1q_u64((uint64_t const*)g->X_refl))));
        /* Handle remainder with the non-fused path. */
        usize rem = ptlen - n128;
        gcm_crypt(g, pt + n128, rem, ct + n128);
        if (rem > 0) {
            ghash_update(g, ct + n128, rem, &g->ptlen);
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
#if defined(__aarch64__)
        if (g->impl == CVMCRYPT_GCM_IMPL_PMULL) {
            vst1q_u64((uint64_t*)g->X_refl, vrev64_ld(g->X));
        }
#endif
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
