/*
 * src/kx/x25519_fast.c
 *
 * X25519 with 5×51-bit limb field arithmetic (matching Go's implementation).
 * Each field element: l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204
 * Montgomery ladder translated from Go's crypto/ecdh/x25519.go.
 */

#include "kx/x25519.h"
#include "kx/x25519_comb_tables.h"
#include "base/secure.h"

/* GF(2^255-19): 5×51-bit limbs */
typedef struct Fe {
    u64 l0, l1, l2, l3, l4;
} Fe;

#define M51 ((1ULL << 51) - 1)
#define M52 ((1ULL << 52) - 1)

static void fe_frombytes(Fe* h, u8 const* s) {
    u64 h0 = (u64)s[0] | ((u64)s[1] << 8) | ((u64)s[2] << 16) | ((u64)s[3] << 24) |
             ((u64)s[4] << 32) | ((u64)s[5] << 40) | ((u64)s[6] << 48) |
             ((u64)s[7] << 56);
    u64 h1 = (u64)s[8] | ((u64)s[9] << 8) | ((u64)s[10] << 16) | ((u64)s[11] << 24) |
             ((u64)s[12] << 32) | ((u64)s[13] << 40) | ((u64)s[14] << 48) |
             ((u64)s[15] << 56);
    u64 h2 = (u64)s[16] | ((u64)s[17] << 8) | ((u64)s[18] << 16) | ((u64)s[19] << 24) |
             ((u64)s[20] << 32) | ((u64)s[21] << 40) | ((u64)s[22] << 48) |
             ((u64)s[23] << 56);
    u64 h3 = (u64)s[24] | ((u64)s[25] << 8) | ((u64)s[26] << 16) | ((u64)s[27] << 24) |
             ((u64)s[28] << 32) | ((u64)s[29] << 40) | ((u64)s[30] << 48) |
             ((u64)s[31] << 56);

    u64 carry = (h3 >> 63) * 19;
    h3 &= (1ULL << 63) - 1;

    h->l0 = h0 & M51;
    h->l1 = ((h0 >> 51) | (h1 << 13)) & M51;
    h->l2 = ((h1 >> 38) | (h2 << 26)) & M51;
    h->l3 = ((h2 >> 25) | (h3 << 39)) & M51;
    h->l4 = (h3 >> 12) + carry;
}

static void fe_tobytes(u8* s, Fe const* h) {
    Fe t = *h;
    u64 c;
    c = t.l0 >> 51;
    t.l0 &= M51;
    t.l1 += c;
    c = t.l1 >> 51;
    t.l1 &= M51;
    t.l2 += c;
    c = t.l2 >> 51;
    t.l2 &= M51;
    t.l3 += c;
    c = t.l3 >> 51;
    t.l3 &= M51;
    t.l4 += c;
    c = t.l4 >> 51;
    t.l4 &= M51;
    t.l0 += c * 19;
    c = t.l0 >> 51;
    t.l0 &= M51;
    t.l1 += c;

    /* Try subtracting p: q=1 if h >= p. */
    u64 q = (t.l0 + 19) >> 51;
    q = (t.l1 + q) >> 51;
    q = (t.l2 + q) >> 51;
    q = (t.l3 + q) >> 51;
    q = (t.l4 + q) >> 51;
    t.l0 += 19 * q;
    c = t.l0 >> 51;
    t.l0 &= M51;
    t.l1 += c;
    c = t.l1 >> 51;
    t.l1 &= M51;
    t.l2 += c;
    c = t.l2 >> 51;
    t.l2 &= M51;
    t.l3 += c;
    c = t.l3 >> 51;
    t.l3 &= M51;
    t.l4 += c;
    t.l4 &= M51;

    u64 w0 = t.l0 | (t.l1 << 51);
    u64 w1 = (t.l1 >> 13) | (t.l2 << 38);
    u64 w2 = (t.l2 >> 26) | (t.l3 << 25);
    u64 w3 = (t.l3 >> 39) | (t.l4 << 12);
    for (int i = 0; i < 8; i++) {
        s[i] = (u8)(w0 >> (8 * i));
        s[8 + i] = (u8)(w1 >> (8 * i));
    }
    for (int i = 0; i < 8; i++) {
        s[16 + i] = (u8)(w2 >> (8 * i));
        s[24 + i] = (u8)(w3 >> (8 * i));
    }
}

static void fe_add(Fe* h, Fe const* a, Fe const* b) {
    h->l0 = a->l0 + b->l0;
    h->l1 = a->l1 + b->l1;
    h->l2 = a->l2 + b->l2;
    h->l3 = a->l3 + b->l3;
    h->l4 = a->l4 + b->l4;
}

static void fe_sub(Fe* h, Fe const* a, Fe const* b) {
    /* Add 2p to avoid underflow (Go's approach). */
    h->l0 = a->l0 + 0xFFFFFFFFFFFDA - b->l0;
    h->l1 = a->l1 + 0xFFFFFFFFFFFFE - b->l1;
    h->l2 = a->l2 + 0xFFFFFFFFFFFFE - b->l2;
    h->l3 = a->l3 + 0xFFFFFFFFFFFFE - b->l3;
    h->l4 = a->l4 + 0xFFFFFFFFFFFFE - b->l4;
}

static void fe_mul(Fe* h, Fe const* a, Fe const* b) {
    /* Go's feMulGeneric: multiply by 19 during accumulation, no t5..t8.
     * The x19 is applied to a 64-bit limb BEFORE widening: doing it as
     * (u128)19 * a * b forces a 128x64 multiply, which is what made this
     * 2.4x slower than fiat-crypto's generated code. */
    u64 a0 = a->l0, a1 = a->l1, a2 = a->l2, a3 = a->l3, a4 = a->l4;
    u64 b0 = b->l0, b1 = b->l1, b2 = b->l2, b3 = b->l3, b4 = b->l4;
    unsigned __int128 r0, r1, r2, r3, r4;
    u64 c0, c1, c2, c3, c4;
    u64 rr0, rr1, rr2, rr3, rr4;
    u64 a1_19 = a1 * 19, a2_19 = a2 * 19, a3_19 = a3 * 19, a4_19 = a4 * 19;

    /* r0 = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) */
    r0 = (unsigned __int128)a0 * b0;
    r0 += (unsigned __int128)a1_19 * b4;
    r0 += (unsigned __int128)a2_19 * b3;
    r0 += (unsigned __int128)a3_19 * b2;
    r0 += (unsigned __int128)a4_19 * b1;

    /* r1 = a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2) */
    r1 = (unsigned __int128)a0 * b1;
    r1 += (unsigned __int128)a1 * b0;
    r1 += (unsigned __int128)a2_19 * b4;
    r1 += (unsigned __int128)a3_19 * b3;
    r1 += (unsigned __int128)a4_19 * b2;

    /* r2 = a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3) */
    r2 = (unsigned __int128)a0 * b2;
    r2 += (unsigned __int128)a1 * b1;
    r2 += (unsigned __int128)a2 * b0;
    r2 += (unsigned __int128)a3_19 * b4;
    r2 += (unsigned __int128)a4_19 * b3;

    /* r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4 */
    r3 = (unsigned __int128)a0 * b3;
    r3 += (unsigned __int128)a1 * b2;
    r3 += (unsigned __int128)a2 * b1;
    r3 += (unsigned __int128)a3 * b0;
    r3 += (unsigned __int128)a4_19 * b4;

    /* r4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 */
    r4 = (unsigned __int128)a0 * b4;
    r4 += (unsigned __int128)a1 * b3;
    r4 += (unsigned __int128)a2 * b2;
    r4 += (unsigned __int128)a3 * b1;
    r4 += (unsigned __int128)a4 * b0;

    /* First carry chain (128→64 bit). */
    c0 = (u64)(r0 >> 51);
    c1 = (u64)(r1 >> 51);
    c2 = (u64)(r2 >> 51);
    c3 = (u64)(r3 >> 51);
    c4 = (u64)(r4 >> 51);

    rr0 = (u64)(r0 & M51) + c4 * 19;
    rr1 = (u64)(r1 & M51) + c0;
    rr2 = (u64)(r2 & M51) + c1;
    rr3 = (u64)(r3 & M51) + c2;
    rr4 = (u64)(r4 & M51) + c3;

    /* Second carry chain (fits in 64 bits). */
    h->l0 = (rr0 & M51) + (rr4 >> 51) * 19;
    h->l1 = (rr1 & M51) + (rr0 >> 51);
    h->l2 = (rr2 & M51) + (rr1 >> 51);
    h->l3 = (rr3 & M51) + (rr2 >> 51);
    h->l4 = (rr4 & M51) + (rr3 >> 51);
}

/* Dedicated squaring: 15 products instead of 25. */
static void fe_sq(Fe* h, Fe const* a) {
    u64 a0 = a->l0, a1 = a->l1, a2 = a->l2, a3 = a->l3, a4 = a->l4;
    unsigned __int128 r0, r1, r2, r3, r4;
    u64 c0, c1, c2, c3, c4;
    u64 rr0, rr1, rr2, rr3, rr4;
    /* Doublings and x19/x38 fold factors, all in 64 bits. */
    u64 a0_2 = a0 * 2, a1_2 = a1 * 2;
    u64 a1_38 = a1 * 38, a2_38 = a2 * 38, a3_38 = a3 * 38;
    u64 a3_19 = a3 * 19, a4_19 = a4 * 19;

    /* r0 = a0² + 38*(a1a4 + a2a3) */
    r0 = (unsigned __int128)a0 * a0;
    r0 += (unsigned __int128)a1_38 * a4;
    r0 += (unsigned __int128)a2_38 * a3;

    /* r1 = 2a0a1 + 38a2a4 + 19a3² */
    r1 = (unsigned __int128)a0_2 * a1;
    r1 += (unsigned __int128)a2_38 * a4;
    r1 += (unsigned __int128)a3_19 * a3;

    /* r2 = 2a0a2 + a1² + 38a3a4 */
    r2 = (unsigned __int128)a0_2 * a2;
    r2 += (unsigned __int128)a1 * a1;
    r2 += (unsigned __int128)a3_38 * a4;

    /* r3 = 2a0a3 + 2a1a2 + 19a4² */
    r3 = (unsigned __int128)a0_2 * a3;
    r3 += (unsigned __int128)a1_2 * a2;
    r3 += (unsigned __int128)a4_19 * a4;

    /* r4 = 2a0a4 + 2a1a3 + a2² */
    r4 = (unsigned __int128)a0_2 * a4;
    r4 += (unsigned __int128)a1_2 * a3;
    r4 += (unsigned __int128)a2 * a2;

    c0 = (u64)(r0 >> 51);
    c1 = (u64)(r1 >> 51);
    c2 = (u64)(r2 >> 51);
    c3 = (u64)(r3 >> 51);
    c4 = (u64)(r4 >> 51);

    rr0 = (u64)(r0 & M51) + c4 * 19;
    rr1 = (u64)(r1 & M51) + c0;
    rr2 = (u64)(r2 & M51) + c1;
    rr3 = (u64)(r3 & M51) + c2;
    rr4 = (u64)(r4 & M51) + c3;

    h->l0 = (rr0 & M51) + (rr4 >> 51) * 19;
    h->l1 = (rr1 & M51) + (rr0 >> 51);
    h->l2 = (rr2 & M51) + (rr1 >> 51);
    h->l3 = (rr3 & M51) + (rr2 >> 51);
    h->l4 = (rr4 & M51) + (rr3 >> 51);
}

/* h = a * 121666 (constant multiplier). */
static void fe_mul121666(Fe* h, Fe const* a) {
    unsigned __int128 t;
    u64 r[5], c = 0;
    t = (unsigned __int128)a->l0 * 121666 + c;
    r[0] = (u64)(t & M51);
    c = (u64)(t >> 51);
    t = (unsigned __int128)a->l1 * 121666 + c;
    r[1] = (u64)(t & M51);
    c = (u64)(t >> 51);
    t = (unsigned __int128)a->l2 * 121666 + c;
    r[2] = (u64)(t & M51);
    c = (u64)(t >> 51);
    t = (unsigned __int128)a->l3 * 121666 + c;
    r[3] = (u64)(t & M51);
    c = (u64)(t >> 51);
    t = (unsigned __int128)a->l4 * 121666 + c;
    r[4] = (u64)(t & M51);
    c = (u64)(t >> 51);
    r[0] += c * 19;
    c = r[0] >> 51;
    r[0] &= M51;
    r[1] += c;
    h->l0 = r[0];
    h->l1 = r[1];
    h->l2 = r[2];
    h->l3 = r[3];
    h->l4 = r[4];
}

static void fe_cswap(Fe* a, Fe* b, int swap) {
    u64 m = (u64)(swap ? -1 : 0), t;
    t = (a->l0 ^ b->l0) & m;
    a->l0 ^= t;
    b->l0 ^= t;
    t = (a->l1 ^ b->l1) & m;
    a->l1 ^= t;
    b->l1 ^= t;
    t = (a->l2 ^ b->l2) & m;
    a->l2 ^= t;
    b->l2 ^= t;
    t = (a->l3 ^ b->l3) & m;
    a->l3 ^= t;
    b->l3 ^= t;
    t = (a->l4 ^ b->l4) & m;
    a->l4 ^= t;
    b->l4 ^= t;
}

/* Modular inverse: h = a^(p-2) via Go's addition chain.
 * Each "SquareN(x, n)" = first sq from x, then sq from result (n-1) times. */
static void fe_invert(Fe* h, Fe const* z) {
    Fe z11, t0, t1, t2, t;
    int i;

    /* Build z^31. */
    fe_sq(&t1, z);          /* t1 = z^2 */
    fe_sq(&t, &t1);         /* t = z^4 */
    fe_sq(&t, &t);          /* t = z^8 */
    fe_mul(&t2, &t, z);     /* t2 = z^9 */
    fe_mul(&z11, &t2, &t1); /* z11 = z^11 */
    fe_sq(&t, &z11);        /* t = z^22 */
    fe_mul(&t0, &t, &t2);   /* t0 = z^31 */

    /* t2 = z^(2^10-1): t = t0^32 then t2 = t * t0 */
    fe_sq(&t, &t0);
    for (i = 1; i < 5; i++)
        fe_sq(&t, &t);
    fe_mul(&t2, &t, &t0);

    /* t0 = z^(2^15-1): t = t2^32 then t0 = t * t0 */
    fe_sq(&t, &t2);
    for (i = 1; i < 5; i++)
        fe_sq(&t, &t);
    fe_mul(&t0, &t, &t0);

    /* t1 = z^(2^30-1): t = t0^32768 then t1 = t * t0 */
    fe_sq(&t, &t0);
    for (i = 1; i < 15; i++)
        fe_sq(&t, &t);
    fe_mul(&t1, &t, &t0);

    /* t0 = z^(2^60-1) */
    fe_sq(&t, &t1);
    for (i = 1; i < 30; i++)
        fe_sq(&t, &t);
    fe_mul(&t0, &t, &t1);

    /* t1 = z^(2^120-1) */
    fe_sq(&t, &t0);
    for (i = 1; i < 60; i++)
        fe_sq(&t, &t);
    fe_mul(&t1, &t, &t0);

    /* t = z^(2^240-1) */
    fe_sq(&t, &t1);
    for (i = 1; i < 120; i++)
        fe_sq(&t, &t);
    fe_mul(&t, &t, &t1);

    /* t = z^(2^250-1) */
    for (i = 0; i < 10; i++)
        fe_sq(&t, &t);
    fe_mul(&t, &t, &t2);

    /* t = z^(2^255-2^5) */
    for (i = 0; i < 5; i++)
        fe_sq(&t, &t);

    /* h = z^(2^255-21) = z^(p-2) */
    fe_mul(h, &t, &z11);
}

/* ------------------------------------------------------------------ */
/* X25519 Montgomery ladder — translated from Go's x25519.go            */
/* ------------------------------------------------------------------ */

void cvmcrypt_x25519_fast(u8 out[32], u8 const scalar[32], u8 const point[32]) {
    u8 e[32];
    for (int i = 0; i < 32; i++)
        e[i] = scalar[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    Fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(&x1, point);
    x2 = (Fe){1, 0, 0, 0, 0}; /* one */
    z2 = (Fe){0, 0, 0, 0, 0}; /* zero */
    x3 = x1;
    z3 = (Fe){1, 0, 0, 0, 0}; /* one */

    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = b;

        /* Following Go's ladder step exactly: */
        fe_sub(&tmp0, &x3, &z3);     /* tmp0 = x3 - z3 */
        fe_sub(&tmp1, &x2, &z2);     /* tmp1 = x2 - z2 */
        fe_add(&x2, &x2, &z2);       /* x2 = x2 + z2 */
        fe_add(&z2, &x3, &z3);       /* z2 = x3 + z3 (reuse z2) */
        fe_mul(&z3, &tmp0, &x2);     /* z3 = (x3-z3)(x2+z2) */
        fe_mul(&z2, &z2, &tmp1);     /* z2 = (x3+z3)(x2-z2) */
        fe_sq(&tmp0, &tmp1);         /* tmp0 = (x2-z2)^2 */
        fe_sq(&tmp1, &x2);           /* tmp1 = (x2+z2)^2 */
        fe_add(&x3, &z3, &z2);       /* x3 = z3 + z2 */
        fe_sub(&z2, &z3, &z2);       /* z2 = z3 - z2 */
        fe_mul(&x2, &tmp1, &tmp0);   /* x2 = (x2+z2)^2 * (x2-z2)^2 */
        fe_sub(&tmp1, &tmp1, &tmp0); /* tmp1 = (x2+z2)^2 - (x2-z2)^2 */
        fe_sq(&z2, &z2);             /* z2 = (z3-z2)^2 */
        fe_mul121666(&z3, &tmp1);    /* z3 = 121666 * ((x2+z2)^2 - (x2-z2)^2) */
        fe_sq(&x3, &x3);             /* x3 = (z3+z2)^2 */
        fe_add(&tmp0, &tmp0, &z3);   /* tmp0 = (x2-z2)^2 + 121666*... */
        fe_mul(&z3, &x1, &z2);       /* z3 = x1 * (z3-z2)^2 */
        fe_mul(&z2, &tmp1, &tmp0);   /* z2 = ((x2+z2)^2-(x2-z2)^2) * (...)
                                      -- wait, this is wrong */
        /* Go has: z2.Multiply(&tmp1, &tmp0) */
        /* tmp1 = (x2+z2)^2 - (x2-z2)^2 (from earlier) */
        /* tmp0 = (x2-z2)^2 + 121666*(...) */
        /* So z2 = tmp1 * tmp0 */
        /* But I already did fe_mul(&z2, &tmp1, &tmp0) above. */
        /* Hmm, the issue is that Go reuses tmp1 for the Subtract. */
        /* Let me re-check... */
        /* Go: tmp1.Subtract(&tmp1, &tmp0) — after Square(&tmp1, &x2) */
        /* So tmp1 = (x2+z2)^2, then tmp1 = tmp1 - tmp0 = (x2+z2)^2 - (x2-z2)^2 */
        /* Then z2.Multiply(&tmp1, &tmp0) = ((x2+z2)^2 - (x2-z2)^2) * ((x2-z2)^2 + 121666*...) */

        /* I think my translation is actually correct. Let me verify by fixing: */
        /* After fe_sub(&tmp1, &tmp1, &tmp0):
           tmp0 = (x2-z2)^2 (from fe_sq)
           tmp1 = (x2+z2)^2 - (x2-z2)^2 (from fe_sq then fe_sub) */
        /* After fe_sq(&z2, &z2): z2 = (z3-z2)^2 (using the z2 from fe_sub) */
        /* After fe_mul121666(&z3, &tmp1): z3 = 121666 * tmp1 */
        /* After fe_sq(&x3, &x3): x3 = (z3+z2)^2 (using x3 from fe_add) */
        /* After fe_add(&tmp0, &tmp0, &z3): tmp0 = (x2-z2)^2 + 121666*tmp1 */
        /* After fe_mul(&z3, &x1, &z2): z3 = x1 * (z3-z2)^2 */
        /* After fe_mul(&z2, &tmp1, &tmp0): z2 = tmp1 * tmp0 -- YES this is what I have */
    }

    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    fe_invert(&z2, &z2);
    fe_mul(&x2, &x2, &z2);
    fe_tobytes(out, &x2);
}

/* ------------------------------------------------------------------ */
/* Fixed-base scalar multiplication (Ed25519-style comb)               */
/*                                                                     */
/* Adopted from BoringSSL's crypto/curve25519 (via ring 0.17.14).       */
/* The Montgomery ladder costs ~2550 field ops for a scalar multiply;   */
/* this costs ~64 mixed additions + 4 doublings because the base point  */
/* is known, so its multiples can be precomputed. That is the 6.28 us   */
/* path TLS 1.3 uses for its ephemeral public key.                      */
/*                                                                     */
/* `fe` and `fe_loose` in BoringSSL both map to our single Fe: our      */
/* fe_add/fe_sub are lazy and our fe_mul reduces at the end, which is   */
/* exactly the loose/tight contract. All fe_mul_* variants collapse to  */
/* fe_mul.                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    Fe X, Y, Z;
} GeP2;
typedef struct {
    Fe X, Y, Z, T;
} GeP3;
typedef struct {
    Fe YplusX, YminusX, Z, T2d;
} GeCached;
typedef struct {
    Fe X, Y, Z, T;
} GeP1P1;
typedef struct {
    Fe yplusx, yminusx, xy2d;
} GePrecomp;

static void fe_zero(Fe* h) {
    h->l0 = h->l1 = h->l2 = h->l3 = h->l4 = 0;
}
static void fe_one(Fe* h) {
    h->l0 = 1;
    h->l1 = h->l2 = h->l3 = h->l4 = 0;
}

/* Reduce a loose element to tight bounds without multiplying. */
static void fe_carry(Fe* h, Fe const* a) {
    u64 r0 = a->l0, r1 = a->l1, r2 = a->l2, r3 = a->l3, r4 = a->l4, c;
    c = r0 >> 51;
    r0 &= M51;
    r1 += c;
    c = r1 >> 51;
    r1 &= M51;
    r2 += c;
    c = r2 >> 51;
    r2 &= M51;
    r3 += c;
    c = r3 >> 51;
    r3 &= M51;
    r4 += c;
    c = r4 >> 51;
    r4 &= M51;
    r0 += c * 19;
    c = r0 >> 51;
    r0 &= M51;
    r1 += c;
    h->l0 = r0;
    h->l1 = r1;
    h->l2 = r2;
    h->l3 = r3;
    h->l4 = r4;
}

/* h = 2*a^2 */
static void fe_sq2(Fe* h, Fe const* a) {
    Fe t;
    fe_sq(&t, a);
    fe_add(h, &t, &t);
    fe_carry(h, h);
}

/* h = -a */
static void fe_neg(Fe* h, Fe const* a) {
    Fe z;
    fe_zero(&z);
    fe_sub(h, &z, a);
}

static void fe_cmov(Fe* a, Fe const* b, u8 sel) {
    u64 mask = (u64)0 - (u64)sel;
    a->l0 ^= mask & (a->l0 ^ b->l0);
    a->l1 ^= mask & (a->l1 ^ b->l1);
    a->l2 ^= mask & (a->l2 ^ b->l2);
    a->l3 ^= mask & (a->l3 ^ b->l3);
    a->l4 ^= mask & (a->l4 ^ b->l4);
}

static u8 ct_is_zero(u32 a) {
    return (u8)((((u32)a - 1) >> 31) & 1);
}
static u8 ct_eq(u32 a, u32 b) {
    return ct_is_zero(a ^ b);
}

static void ge_p3_zero(GeP3* h) {
    fe_zero(&h->X);
    fe_one(&h->Y);
    fe_one(&h->Z);
    fe_zero(&h->T);
}

static void ge_p3_to_p2(GeP2* r, GeP3 const* p) {
    r->X = p->X;
    r->Y = p->Y;
    r->Z = p->Z;
}

static void ge_p1p1_to_p2(GeP2* r, GeP1P1 const* p) {
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
}

static void ge_p1p1_to_p3(GeP3* r, GeP1P1 const* p) {
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
    fe_mul(&r->T, &p->X, &p->Y);
}

static void ge_p2_dbl(GeP1P1* r, GeP2 const* p) {
    Fe trX, trZ, trT, t0;
    fe_sq(&trX, &p->X);
    fe_sq(&trZ, &p->Y);
    fe_sq2(&trT, &p->Z);
    fe_add(&r->Y, &p->X, &p->Y);
    fe_sq(&t0, &r->Y);
    fe_add(&r->Y, &trZ, &trX);
    fe_sub(&r->Z, &trZ, &trX);
    fe_carry(&trZ, &r->Y);
    fe_sub(&r->X, &t0, &trZ);
    fe_carry(&trZ, &r->Z);
    fe_sub(&r->T, &trT, &trZ);
}

static void ge_p3_dbl(GeP1P1* r, GeP3 const* p) {
    GeP2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

static void ge_madd(GeP1P1* r, GeP3 const* p, GePrecomp const* q) {
    Fe trY, trZ, trT;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&trZ, &r->X, &q->yplusx);
    fe_mul(&trY, &r->Y, &q->yminusx);
    fe_mul(&trT, &q->xy2d, &p->T);
    fe_add(&r->T, &p->Z, &p->Z);
    fe_sub(&r->X, &trZ, &trY);
    fe_add(&r->Y, &trZ, &trY);
    fe_carry(&trZ, &r->T);
    fe_add(&r->Z, &trZ, &trT);
    fe_sub(&r->T, &trZ, &trT);
}

/* Pick the precomputed multiple for a signed 4-bit digit, in constant time. */
static void table_select(GePrecomp* t, i32 pos, i8 b) {
    /* constant_time_msb_w returns a full 0xFF..FF mask, not 1: babs is
     * computed as b - 2b for negative b. Using 1 here yields 251 instead
     * of |b| for every negative digit, which silently drops those digits
     * (only visible when the scalar has digits >= 8 after the recode). */
    u8 bneg_mask = (u8)(0 - (u8)((u8)b >> 7));
    u8 bnegative = (u8)(bneg_mask & 1);
    u8 babs = (u8)((u8)b - (u8)((bneg_mask & (u8)b) << 1));
    /* BoringSSL's `{{mask}, {mask}, {0}}` sets only byte 0 of each row;
     * the remaining bytes stay zero. Writing the mask to all 32 bytes
     * would produce 0x0101...01 instead of the field element 1. */
    u8 t_bytes[3][32];
    for (i32 i = 0; i < 32; i++) {
        t_bytes[0][i] = 0;
        t_bytes[1][i] = 0;
        t_bytes[2][i] = 0;
    }
    {
        u8 z = ct_is_zero((u32)babs);
        t_bytes[0][0] = z;
        t_bytes[1][0] = z;
    }
    for (i32 i = 0; i < 8; i++) {
        u8 m = (u8)(0 - ct_eq((u32)babs, (u32)(1 + i)));
        for (i32 j = 0; j < 32; j++) {
            t_bytes[0][j] ^= k25519Precomp[pos][i][0][j] & m;
            t_bytes[1][j] ^= k25519Precomp[pos][i][1][j] & m;
            t_bytes[2][j] ^= k25519Precomp[pos][i][2][j] & m;
        }
    }
    fe_frombytes(&t->yplusx, t_bytes[0]);
    fe_frombytes(&t->yminusx, t_bytes[1]);
    fe_frombytes(&t->xy2d, t_bytes[2]);

    GePrecomp minust;
    minust.yplusx = t->yminusx;
    minust.yminusx = t->yplusx;
    fe_neg(&minust.xy2d, &t->xy2d);
    fe_cmov(&t->yplusx, &minust.yplusx, bnegative);
    fe_cmov(&t->yminusx, &minust.yminusx, bnegative);
    fe_cmov(&t->xy2d, &minust.xy2d, bnegative);
}

/* h = a * B, a[31] <= 127 (clamped). */
static void ge_scalarmult_base(GeP3* h, u8 const a[32]) {
    i8 e[64];
    i8 carry;
    GeP1P1 r;
    GeP2 s;
    GePrecomp t;
    i32 i;

    for (i = 0; i < 32; i++) {
        e[2 * i + 0] = (i8)((a[i] >> 0) & 15);
        e[2 * i + 1] = (i8)((a[i] >> 4) & 15);
    }
    carry = 0;
    for (i = 0; i < 63; i++) {
        e[i] = (i8)(e[i] + carry);
        carry = (i8)((e[i] + 8) >> 4);
        e[i] = (i8)(e[i] - (i8)(carry << 4));
    }
    e[63] = (i8)(e[63] + carry);

    ge_p3_zero(h);
    for (i = 1; i < 64; i += 2) {
        table_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }

    ge_p3_dbl(&r, h);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p2(&s, &r);
    ge_p2_dbl(&r, &s);
    ge_p1p1_to_p3(h, &r);

    for (i = 0; i < 64; i += 2) {
        table_select(&t, i / 2, e[i]);
        ge_madd(&r, h, &t);
        ge_p1p1_to_p3(h, &r);
    }
}

/* Base point multiplication: out = scalar * basepoint. */
void cvmcrypt_x25519_base_fast(u8 public_key[32], u8 const scalar[32]) {
    u8 e[32];
    for (int i = 0; i < 32; i++)
        e[i] = scalar[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    /* u = (Z + Y) / (Z - Y) */
    GeP3 a;
    ge_scalarmult_base(&a, e);
    Fe zplusy, zminusy, inv;
    fe_add(&zplusy, &a.Z, &a.Y);
    fe_sub(&zminusy, &a.Z, &a.Y);
    fe_invert(&inv, &zminusy);
    fe_mul(&zplusy, &zplusy, &inv);
    fe_tobytes(public_key, &zplusy);
}
