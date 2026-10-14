/*
 * src/kx/x25519_fast.c
 *
 * X25519 with 5×51-bit limb field arithmetic (matching Go's implementation).
 * Each field element: l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204
 * Montgomery ladder translated from Go's crypto/ecdh/x25519.go.
 */

#include "kx/x25519.h"
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
    /* Go's feMulGeneric: multiply by 19 during accumulation, no t5..t8. */
    u64 a0 = a->l0, a1 = a->l1, a2 = a->l2, a3 = a->l3, a4 = a->l4;
    u64 b0 = b->l0, b1 = b->l1, b2 = b->l2, b3 = b->l3, b4 = b->l4;
    unsigned __int128 r0, r1, r2, r3, r4;
    u64 c0, c1, c2, c3, c4;
    u64 rr0, rr1, rr2, rr3, rr4;

    /* r0 = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) */
    r0 = (unsigned __int128)a0 * b0;
    r0 += (unsigned __int128)19 * a1 * b4;
    r0 += (unsigned __int128)19 * a2 * b3;
    r0 += (unsigned __int128)19 * a3 * b2;
    r0 += (unsigned __int128)19 * a4 * b1;

    /* r1 = a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2) */
    r1 = (unsigned __int128)a0 * b1;
    r1 += (unsigned __int128)a1 * b0;
    r1 += (unsigned __int128)19 * a2 * b4;
    r1 += (unsigned __int128)19 * a3 * b3;
    r1 += (unsigned __int128)19 * a4 * b2;

    /* r2 = a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3) */
    r2 = (unsigned __int128)a0 * b2;
    r2 += (unsigned __int128)a1 * b1;
    r2 += (unsigned __int128)a2 * b0;
    r2 += (unsigned __int128)19 * a3 * b4;
    r2 += (unsigned __int128)19 * a4 * b3;

    /* r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4 */
    r3 = (unsigned __int128)a0 * b3;
    r3 += (unsigned __int128)a1 * b2;
    r3 += (unsigned __int128)a2 * b1;
    r3 += (unsigned __int128)a3 * b0;
    r3 += (unsigned __int128)19 * a4 * b4;

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

static void fe_sq(Fe* h, Fe const* a) {
    fe_mul(h, a, a);
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

/* Base point multiplication: out = scalar * basepoint. */
void cvmcrypt_x25519_base_fast(u8 public_key[32], u8 const scalar[32]) {
    static u8 const basepoint[32] = {9};
    cvmcrypt_x25519_fast(public_key, scalar, basepoint);
}
