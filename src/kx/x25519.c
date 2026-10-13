/*
 * src/kx/x25519.c
 *
 * X25519 (RFC 7748). Tweetnacl-style field arithmetic (16 i64 limbs)
 * and Montgomery ladder, following the proven tweetnacl formulation.
 * The tweetnacl car25519 handles negative limbs by adding 2^16 first,
 * which is what makes the arithmetic work correctly.
 *
 * Source: libtomcrypt's tweetnacl.c (Unlicense), adapted to cvm style.
 */

#include "kx/x25519.h"

#include "base/mem.h"

typedef i64 gf[16];

#define GF_RADIX (((i64)1) << 16)

static void car25519(gf o) {
    for (usize i = 0; i < 16; i++) {
        o[i] += GF_RADIX;
        i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * GF_RADIX;
    }
}

static void sel25519(gf p, gf q, i64 b) {
    i64 c = ~(b - 1);
    for (usize i = 0; i < 16; i++) {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8* o, gf const n) {
    gf m, t;
    for (usize i = 0; i < 16; i++)
        t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (usize j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (usize i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        i64 b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (usize i = 0; i < 16; i++) {
        o[2 * i] = (u8)(t[i] & 0xff);
        o[2 * i + 1] = (u8)(t[i] >> 8);
    }
}

static void unpack25519(gf o, u8 const* n) {
    for (usize i = 0; i < 16; i++)
        o[i] = (i64)n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, gf const a, gf const b) {
    for (usize i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void Z(gf o, gf const a, gf const b) {
    for (usize i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void M(gf o, gf const a, gf const b) {
    i64 t[31];
    for (usize i = 0; i < 31; i++)
        t[i] = 0;
    for (usize i = 0; i < 16; i++)
        for (usize j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (usize i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (usize i = 0; i < 16; i++)
        o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, gf const a) {
    M(o, a, a);
}

static void inv25519(gf o, gf const in) {
    gf c;
    for (usize i = 0; i < 16; i++)
        c[i] = in[i];
    for (i32 a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4)
            M(c, c, in);
    }
    for (usize i = 0; i < 16; i++)
        o[i] = c[i];
}

static gf const gf121665 = {0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static u8 const nine[32] = {9};

void cvmcrypt_x25519(u8 out[32], u8 const scalar[32], u8 const u_point[32]) {
    u8 z[32];
    i64 x[80], r;
    gf a, b, c, d, e, f;

    for (usize i = 0; i < 31; i++)
        z[i] = scalar[i];
    z[31] = (scalar[31] & 127) | 64;
    z[0] &= 248;

    unpack25519(x, u_point);

    for (usize i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (i32 i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, gf121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }

    for (usize i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    M(x + 16, x + 16, x + 32);
    pack25519(out, x + 16);
}

void cvmcrypt_x25519_base(u8 public_key[32], u8 const scalar[32]) {
    cvmcrypt_x25519(public_key, scalar, nine);
}

void cvmcrypt_x25519_shared(u8 shared[32], u8 const scalar[32],
                            u8 const peer_public[32]) {
    cvmcrypt_x25519(shared, scalar, peer_public);
}
