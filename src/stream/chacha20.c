/*
 * src/stream/chacha20.c
 *
 * ChaCha20 (RFC 8439 §2.4).
 *
 * Vector path: 4 blocks in parallel using compiler vector extensions
 * (__attribute__((vector_size(16))), 4 lanes of u32 = 16 bytes).
 * One source for arm64 (NEON) and amd64 (SSE2) — no platform headers.
 * Scalar path handles the tail (< 256 bytes) and the partial-block buffer.
 */

#include "stream/chacha20.h"

#include "base/mem.h"

CVM_INLINE u32 load_le32(u8 const* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

CVM_INLINE void store_le32(u8* p, u32 v) {
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

CVM_INLINE u32 rotl32(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

/* ------------------------------------------------------------------ */
/* vector path (4 blocks in parallel)                                   */
/* ------------------------------------------------------------------ */

#if defined(__GNUC__) || defined(__clang__)
#define CHACHA20_VEC 1
typedef u32 v4u32 __attribute__((vector_size(16)));

/* Vector quarter round: same as scalar, but rotations via shifts.
 * For u32 lanes, (x << n) | (x >> (32-n)) is a left rotate. */
#define VQR(a, b, c, d)                                                                \
    a += b;                                                                            \
    d ^= a;                                                                            \
    d = (d << 16) | (d >> 16);                                                         \
    c += d;                                                                            \
    b ^= c;                                                                            \
    b = (b << 12) | (b >> 20);                                                         \
    a += b;                                                                            \
    d ^= a;                                                                            \
    d = (d << 8) | (d >> 24);                                                          \
    c += d;                                                                            \
    b ^= c;                                                                            \
    b = (b << 7) | (b >> 25);

CVM_INLINE v4u32 v4u32_splat(u32 x) {
    v4u32 v = {x, x, x, x};
    return v;
}

/* 4×4 transpose using vector shuffles: [state][block] → [block][state]. */
#define TRANSPOSE4(a, b, c, d)                                                         \
    {                                                                                  \
        v4u32 t0 = __builtin_shufflevector(a, b, 0, 4, 2, 6);                          \
        v4u32 t1 = __builtin_shufflevector(a, b, 1, 5, 3, 7);                          \
        v4u32 t2 = __builtin_shufflevector(c, d, 0, 4, 2, 6);                          \
        v4u32 t3 = __builtin_shufflevector(c, d, 1, 5, 3, 7);                          \
        a = __builtin_shufflevector(t0, t2, 0, 1, 4, 5);                               \
        b = __builtin_shufflevector(t1, t3, 0, 1, 4, 5);                               \
        c = __builtin_shufflevector(t0, t2, 2, 3, 6, 7);                               \
        d = __builtin_shufflevector(t1, t3, 2, 3, 6, 7);                               \
    }

/* Process 4 blocks (256 bytes) at once. Advances counter by 4. */
static void chacha20_blocks4(CvmcryptChaCha20* c, u8 const* in, u8* out) {
    v4u32 x[16];
    u32 orig[16];

    /* Broadcast state to 4 lanes. Counter (x[12]) gets +0,+1,+2,+3. */
    for (usize i = 0; i < 16; i++) {
        orig[i] = c->state[i];
        if (i == 12) {
            u32 ctr = c->state[12];
            v4u32 v = {ctr, ctr + 1, ctr + 2, ctr + 3};
            x[12] = v;
        } else {
            x[i] = v4u32_splat(c->state[i]);
        }
    }

    /* 20 rounds (10 × column + diagonal). */
    for (usize r = 0; r < 10; r++) {
        VQR(x[0], x[4], x[8], x[12])
        VQR(x[1], x[5], x[9], x[13])
        VQR(x[2], x[6], x[10], x[14])
        VQR(x[3], x[7], x[11], x[15])
        VQR(x[0], x[5], x[10], x[15])
        VQR(x[1], x[6], x[11], x[12])
        VQR(x[2], x[7], x[8], x[13])
        VQR(x[3], x[4], x[9], x[14])
    }

    /* Transpose: after rounds, x[i] = {val_block0, ..block1, ..block2, ..block3}.
     * After transpose: x[b + g*4] = block b's words g*4..g*4+3. */
    TRANSPOSE4(x[0], x[1], x[2], x[3])
    TRANSPOSE4(x[4], x[5], x[6], x[7])
    TRANSPOSE4(x[8], x[9], x[10], x[11])
    TRANSPOSE4(x[12], x[13], x[14], x[15])

    /* Original state as vectors (for the feed-forward addition). */
    v4u32 const orig_v[4] = {
        {orig[0], orig[1], orig[2], orig[3]},
        {orig[4], orig[5], orig[6], orig[7]},
        {orig[8], orig[9], orig[10], orig[11]},
        {orig[12], orig[13], orig[14], orig[15]},
    };

    /* Output: add orig state, XOR input, store — all in vector form. */
    for (usize b = 0; b < 4; b++) {
        u8* dst = out + b * 64;
        u8 const* src = in + b * 64;
        for (usize g = 0; g < 4; g++) {
            v4u32 ks = x[b + g * 4] + orig_v[g];
            /* Counter group (g==3): word 12 gets +b (block number). */
            if (g == 3) {
                v4u32 fix = {(u32)b, 0, 0, 0};
                ks += fix;
            }
            v4u32 in_v;
            __builtin_memcpy(&in_v, src + g * 16, 16);
            v4u32 out_v = ks ^ in_v;
            __builtin_memcpy(dst + g * 16, &out_v, 16);
        }
    }

    c->state[12] += 4;
}
#endif /* CHACHA20_VEC */

/* ------------------------------------------------------------------ */
/* scalar path (single block)                                           */
/* ------------------------------------------------------------------ */

#define QR(a, b, c, d)                                                                 \
    a += b;                                                                            \
    d ^= a;                                                                            \
    d = rotl32(d, 16);                                                                 \
    c += d;                                                                            \
    b ^= c;                                                                            \
    b = rotl32(b, 12);                                                                 \
    a += b;                                                                            \
    d ^= a;                                                                            \
    d = rotl32(d, 8);                                                                  \
    c += d;                                                                            \
    b ^= c;                                                                            \
    b = rotl32(b, 7);

void cvmcrypt_chacha20_init(CvmcryptChaCha20* c, u8 const key[32], u32 counter,
                            u8 const nonce[12]) {
    static u32 const SIGMA[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    c->state[0] = SIGMA[0];
    c->state[1] = SIGMA[1];
    c->state[2] = SIGMA[2];
    c->state[3] = SIGMA[3];
    for (usize i = 0; i < 8; i++) {
        c->state[4 + i] = load_le32(key + 4 * i);
    }
    c->state[12] = counter;
    c->state[13] = load_le32(nonce);
    c->state[14] = load_le32(nonce + 4);
    c->state[15] = load_le32(nonce + 8);
    c->pos = 64; /* No buffered keystream. */
}

static void chacha20_block(CvmcryptChaCha20* c, u8* out) {
    u32 x[16];
    u32 s[16];

    for (usize i = 0; i < 16; i++) {
        x[i] = c->state[i];
        s[i] = x[i];
    }

    for (usize i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12])
        QR(x[1], x[5], x[9], x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8], x[13])
        QR(x[3], x[4], x[9], x[14])
    }

    for (usize i = 0; i < 16; i++) {
        store_le32(out + 4 * i, x[i] + s[i]);
    }
}

void cvmcrypt_chacha20_xor(CvmcryptChaCha20* c, u8 const* in, usize len, u8* out) {
    /* Drain the buffered keystream first. */
    if (c->pos < 64) {
        usize n = 64 - c->pos;
        if (n > len)
            n = len;
        for (usize i = 0; i < n; i++) {
            out[i] = in[i] ^ c->buf[c->pos + i];
        }
        c->pos += n;
        in += n;
        out += n;
        len -= n;
    }

#ifdef CHACHA20_VEC
    /* Vector path: 4 blocks (256 bytes) at a time. */
    while (len >= 256) {
        chacha20_blocks4(c, in, out);
        in += 256;
        out += 256;
        len -= 256;
    }
#endif

    /* Scalar path for remaining full blocks. */
    while (len >= 64) {
        chacha20_block(c, c->buf);
        for (usize i = 0; i < 64; i++) {
            out[i] = in[i] ^ c->buf[i];
        }
        c->state[12]++;
        in += 64;
        out += 64;
        len -= 64;
    }

    /* Buffer a partial block for the next call. */
    if (len > 0) {
        chacha20_block(c, c->buf);
        for (usize i = 0; i < len; i++) {
            out[i] = in[i] ^ c->buf[i];
        }
        c->state[12]++;
        c->pos = len;
    } else {
        c->pos = 64;
    }
}
