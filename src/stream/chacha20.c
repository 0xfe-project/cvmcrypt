/*
 * src/stream/chacha20.c
 *
 * ChaCha20 (RFC 8439 §2.4).
 *
 * The scalar path is correct and verified. The vector extension path
 * (v4u32, one source for both platforms) is the target implementation;
 * see the SIMD note in PLAN.md. The diagonal round's lane-rotation
 * needs debugging before the vector path replaces the scalar one.
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
        /* Column rounds */
        QR(x[0], x[4], x[8], x[12])
        QR(x[1], x[5], x[9], x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        /* Diagonal rounds */
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

    /* Full blocks straight from the block function. */
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
