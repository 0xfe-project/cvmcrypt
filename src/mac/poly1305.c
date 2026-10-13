/*
 * src/mac/poly1305.c
 *
 * Poly1305, RFC 8439 §2.5. Written from the spec.
 *
 * The accumulator h and the multiplier r are each held as five 26-bit
 * limbs (h[4] is the most significant). The carry from the multiply
 * propagates into h[4], which is then folded back via 2^130 ≡ 5
 * (mod 2^130 - 5).
 */

#include "mac/poly1305.h"

#include "base/mem.h"

CVM_INLINE u32 load_le32(u8 const* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

void cvmcrypt_poly1305_init(CvmcryptPoly1305* p, u8 const key[32]) {
    /* Clamp r: clear some high bits, set some low bits. */
    u32 r0 = load_le32(key) & 0x03ffffff;
    u32 r1 = (load_le32(key + 3) >> 2) & 0x03ffff03;
    u32 r2 = (load_le32(key + 6) >> 4) & 0x03ffc0ff;
    u32 r3 = (load_le32(key + 9) >> 6) & 0x03f03fff;
    u32 r4 = (load_le32(key + 12) >> 8) & 0x000fffff;

    p->r[0] = r0;
    p->r[1] = r1;
    p->r[2] = r2;
    p->r[3] = r3;
    p->r[4] = r4;

    for (usize i = 0; i < 5; i++) {
        p->h[i] = 0;
    }

    p->s[0] = load_le32(key + 16);
    p->s[1] = load_le32(key + 20);
    p->s[2] = load_le32(key + 24);
    p->s[3] = load_le32(key + 28);

    p->buflen = 0;
}

/* Process one 16-byte block (padded with 0x01 for the final partial). */
static void poly1305_block(CvmcryptPoly1305* p, u8 const block[16], bool final) {
    u64 d0, d1, d2, d3, d4;
    u32 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
    u32 const r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
    u64 c;

    /* Add the block to h. For a non-final block, the 2^128 bit is
     * implicit (the 0x01 we'd append). For a final partial block,
     * the 0x01 is already in the data. */
    d0 = (u64)load_le32(block) & 0x03ffffff;
    h0 += (u32)d0;

    d1 = ((u64)load_le32(block + 3) >> 2) & 0x03ffffff;
    h1 += (u32)d1;

    d2 = ((u64)load_le32(block + 6) >> 4) & 0x03ffffff;
    h2 += (u32)d2;

    d3 = ((u64)load_le32(block + 9) >> 6) & 0x03ffffff;
    h3 += (u32)d3;

    d4 = ((u64)load_le32(block + 12) >> 8) & 0x03ffffff;
    if (!final) {
        d4 += (1 << 24); /* the 2^128 bit: h4 += 1 in the top position */
    }
    h4 += (u32)d4;

    /* Multiply h by r (schoolbook, 26-bit limbs). */
    {
        u64 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        u64 hh0, hh1, hh2, hh3, hh4;

        hh0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 + (u64)h3 * s2 + (u64)h4 * s1;
        hh1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 + (u64)h3 * s3 + (u64)h4 * s2;
        hh2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 + (u64)h3 * s4 + (u64)h4 * s3;
        hh3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 + (u64)h3 * r0 + (u64)h4 * s4;
        hh4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 + (u64)h3 * r1 + (u64)h4 * r0;

        /* Carry propagation: 26-bit limbs. */
        c = hh0 >> 26;
        h0 = (u32)hh0 & 0x03ffffff;
        hh1 += c;
        c = hh1 >> 26;
        h1 = (u32)hh1 & 0x03ffffff;
        hh2 += c;
        c = hh2 >> 26;
        h2 = (u32)hh2 & 0x03ffffff;
        hh3 += c;
        c = hh3 >> 26;
        h3 = (u32)hh3 & 0x03ffffff;
        hh4 += c;
        c = hh4 >> 26;
        h4 = (u32)hh4 & 0x03ffffff;

        /* Fold the overflow back: h += c * 5 (since 2^130 ≡ 5). */
        h0 += (u32)c * 5;
        c = h0 >> 26;
        h0 &= 0x03ffffff;
        h1 += (u32)c;
    }

    p->h[0] = h0;
    p->h[1] = h1;
    p->h[2] = h2;
    p->h[3] = h3;
    p->h[4] = h4;
}

void cvmcrypt_poly1305_update(CvmcryptPoly1305* p, u8 const* data, usize len) {
    while (p->buflen > 0 && len > 0) {
        usize n = 16 - p->buflen;
        if (n > len)
            n = len;
        memcpy(p->buf + p->buflen, data, n);
        p->buflen += n;
        data += n;
        len -= n;
        if (p->buflen == 16) {
            poly1305_block(p, p->buf, false);
            p->buflen = 0;
        }
    }

    while (len >= 16) {
        poly1305_block(p, data, false);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        memcpy(p->buf, data, len);
        p->buflen = len;
    }
}

void cvmcrypt_poly1305_final(CvmcryptPoly1305* p, u8 tag[16]) {
    u32 h0, h1, h2, h3, h4, c;
    u32 g0, g1, g2, g3, g4;
    u64 f;
    u32 mask;

    /* Process any remaining partial block. */
    if (p->buflen > 0) {
        memset(p->buf + p->buflen, 0, 16 - p->buflen);
        p->buf[p->buflen] = 0x01; /* RFC 8439: append 1 then zeros. */
        poly1305_block(p, p->buf, true);
        p->buflen = 0;
    }

    /* Fully carry h. */
    h0 = p->h[0];
    h1 = p->h[1];
    h2 = p->h[2];
    h3 = p->h[3];
    h4 = p->h[4];

    c = h1 >> 26;
    h1 &= 0x03ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ffffff;
    h1 += c;

    /* Compute h + -p (i.e., h - (2^130 - 5)) for the final subtraction. */
    g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x03ffffff;
    g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x03ffffff;
    g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x03ffffff;
    g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x03ffffff;
    g4 = h4 + c - (1 << 26);

    /* Select h if h < p, or h + -p if h >= p. */
    mask = (g4 >> 31) - 1; /* all-ones if g4 is negative (h < p) */
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Pack h to 128 bits and add s. */
    f = (u64)h0 + ((u64)h1 << 26) + (u64)p->s[0];
    tag[0] = (u8)f;
    tag[1] = (u8)(f >> 8);
    tag[2] = (u8)(f >> 16);
    tag[3] = (u8)(f >> 24);

    f = (u64)(f >> 32) + ((u64)h2 << 20) + p->s[1];
    tag[4] = (u8)f;
    tag[5] = (u8)(f >> 8);
    tag[6] = (u8)(f >> 16);
    tag[7] = (u8)(f >> 24);

    f = (u64)(f >> 32) + ((u64)h3 << 14) + p->s[2];
    tag[8] = (u8)f;
    tag[9] = (u8)(f >> 8);
    tag[10] = (u8)(f >> 16);
    tag[11] = (u8)(f >> 24);

    f = (u64)(f >> 32) + ((u64)h4 << 8) + p->s[3];
    tag[12] = (u8)f;
    tag[13] = (u8)(f >> 8);
    tag[14] = (u8)(f >> 16);
    tag[15] = (u8)(f >> 24);

    memset(p, 0, sizeof(*p));
}

void cvmcrypt_poly1305(u8 const key[32], u8 const* data, usize len, u8 tag[16]) {
    CvmcryptPoly1305 p;
    cvmcrypt_poly1305_init(&p, key);
    cvmcrypt_poly1305_update(&p, data, len);
    cvmcrypt_poly1305_final(&p, tag);
}
