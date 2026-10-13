/*
 * src/hash/sha512.c
 *
 * SHA-512 / SHA-384 compression, scalar path plus aarch64 FEAT_SHA512.
 *
 * Carried over from libtomcrypt's sha512.c (Unlicense). The arm64
 * path follows Mbed TLS 3.6.7's sha512.c (Apache-2.0): SHA512H and
 * SHA512H2 have no clang intrinsic, so the two instructions are
 * written as inline asm.
 *
 * Note on u32 state[8]: the words are u64; the struct stores them as
 * u32 pairs because FEAT_SHA512 loads uint64x2_t and this keeps the
 * scalar path's alignment guarantee without a union.
 */

#include "cvmcrypt/cvmcrypt.h"
#include "hash/sha512.h"

#include "base/mem.h"

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

CVM_INLINE u64 rotr64(u64 x, u32 n) {
    return (x >> n) | (x << (64 - n));
}

CVM_INLINE u64 load_be64(u8 const* p) {
    return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) |
           ((u64)p[3] << 32) | ((u64)p[4] << 24) | ((u64)p[5] << 16) |
           ((u64)p[6] << 8) | (u64)p[7];
}

CVM_INLINE void store_be64(u8* p, u64 v) {
    for (usize i = 0; i < 8; i++) {
        p[i] = (u8)(v >> (56 - 8 * i));
    }
}

/* ------------------------------------------------------------------ */
/* constant table                                                      */
/* ------------------------------------------------------------------ */

static u64 const K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/* ------------------------------------------------------------------ */
/* scalar compression                                                  */
/* ------------------------------------------------------------------ */

#define CH64(x, y, z) (z ^ (x & (y ^ z)))
#define MAJ64(x, y, z) (((x | y) & z) | (x & y))
#define SIGMA0_64(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define SIGMA1_64(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define GAMMA0_64(x) (rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7))
#define GAMMA1_64(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6))

static void __attribute__((unused)) sha512_compress_scalar(CvmcryptSha512* md,
                                                           u8 const* block) {
    u64 s[8];
    u64 w[80];
    u64 t0, t1;

    for (usize i = 0; i < 8; i++) {
        s[i] = md->state[i];
    }
    for (usize i = 0; i < 16; i++) {
        w[i] = load_be64(block + 8 * i);
    }
    for (usize i = 16; i < 80; i++) {
        w[i] = GAMMA1_64(w[i - 2]) + w[i - 7] + GAMMA0_64(w[i - 15]) + w[i - 16];
    }

#define RND(a, b, c, d, e, f, g, h, i)                                                 \
    t0 = h + SIGMA1_64(e) + CH64(e, f, g) + K[i] + w[i];                               \
    t1 = SIGMA0_64(a) + MAJ64(a, b, c);                                                \
    d += t0;                                                                           \
    h = t0 + t1;

    /* 80 rounds, rotating the working variables. */
    for (usize i = 0; i < 80; i++) {
        RND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], i)
        u64 t = s[7];
        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = s[3];
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = t;
    }

#undef RND

    for (usize i = 0; i < 8; i++) {
        md->state[i] += s[i];
    }
}

/* ------------------------------------------------------------------ */
/* aarch64 FEAT_SHA512                                                 */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__)
#include <arm_neon.h>

/* Clang 17+ and GCC 14+ provide these intrinsics with target("sha3,neon")
 * (FEAT_SHA512, ARMv8.2). No inline asm needed — arm_neon.h has them. */
__attribute__((target("sha3,neon"))) static void
sha512_compress_arm64(CvmcryptSha512* md, u8 const* block) {
    uint64x2_t ab = vld1q_u64(&md->state[0]);
    uint64x2_t cd = vld1q_u64(&md->state[2]);
    uint64x2_t ef = vld1q_u64(&md->state[4]);
    uint64x2_t gh = vld1q_u64(&md->state[6]);

    uint64x2_t ab_orig = ab;
    uint64x2_t cd_orig = cd;
    uint64x2_t ef_orig = ef;
    uint64x2_t gh_orig = gh;

    uint64x2_t s0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 0)));
    uint64x2_t s1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 16)));
    uint64x2_t s2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 32)));
    uint64x2_t s3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 48)));
    uint64x2_t s4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 64)));
    uint64x2_t s5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 80)));
    uint64x2_t s6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 96)));
    uint64x2_t s7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 112)));

    uint64x2_t initial_sum, sum, intermed;

#define R4(a, b, c, d, sched, idx)                                                     \
    initial_sum = vaddq_u64(sched, vld1q_u64(&K[idx]));                                \
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), d);                        \
    intermed = vsha512hq_u64(sum, vextq_u64(c, d, 1), vextq_u64(b, c, 1));             \
    d = vsha512h2q_u64(intermed, b, a);                                                \
    b = vaddq_u64(b, intermed);

    /* Rounds 0-15: schedule from input. */
    R4(ab, cd, ef, gh, s0, 0)
    R4(gh, ab, cd, ef, s1, 2)
    R4(ef, gh, ab, cd, s2, 4)
    R4(cd, ef, gh, ab, s3, 6)
    R4(ab, cd, ef, gh, s4, 8)
    R4(gh, ab, cd, ef, s5, 10)
    R4(ef, gh, ab, cd, s6, 12)
    R4(cd, ef, gh, ab, s7, 14)

    /* Rounds 16-79: schedule rolling. */
    for (u32 t = 16; t < 80; t += 16) {
        s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
        R4(ab, cd, ef, gh, s0, t)
        s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
        R4(gh, ab, cd, ef, s1, t + 2)
        s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
        R4(ef, gh, ab, cd, s2, t + 4)
        s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
        R4(cd, ef, gh, ab, s3, t + 6)
        s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
        R4(ab, cd, ef, gh, s4, t + 8)
        s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
        R4(gh, ab, cd, ef, s5, t + 10)
        s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
        R4(ef, gh, ab, cd, s6, t + 12)
        s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
        R4(cd, ef, gh, ab, s7, t + 14)
    }

#undef R4

    ab = vaddq_u64(ab, ab_orig);
    cd = vaddq_u64(cd, cd_orig);
    ef = vaddq_u64(ef, ef_orig);
    gh = vaddq_u64(gh, gh_orig);

    vst1q_u64(&md->state[0], ab);
    vst1q_u64(&md->state[2], cd);
    vst1q_u64(&md->state[4], ef);
    vst1q_u64(&md->state[6], gh);
}
#endif /* __aarch64__ */

/* ------------------------------------------------------------------ */
/* dispatch + padding                                                  */
/* ------------------------------------------------------------------ */

static void compress(CvmcryptSha512* md, u8 const* block) {
#if defined(__aarch64__) && !defined(CVMCRYPT_SHA512_FORCE_SCALAR)
    sha512_compress_arm64(md, block);
#else
    sha512_compress_scalar(md, block);
#endif
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

void cvmcrypt_sha512_init(CvmcryptSha512* md) {
    md->state[0] = 0x6a09e667f3bcc908;
    md->state[1] = 0xbb67ae8584caa73b;
    md->state[2] = 0x3c6ef372fe94f82b;
    md->state[3] = 0xa54ff53a5f1d36f1;
    md->state[4] = 0x510e527fade682d1;
    md->state[5] = 0x9b05688c2b3e6c1f;
    md->state[6] = 0x1f83d9abfb41bd6b;
    md->state[7] = 0x5be0cd19137e2179;
    md->length = 0;
    md->curlen = 0;
#if defined(__aarch64__)
    md->impl = CVMCRYPT_SHA512_IMPL_ARM64;
#else
    md->impl = CVMCRYPT_SHA512_IMPL_SCALAR;
#endif
}

void cvmcrypt_sha384_init(CvmcryptSha512* md) {
    md->state[0] = 0xcbbb9d5dc1059ed8;
    md->state[1] = 0x629a292a367cd507;
    md->state[2] = 0x9159015a3070dd17;
    md->state[3] = 0x152fecd8f70e5939;
    md->state[4] = 0x67332667ffc00b31;
    md->state[5] = 0x8eb44a8768581511;
    md->state[6] = 0xdb0c2e0d64f98fa7;
    md->state[7] = 0x47b5481dbefa4fa4;
    md->length = 0;
    md->curlen = 0;
#if defined(__aarch64__)
    md->impl = CVMCRYPT_SHA512_IMPL_ARM64;
#else
    md->impl = CVMCRYPT_SHA512_IMPL_SCALAR;
#endif
}

void cvmcrypt_sha512_update(CvmcryptSha512* md, u8 const* data, usize len) {
    md->length += len;

    if (md->curlen == 0 && len >= CVMCRYPT_SHA512_BLOCK_SIZE) {
        while (len >= CVMCRYPT_SHA512_BLOCK_SIZE) {
            compress(md, data);
            data += CVMCRYPT_SHA512_BLOCK_SIZE;
            len -= CVMCRYPT_SHA512_BLOCK_SIZE;
        }
    }

    while (len > 0) {
        usize n = CVMCRYPT_SHA512_BLOCK_SIZE - md->curlen;
        if (n > len)
            n = len;
        memcpy(md->buf + md->curlen, data, n);
        md->curlen += n;
        data += n;
        len -= n;
        if (md->curlen == CVMCRYPT_SHA512_BLOCK_SIZE) {
            compress(md, md->buf);
            md->curlen = 0;
        }
    }
}

static void finalize(CvmcryptSha512* md, u8* out, usize outlen) {
    u64 bits = md->length * 8;

    md->buf[md->curlen++] = 0x80;
    /* SHA-512 padding: 128-byte block, 16 bytes of length. */
    if (md->curlen > 112) {
        while (md->curlen < 128) {
            md->buf[md->curlen++] = 0;
        }
        compress(md, md->buf);
        md->curlen = 0;
    }
    while (md->curlen < 112) {
        md->buf[md->curlen++] = 0;
    }
    /* SHA-512 uses a 128-bit length field; the upper 64 bits are zero
     * for anything we will ever hash. */
    store_be64(md->buf + 112, 0);
    store_be64(md->buf + 120, bits);
    compress(md, md->buf);

    for (usize i = 0; i < outlen / 8; i++) {
        store_be64(out + 8 * i, md->state[i]);
    }
    memset(md, 0, sizeof(*md));
}

void cvmcrypt_sha512_final(CvmcryptSha512* md, u8 out[64]) {
    finalize(md, out, 64);
}

void cvmcrypt_sha384_final(CvmcryptSha512* md, u8 out[48]) {
    finalize(md, out, 48);
}

void cvmcrypt_sha512(u8 const* data, usize len, u8 out[64]) {
    CvmcryptSha512 md;
    cvmcrypt_sha512_init(&md);
    cvmcrypt_sha512_update(&md, data, len);
    cvmcrypt_sha512_final(&md, out);
}

void cvmcrypt_sha384(u8 const* data, usize len, u8 out[48]) {
    CvmcryptSha512 md;
    cvmcrypt_sha384_init(&md);
    cvmcrypt_sha512_update(&md, data, len);
    cvmcrypt_sha384_final(&md, out);
}
