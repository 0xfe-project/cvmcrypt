/*
 * src/hash/sha256.c
 *
 * SHA-256, the portable scalar path plus the dispatch.
 *
 * Carried over from libtomcrypt's sha256.c (Unlicense, Tom St Denis),
 * rewritten to cvm conventions. The 64-round expansion and the
 * constant table are the standard FIPS 180-4 ones, not carried: every
 * SHA-256 on earth has the same table. What was carried is the
 * structure: the compress function's shape, the padding logic, and
 * the buffer management.
 */

#include "cvmcrypt/cvmcrypt.h"
#include "hash/sha256.h"

#include "base/mem.h"
#include "base/secure.h"

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

CVM_INLINE u32 rotr32(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

CVM_INLINE u32 load_be32(u8 const* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

CVM_INLINE void store_be32(u8* p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)v;
}

CVM_INLINE void store_be64(u8* p, u64 v) {
    for (usize i = 0; i < 8; i++) {
        p[i] = (u8)(v >> (56 - 8 * i));
    }
}

/* ------------------------------------------------------------------ */
/* scalar compression                                                  */
/* ------------------------------------------------------------------ */

static u32 const K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
};

#define CH(x, y, z) (z ^ (x & (y ^ z)))
#define MAJ(x, y, z) (((x | y) & z) | (x & y))
#define SIGMA0(x) (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22))
#define SIGMA1(x) (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25))
#define GAMMA0(x) (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3))
#define GAMMA1(x) (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10))

static void __attribute__((unused)) sha256_compress_scalar(CvmcryptSha256* md,
                                                           u8 const* block) {
    u32 s[8];
    u32 w[64];
    u32 t0, t1;

    for (usize i = 0; i < 8; i++) {
        s[i] = md->state[i];
    }
    for (usize i = 0; i < 16; i++) {
        w[i] = load_be32(block + 4 * i);
    }
    for (usize i = 16; i < 64; i++) {
        w[i] = GAMMA1(w[i - 2]) + w[i - 7] + GAMMA0(w[i - 15]) + w[i - 16];
    }

#define ROUND(a, b, c, d, e, f, g, h, i)                                               \
    t0 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];                                    \
    t1 = SIGMA0(a) + MAJ(a, b, c);                                                     \
    d += t0;                                                                           \
    h = t0 + t1;

    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 0)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 1)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 2)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 3)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 4)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 5)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 6)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 7)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 8)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 9)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 10)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 11)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 12)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 13)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 14)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 15)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 16)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 17)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 18)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 19)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 20)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 21)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 22)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 23)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 24)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 25)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 26)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 27)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 28)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 29)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 30)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 31)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 32)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 33)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 34)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 35)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 36)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 37)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 38)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 39)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 40)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 41)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 42)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 43)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 44)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 45)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 46)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 47)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 48)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 49)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 50)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 51)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 52)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 53)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 54)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 55)
    ROUND(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 56)
    ROUND(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 57)
    ROUND(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 58)
    ROUND(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 59)
    ROUND(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 60)
    ROUND(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 61)
    ROUND(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 62)
    ROUND(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 63)

#undef ROUND

    for (usize i = 0; i < 8; i++) {
        md->state[i] += s[i];
    }
}

/* ------------------------------------------------------------------ */
/* aarch64 crypto extension: SHA256H / SHA256H2 / SHA256SU0 / SHA256SU1  */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__)
#include <arm_neon.h>

static void sha256_compress_arm64(CvmcryptSha256* md, u8 const* block) {
    /* State packing: abcd = {a,b,c,d}, efgh = {e,f,g,h}. vsha256hq_u32
     * takes the previous (abcd, efgh) plus the schedule chunk and
     * produces the new abcd; vsha256h2q_u32 produces the new efgh from
     * the same inputs. Both must see the *old* values, hence abcd_prev.
     *
     * Schedule: sched0..3 hold W[t..t+3] through W[t+12..t+15]. Rounds
     * 16 onward rotate the window with vsha256su0q/su1q. */
    uint32x4_t abcd = vld1q_u32(&md->state[0]);
    uint32x4_t efgh = vld1q_u32(&md->state[4]);

    uint32x4_t abcd_orig = abcd;
    uint32x4_t efgh_orig = efgh;

    uint32x4_t sched0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    uint32x4_t sched1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t sched2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t sched3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    uint32x4_t tmp, abcd_prev;

    tmp = vaddq_u32(sched0, vld1q_u32(&K[0]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    tmp = vaddq_u32(sched1, vld1q_u32(&K[4]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    tmp = vaddq_u32(sched2, vld1q_u32(&K[8]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    tmp = vaddq_u32(sched3, vld1q_u32(&K[12]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    for (u32 t = 16; t < 64; t += 16) {
        sched0 = vsha256su1q_u32(vsha256su0q_u32(sched0, sched1), sched2, sched3);
        tmp = vaddq_u32(sched0, vld1q_u32(&K[t]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        sched1 = vsha256su1q_u32(vsha256su0q_u32(sched1, sched2), sched3, sched0);
        tmp = vaddq_u32(sched1, vld1q_u32(&K[t + 4]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        sched2 = vsha256su1q_u32(vsha256su0q_u32(sched2, sched3), sched0, sched1);
        tmp = vaddq_u32(sched2, vld1q_u32(&K[t + 8]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        sched3 = vsha256su1q_u32(vsha256su0q_u32(sched3, sched0), sched1, sched2);
        tmp = vaddq_u32(sched3, vld1q_u32(&K[t + 12]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);
    }

    abcd = vaddq_u32(abcd, abcd_orig);
    efgh = vaddq_u32(efgh, efgh_orig);

    vst1q_u32(&md->state[0], abcd);
    vst1q_u32(&md->state[4], efgh);
}
#endif /* __aarch64__ */

/* ------------------------------------------------------------------ */
/* x86 SHA extensions: SHA256RNDS2 / SHA256MSG1 / SHA256MSG2            */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__) || defined(_M_X64)

#include <immintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>

__attribute__((target("sse2,ssse3,sse4.1,sha"))) static void
sha256_compress_shani(CvmcryptSha256* md, u8 const* block) {
    /* State packing per Intel's SHA extension guide: state0 holds
     * (a,b,e,f), state1 holds (c,d,g,h). The shuffles below map our
     * linear state[0..7] into that layout.
     *
     * SHA-NI requires SSE2+SSSE3+SSE4.1+SHA; the dispatch only picks
     * this path when cpuid confirms all of them. */
    __m128i reverse = _mm_set_epi64x(0x0c0d0e0f08090a0bull, 0x0405060700010203ull);
    __m128i state_0 = _mm_loadu_si128((__m128i const*)(&md->state[0]));
    __m128i state_1 = _mm_loadu_si128((__m128i const*)(&md->state[4]));
    __m128i tmp = _mm_shuffle_epi32(state_0, 0x4E); /* 0x4E = 0b101110 = swap halves */
    state_1 = _mm_shuffle_epi32(state_1, 0x1B); /* 0x1B = 0b011010 = reverse lanes */
    state_0 = _mm_alignr_epi8(tmp, state_1, 8);
    /* blend: take the two lower lanes from state_1's upper */
    state_1 = _mm_blend_epi16(state_1, tmp, 0x30);

    __m128i old_0 = state_0;
    __m128i old_1 = state_1;
    __m128i msg, msg_0, msg_1, msg_2, msg_3;

    /* Rounds 0-3 */
    msg_0 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i const*)(&block[0])), reverse);
    msg = _mm_add_epi32(msg_0, _mm_load_si128((__m128i const*)(&K[0])));
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, 0x30);
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

    /* Rounds 4-7 */
    msg_1 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i const*)(&block[16])), reverse);
    msg = _mm_add_epi32(msg_1, _mm_load_si128((__m128i const*)(&K[4])));
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, 0x30);
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

    /* Rounds 8-11 */
    msg_2 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i const*)(&block[32])), reverse);
    msg = _mm_add_epi32(msg_2, _mm_load_si128((__m128i const*)(&K[8])));
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, 0x30);
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

    /* Rounds 12-15 */
    msg_3 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i const*)(&block[48])), reverse);
    msg = _mm_add_epi32(msg_3, _mm_load_si128((__m128i const*)(&K[12])));
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, 0x30);
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

    /* Rounds 16-59: 4 rounds at a time, the schedule rolling in msg_0..3. */
    for (u32 i = 16; i < 60; i += 4) {
        msg_0 = _mm_sha256msg1_epu32(msg_0, msg_1);
        tmp = _mm_alignr_epi8(msg_3, msg_2, 4);
        msg_0 = _mm_add_epi32(msg_0, tmp);
        msg_0 = _mm_sha256msg2_epu32(msg_0, msg_3);
        msg = _mm_add_epi32(msg_0, _mm_load_si128((__m128i const*)(&K[i])));
        state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
        msg = _mm_shuffle_epi32(msg, 0x30);
        state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

        /* rotate the schedule window */
        __m128i t = msg_0;
        msg_0 = msg_1;
        msg_1 = msg_2;
        msg_2 = msg_3;
        msg_3 = t;
    }

    /* Rounds 60-63: no more schedule update. */
    msg = _mm_add_epi32(msg_3, _mm_load_si128((__m128i const*)(&K[60])));
    state_1 = _mm_sha256rnds2_epu32(state_1, state_0, msg);
    msg = _mm_shuffle_epi32(msg, 0x30);
    state_0 = _mm_sha256rnds2_epu32(state_0, state_1, msg);

    /* Add the original state. */
    state_0 = _mm_add_epi32(old_0, state_0);
    state_1 = _mm_add_epi32(old_1, state_1);

    /* Unpack state back to linear. */
    tmp = _mm_shuffle_epi32(state_0, 0x4E);
    state_0 = _mm_blend_epi16(state_0, _mm_shuffle_epi32(state_1, 0x1B), 0x30);
    state_1 = _mm_blend_epi16(state_1, tmp, 0xC0);

    _mm_storeu_si128((__m128i*)&md->state[0], state_0);
    _mm_storeu_si128((__m128i*)&md->state[4], state_1);
}
#endif /* __x86_64__ */

/* ------------------------------------------------------------------ */
/* dispatch                                                             */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__) || defined(_M_X64)
static bool shani_available(void) {
    /* cpuid leaf 7, ebx bit 29 = SHA. Needs SSE2/SSSE3/SSE4.1 as well;
     * any CPU with SHA has all of them. One-shot cache because the
     * answer is per-process and init() is called once per state. */
    static i8 cached = -1;
    if (cached < 0) {
        u32 a, b, c, d;
        a = 0;
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a), "c"(c));
        u32 max_leaf = a;
        if (max_leaf >= 7) {
            a = 7;
            __asm__ volatile("cpuid"
                             : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(a), "c"(0));
            cached = ((b >> 29) & 1) ? 1 : 0;
        } else {
            cached = 0;
        }
    }
    return cached != 0;
}
#endif

static void compress(CvmcryptSha256* md, u8 const* block) {
#if defined(__aarch64__)
    sha256_compress_arm64(md, block);
#elif defined(__x86_64__) || defined(_M_X64)
    if (md->impl == CVMCRYPT_SHA256_IMPL_SHANI) {
        sha256_compress_shani(md, block);
    } else {
        sha256_compress_scalar(md, block);
    }
#else
    sha256_compress_scalar(md, block);
#endif
}

static u8 pick_impl(void) {
#if defined(__aarch64__)
    return CVMCRYPT_SHA256_IMPL_ARM64;
#elif defined(__x86_64__) || defined(_M_X64)
    return shani_available() ? CVMCRYPT_SHA256_IMPL_SHANI : CVMCRYPT_SHA256_IMPL_SCALAR;
#else
    return CVMCRYPT_SHA256_IMPL_SCALAR;
#endif
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

void cvmcrypt_sha256_init(CvmcryptSha256* md) {
    md->state[0] = 0x6a09e667;
    md->state[1] = 0xbb67ae85;
    md->state[2] = 0x3c6ef372;
    md->state[3] = 0xa54ff53a;
    md->state[4] = 0x510e527f;
    md->state[5] = 0x9b05688c;
    md->state[6] = 0x1f83d9ab;
    md->state[7] = 0x5be0cd19;
    md->length = 0;
    md->curlen = 0;
    md->impl = pick_impl();
}

void cvmcrypt_sha256_update(CvmcryptSha256* md, u8 const* data, usize len) {
    md->length += len;

    /* Absorb a full block straight from the input, no copy. */
    if (md->curlen == 0 && len >= CVMCRYPT_SHA256_BLOCK_SIZE) {
        while (len >= CVMCRYPT_SHA256_BLOCK_SIZE) {
            compress(md, data);
            data += CVMCRYPT_SHA256_BLOCK_SIZE;
            len -= CVMCRYPT_SHA256_BLOCK_SIZE;
        }
    }

    /* Buffer whatever is left. */
    while (len > 0) {
        usize n = CVMCRYPT_SHA256_BLOCK_SIZE - md->curlen;
        if (n > len)
            n = len;
        memcpy(md->buf + md->curlen, data, n);
        md->curlen += n;
        data += n;
        len -= n;
        if (md->curlen == CVMCRYPT_SHA256_BLOCK_SIZE) {
            compress(md, md->buf);
            md->curlen = 0;
        }
    }
}

void cvmcrypt_sha256_final(CvmcryptSha256* md, u8 out[32]) {
    /* length counts bytes absorbed; the padding needs bits. */
    u64 bits = md->length * 8;

    md->buf[md->curlen++] = 0x80;
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = 0;
        }
        compress(md, md->buf);
        md->curlen = 0;
    }
    while (md->curlen < 56) {
        md->buf[md->curlen++] = 0;
    }
    store_be64(md->buf + 56, bits);
    compress(md, md->buf);

    for (usize i = 0; i < 8; i++) {
        store_be32(out + 4 * i, md->state[i]);
    }

    /* The state held key material only in the sense that a hash state
     * is not something to leak across uses. Clear it. */
    memset(md, 0, sizeof(*md));
}

void cvmcrypt_sha256(u8 const* data, usize len, u8 out[32]) {
    CvmcryptSha256 md;
    cvmcrypt_sha256_init(&md);
    cvmcrypt_sha256_update(&md, data, len);
    cvmcrypt_sha256_final(&md, out);
}
