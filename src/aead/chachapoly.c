/*
 * src/aead/chachapoly.c
 *
 * ChaCha20-Poly1305 AEAD, RFC 8439 §2.8. The composition of the two
 * primitives cvmcrypt already carries: the first ChaCha20 block (with
 * counter 0) provides the Poly1305 one-time key, and the remaining
 * blocks (counter 1 onward) encrypt the plaintext.
 */

#include "aead/chachapoly.h"

#include "base/mem.h"
#include "base/secure.h"
#include "mac/poly1305.h"
#include "stream/chacha20.h"

#if defined(__aarch64__) || defined(__x86_64__)
/* Adopted from BoringSSL via ring 0.17.14 pregenerated/
 * (asm/chachapoly_arm64_{apple,elf}.S). Fused ChaCha20 + Poly1305: the
 * two primitives are interleaved, which is why it beats running our
 * separate implementations back to back. */
typedef struct {
    u32 key[8];
    u32 counter;
    u8 nonce[12];
    u8 const* extra_ciphertext;
    usize extra_ciphertext_len;
} ChaChaPolyIn;

/* The tag is written at offset 0, over the key, so this must be a union. */
typedef union {
    ChaChaPolyIn in;
    u8 tag[16];
} ChaChaPolyData;

#if defined(__aarch64__)
extern void chacha20_poly1305_seal(u8* out, u8 const* in, usize len, u8 const* ad,
                                   usize adlen, ChaChaPolyData* data);
extern void chacha20_poly1305_open(u8* out, u8 const* in, usize len, u8 const* ad,
                                   usize adlen, ChaChaPolyData* data);
#define chachapoly_seal_k chacha20_poly1305_seal
#define chachapoly_open_k chacha20_poly1305_open
#else
/* x86_64: SSE4.1 variant (SSSE3 + SSE4.1) and an AVX2+BMI2 one. */
extern void chacha20_poly1305_seal_sse41(u8* out, u8 const* in, usize len, u8 const* ad,
                                         usize adlen, ChaChaPolyData* data);
extern void chacha20_poly1305_open_sse41(u8* out, u8 const* in, usize len, u8 const* ad,
                                         usize adlen, ChaChaPolyData* data);
extern void chacha20_poly1305_seal_avx2(u8* out, u8 const* in, usize len, u8 const* ad,
                                        usize adlen, ChaChaPolyData* data);
extern void chacha20_poly1305_open_avx2(u8* out, u8 const* in, usize len, u8 const* ad,
                                        usize adlen, ChaChaPolyData* data);

/* 0 = portable, 1 = sse41, 2 = avx2 */
static u8 chachapoly_x86_level(void) {
#ifdef CVMCRYPT_CHACHAPOLY_FORCE_PORTABLE
    return 0;
#endif
    u32 a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    (void)a;
    (void)b;
    u8 ssse3 = (u8)((c >> 9) & 1);
    u8 sse41 = (u8)((c >> 19) & 1);
    u8 osxsave = (u8)((c >> 27) & 1);
    u8 avx = (u8)((c >> 28) & 1);
    if (!(ssse3 && sse41)) {
        return 0;
    }
    if (osxsave && avx) {
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7), "c"(0));
        u8 avx2 = (u8)((b >> 5) & 1);
        u8 bmi2 = (u8)((b >> 8) & 1);
        u32 xcr0_lo, xcr0_hi;
        __asm__ volatile("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
        (void)xcr0_hi;
        if (avx2 && bmi2 && ((xcr0_lo & 0x6) == 0x6)) {
            return 2;
        }
    }
    return 1;
}
/* Runtime dispatch: x86_64 picks AVX2 / SSE4.1 / portable. */
#ifdef CVMCRYPT_CHACHAPOLY_FORCE_PORTABLE
#define chachapoly_level() 0
#else
static u8 g_chachapoly_level = 0xff;
static u8 chachapoly_level(void) {
    if (g_chachapoly_level == 0xff) {
        g_chachapoly_level = chachapoly_x86_level();
    }
    return g_chachapoly_level;
}
#endif
#endif

/* The asm needs a 16-byte-aligned, 16-byte-sized data block and a callable
 * AAD pointer (NULL is not obviously safe), so use a static zero block for
 * the empty case. */
static u8 const EMPTY_AAD[16] = {0};

static void asm_data_init(ChaChaPolyData* d, u8 const key[32], u8 const nonce[12]) {
    memset(d, 0, sizeof(*d));
    for (int i = 0; i < 8; i++) {
        u32 w;
        memcpy(&w, key + 4 * i, 4);
        d->in.key[i] = w;
    }
    d->in.counter = 0;
    memcpy(d->in.nonce, nonce, 12);
}
#endif

/* Generate the Poly1305 key from the first ChaCha20 block. */
__attribute__((unused)) static void make_poly_key(u8 const key[32], u8 const nonce[12],
                                                  u8 poly_key[32]) {
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 0, nonce);
    /* We only need the first 32 bytes of the first block. */
    /* Generate the block and take bytes 0-31. */
    /* The chacha20_xor with 32 zero bytes gives us what we need. */
    u8 zeros[32] = {0};
    cvmcrypt_chacha20_xor(&c, zeros, 32, poly_key);
}

/* Feed AAD and ciphertext into Poly1305 with padding and lengths. */
__attribute__((unused)) static void poly_tag(u8 const poly_key[32], u8 const* aad,
                                             usize aadlen, u8 const* ct, usize ctlen,
                                             u8 tag[16]) {
    CvmcryptPoly1305 p;
    cvmcrypt_poly1305_init(&p, poly_key);

    /* AAD padded to 16-byte boundary. */
    cvmcrypt_poly1305_update(&p, aad, aadlen);
    if (aadlen % 16 != 0) {
        u8 pad[16] = {0};
        cvmcrypt_poly1305_update(&p, pad, 16 - (aadlen % 16));
    }

    /* Ciphertext padded to 16-byte boundary. */
    cvmcrypt_poly1305_update(&p, ct, ctlen);
    if (ctlen % 16 != 0) {
        u8 pad[16] = {0};
        cvmcrypt_poly1305_update(&p, pad, 16 - (ctlen % 16));
    }

    /* Lengths: aadlen (LE 64-bit) || ctlen (LE 64-bit). */
    u8 lenblk[16];
    for (usize i = 0; i < 8; i++) {
        lenblk[i] = (u8)(aadlen >> (8 * i));
        lenblk[8 + i] = (u8)(ctlen >> (8 * i));
    }
    cvmcrypt_poly1305_update(&p, lenblk, 16);

    cvmcrypt_poly1305_final(&p, tag);
}

/* Portable composition: block-0 Poly1305 key, ChaCha20 from counter 1,
 * Poly1305 over AAD || pad || ct || pad || lengths. */
__attribute__((unused)) static void
chachapoly_encrypt_portable(u8 const key[32], u8 const nonce[12], u8 const* aad,
                            usize aadlen, u8 const* pt, usize ptlen, u8* ct,
                            u8 tag[16]) {
    u8 poly_key[32];
    make_poly_key(key, nonce, poly_key);
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);
    cvmcrypt_chacha20_xor(&c, pt, ptlen, ct);
    poly_tag(poly_key, aad, aadlen, ct, ptlen, tag);
    memset(poly_key, 0, sizeof(poly_key));
}

__attribute__((unused)) static bool
chachapoly_decrypt_portable(u8 const key[32], u8 const nonce[12], u8 const* aad,
                            usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                            u8 const tag[16]) {
    u8 poly_key[32];
    make_poly_key(key, nonce, poly_key);
    u8 expected[16];
    poly_tag(poly_key, aad, aadlen, ct, ctlen, expected);
    if (!cvmcrypt_ct_eq(expected, tag, 16)) {
        memset(poly_key, 0, sizeof(poly_key));
        if (pt && ctlen > 0) {
            memset(pt, 0, ctlen);
        }
        return false;
    }
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);
    cvmcrypt_chacha20_xor(&c, ct, ctlen, pt);
    memset(poly_key, 0, sizeof(poly_key));
    return true;
}

void cvmcrypt_chachapoly_encrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* pt, usize ptlen, u8* ct,
                                 u8 tag[16]) {
#if defined(__aarch64__)
    ChaChaPolyData d;
    asm_data_init(&d, key, nonce);
    chacha20_poly1305_seal(ct, pt, ptlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    memcpy(tag, d.tag, 16);
    memset(&d, 0, sizeof(d));
#elif defined(__x86_64__)
    u8 lv = chachapoly_level();
    if (lv == 0) {
        chachapoly_encrypt_portable(key, nonce, aad, aadlen, pt, ptlen, ct, tag);
        return;
    }
    ChaChaPolyData d;
    asm_data_init(&d, key, nonce);
    if (lv >= 2) {
        chacha20_poly1305_seal_avx2(ct, pt, ptlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    } else {
        chacha20_poly1305_seal_sse41(ct, pt, ptlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    }
    memcpy(tag, d.tag, 16);
    memset(&d, 0, sizeof(d));
#else
    chachapoly_encrypt_portable(key, nonce, aad, aadlen, pt, ptlen, ct, tag);
#endif
}

bool cvmcrypt_chachapoly_decrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                                 u8 const tag[16]) {
#if defined(__aarch64__)
    /* open() verifies the tag itself and zeroes the plaintext on failure. */
    ChaChaPolyData d;
    asm_data_init(&d, key, nonce);
    memset(pt, 0, ctlen);
    chacha20_poly1305_open(pt, ct, ctlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    bool ok = cvmcrypt_ct_eq(d.tag, tag, 16);
    if (!ok && pt && ctlen > 0) {
        memset(pt, 0, ctlen);
    }
    memset(&d, 0, sizeof(d));
    return ok;
#elif defined(__x86_64__)
    u8 lv = chachapoly_level();
    if (lv == 0) {
        return chachapoly_decrypt_portable(key, nonce, aad, aadlen, ct, ctlen, pt, tag);
    }
    ChaChaPolyData d;
    asm_data_init(&d, key, nonce);
    memset(pt, 0, ctlen);
    if (lv >= 2) {
        chacha20_poly1305_open_avx2(pt, ct, ctlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    } else {
        chacha20_poly1305_open_sse41(pt, ct, ctlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    }
    bool ok = cvmcrypt_ct_eq(d.tag, tag, 16);
    if (!ok && pt && ctlen > 0) {
        memset(pt, 0, ctlen);
    }
    memset(&d, 0, sizeof(d));
    return ok;
#else
    return chachapoly_decrypt_portable(key, nonce, aad, aadlen, ct, ctlen, pt, tag);
#endif
}
