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

#if defined(__aarch64__)
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

extern void chacha20_poly1305_seal(u8* out, u8 const* in, usize len, u8 const* ad,
                                   usize adlen, ChaChaPolyData* data);
extern void chacha20_poly1305_open(u8* out, u8 const* in, usize len, u8 const* ad,
                                   usize adlen, ChaChaPolyData* data);

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

void cvmcrypt_chachapoly_encrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* pt, usize ptlen, u8* ct,
                                 u8 tag[16]) {
#if defined(__aarch64__)
    ChaChaPolyData d;
    asm_data_init(&d, key, nonce);
    chacha20_poly1305_seal(ct, pt, ptlen, aad ? aad : EMPTY_AAD, aadlen, &d);
    memcpy(tag, d.tag, 16);
    memset(&d, 0, sizeof(d));
#else
    /* Poly1305 key from block 0. */
    u8 poly_key[32];
    make_poly_key(key, nonce, poly_key);

    /* Encrypt with counter starting at 1. */
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);
    cvmcrypt_chacha20_xor(&c, pt, ptlen, ct);

    /* Tag over AAD || pad || ct || pad || lengths. */
    poly_tag(poly_key, aad, aadlen, ct, ptlen, tag);

    /* Clear the one-time key. */
    memset(poly_key, 0, sizeof(poly_key));
#endif
}

bool cvmcrypt_chachapoly_decrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                                 u8 const tag[16]) {
#if defined(__aarch64__)
    /* open() verifies the tag itself and zeroes the plaintext on failure,
     * so there is no separate tag comparison here. */
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
#else
    u8 poly_key[32];
    make_poly_key(key, nonce, poly_key);

    /* Compute the expected tag. */
    u8 expected[16];
    poly_tag(poly_key, aad, aadlen, ct, ctlen, expected);

    /* Constant-time tag comparison. */
    if (!cvmcrypt_ct_eq(expected, tag, 16)) {
        memset(poly_key, 0, sizeof(poly_key));
        if (pt && ctlen > 0) {
            memset(pt, 0, ctlen);
        }
        return false;
    }

    /* Decrypt with counter starting at 1. */
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);
    cvmcrypt_chacha20_xor(&c, ct, ctlen, pt);

    memset(poly_key, 0, sizeof(poly_key));
    return true;
#endif
}
