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

/* Generate the Poly1305 key from the first ChaCha20 block. */
static void make_poly_key(u8 const key[32], u8 const nonce[12], u8 poly_key[32]) {
    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 0, nonce);
    /* We only need the first 32 bytes of the first block. */
    /* Generate the block and take bytes 0-31. */
    /* The chacha20_xor with 32 zero bytes gives us what we need. */
    u8 zeros[32] = {0};
    cvmcrypt_chacha20_xor(&c, zeros, 32, poly_key);
}

/* Feed AAD and ciphertext into Poly1305 with padding and lengths. */
static void poly_tag(u8 const poly_key[32], u8 const* aad, usize aadlen, u8 const* ct,
                     usize ctlen, u8 tag[16]) {
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
}

bool cvmcrypt_chachapoly_decrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                                 u8 const tag[16]) {
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
}
