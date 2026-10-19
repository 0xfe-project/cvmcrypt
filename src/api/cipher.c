/*
 * src/api/cipher.c
 *
 * The keystream-block surface from include/cvmcrypt/cipher.h.
 *
 * Both cipher families reduce to "16 bytes in, 16 bytes of keystream out":
 *
 *   AES      out = AES-ECB_K(in)
 *   ChaCha20 in[0..3] is the counter (little-endian), in[4..15] the nonce
 *
 * so header protection is one memcpy of the first five bytes and there is no
 * second code path to get wrong.
 */

#include "cvmcrypt/cipher.h"

#include "base/mem.h"
#include "cipher/aes.h"
#include "stream/chacha20.h"

enum {
    CIPHER_KIND_AES = 0,
    CIPHER_KIND_CHACHA20 = 1,
};

struct CvmcryptCipherAlg {
    u8 kind;
    u8 key_size;
};

CvmcryptCipherAlg const cvmcrypt_cipher_aes128 = {.kind = CIPHER_KIND_AES,
                                                  .key_size = 16};
CvmcryptCipherAlg const cvmcrypt_cipher_aes192 = {.kind = CIPHER_KIND_AES,
                                                  .key_size = 24};
CvmcryptCipherAlg const cvmcrypt_cipher_aes256 = {.kind = CIPHER_KIND_AES,
                                                  .key_size = 32};
CvmcryptCipherAlg const cvmcrypt_cipher_chacha20 = {
    .kind = CIPHER_KIND_CHACHA20,
    .key_size = CVMCRYPT_CHACHA20_KEY_SIZE,
};

usize cvmcrypt_cipher_key_size(CvmcryptCipherAlg const* alg) {
    return alg ? alg->key_size : 0;
}

bool cvmcrypt_cipher_init(CvmcryptCipherCtx* ctx, CvmcryptCipherAlg const* alg,
                          u8 const* key) {
    if (ctx == NULL || alg == NULL || key == NULL) {
        return false;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;

    if (alg->kind == CIPHER_KIND_AES) {
        return cvmcrypt_aes_setup(&ctx->u.aes, key, alg->key_size);
    }
    memcpy(ctx->u.chacha_key, key, alg->key_size);
    return true;
}

bool cvmcrypt_cipher_keystream(CvmcryptCipherCtx* ctx, u8 const in[16], u8 out[16]) {
    if (ctx == NULL || ctx->alg == NULL || in == NULL || out == NULL) {
        return false;
    }

    if (ctx->alg->kind == CIPHER_KIND_AES) {
        cvmcrypt_aes_encrypt_block(&ctx->u.aes, in, out);
        return true;
    }

    /* ChaCha20: the sample is the block input, split as counter || nonce. */
    u32 const counter =
        (u32)in[0] | ((u32)in[1] << 8) | ((u32)in[2] << 16) | ((u32)in[3] << 24);
    CvmcryptChaCha20 c;
    u8 zero[16] = {0};
    cvmcrypt_chacha20_init(&c, ctx->u.chacha_key, counter, in + 4);
    cvmcrypt_chacha20_xor(&c, zero, sizeof(zero), out);
    memset(&c, 0, sizeof(c));
    return true;
}

bool cvmcrypt_cipher_hp_mask(CvmcryptCipherCtx* ctx, u8 const sample[16], u8 mask[5]) {
    u8 block[16];

    if (mask == NULL) {
        return false;
    }
    if (!cvmcrypt_cipher_keystream(ctx, sample, block)) {
        return false;
    }
    memcpy(mask, block, 5);
    memset(block, 0, sizeof(block));
    return true;
}

void cvmcrypt_cipher_clear(CvmcryptCipherCtx* ctx) {
    if (ctx == NULL) {
        return;
    }
    /* Caller-owned, possibly a stack frame: zeroise, never free. */
    memset(ctx, 0, sizeof(*ctx));
}
