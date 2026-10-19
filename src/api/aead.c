/*
 * src/api/aead.c
 *
 * The polymorphic AEAD surface from include/cvmcrypt/aead.h.
 *
 * A thin dispatch over two already-written implementations. Nothing
 * cryptographic lives here: if a seal looks wrong, the bug is in gcm.c or
 * chachapoly.c and this file only decided which one to call.
 */

#include "cvmcrypt/aead.h"

#include "aead/chachapoly.h"
#include "aead/gcm.h"
#include "base/mem.h"
#include "base/secure.h"

enum {
    AEAD_KIND_GCM = 0,
    AEAD_KIND_CHACHAPOLY = 1,
};

struct CvmcryptAeadAlg {
    u8 kind;
    u8 key_size;
    u8 nonce_size;
    u8 tag_size;
};

CvmcryptAeadAlg const cvmcrypt_aead_aes128gcm = {
    .kind = AEAD_KIND_GCM,
    .key_size = 16,
    .nonce_size = 12,
    .tag_size = 16,
};

CvmcryptAeadAlg const cvmcrypt_aead_aes256gcm = {
    .kind = AEAD_KIND_GCM,
    .key_size = 32,
    .nonce_size = 12,
    .tag_size = 16,
};

CvmcryptAeadAlg const cvmcrypt_aead_chacha20poly1305 = {
    .kind = AEAD_KIND_CHACHAPOLY,
    .key_size = CVMCRYPT_CHACHAPOLY_KEY_SIZE,
    .nonce_size = CVMCRYPT_CHACHAPOLY_NONCE_SIZE,
    .tag_size = CVMCRYPT_CHACHAPOLY_TAG_SIZE,
};

usize cvmcrypt_aead_key_size(CvmcryptAeadAlg const* alg) {
    return alg ? alg->key_size : 0;
}

usize cvmcrypt_aead_nonce_size(CvmcryptAeadAlg const* alg) {
    return alg ? alg->nonce_size : 0;
}

usize cvmcrypt_aead_tag_size(CvmcryptAeadAlg const* alg) {
    return alg ? alg->tag_size : 0;
}

bool cvmcrypt_aead_init(CvmcryptAeadCtx* ctx, CvmcryptAeadAlg const* alg,
                        u8 const* key) {
    if (ctx == NULL || alg == NULL || key == NULL) {
        return false;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;

    switch (alg->kind) {
    case AEAD_KIND_GCM:
        return cvmcrypt_gcm_setup(&ctx->u.gcm, key, alg->key_size);
    case AEAD_KIND_CHACHAPOLY:
        memcpy(ctx->u.chacha_key, key, alg->key_size);
        return true;
    default:
        return false;
    }
}

bool cvmcrypt_aead_seal(CvmcryptAeadCtx* ctx, u8 const* nonce, u8 const* aad,
                        usize aadlen, u8 const* pt, usize ptlen, u8* ct, u8* tag) {
    if (ctx == NULL || ctx->alg == NULL || nonce == NULL || tag == NULL) {
        return false;
    }

    switch (ctx->alg->kind) {
    case AEAD_KIND_GCM:
        return cvmcrypt_gcm_seal(&ctx->u.gcm, nonce, aad, aadlen, pt, ptlen, ct, tag);
    case AEAD_KIND_CHACHAPOLY:
        cvmcrypt_chachapoly_encrypt(ctx->u.chacha_key, nonce, aad, aadlen, pt, ptlen,
                                    ct, tag);
        return true;
    default:
        return false;
    }
}

bool cvmcrypt_aead_open(CvmcryptAeadCtx* ctx, u8 const* nonce, u8 const* aad,
                        usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                        u8 const* tag) {
    if (ctx == NULL || ctx->alg == NULL || nonce == NULL || tag == NULL) {
        return false;
    }

    switch (ctx->alg->kind) {
    case AEAD_KIND_GCM:
        return cvmcrypt_gcm_open(&ctx->u.gcm, nonce, aad, aadlen, ct, ctlen, pt, tag);
    case AEAD_KIND_CHACHAPOLY:
        return cvmcrypt_chachapoly_decrypt(ctx->u.chacha_key, nonce, aad, aadlen, ct,
                                           ctlen, pt, tag);
    default:
        return false;
    }
}

void cvmcrypt_aead_clear(CvmcryptAeadCtx* ctx) {
    if (ctx == NULL) {
        return;
    }

    switch (ctx->alg ? ctx->alg->kind : 0xff) {
    case AEAD_KIND_GCM:
        cvmcrypt_gcm_clear(&ctx->u.gcm);
        break;
    case AEAD_KIND_CHACHAPOLY:
        /* ctx is caller-owned and may be a stack frame, so zeroise only. */
        memset(ctx->u.chacha_key, 0, sizeof(ctx->u.chacha_key));
        break;
    default:
        break;
    }

    memset(ctx, 0, sizeof(*ctx));
}
