/*
 * src/api/hash.c
 *
 * The polymorphic hash and HKDF surface from include/cvmcrypt/hash.h.
 *
 * HKDF is written once over the descriptor's init/update/final, with a small
 * HMAC built the same way. The alternative — one extract/expand pair per hash
 * — is three copies of the same loop, and SHA-384 had none of them until now.
 *
 * SHA-384 needs no separate compression function: it is SHA-512's, with a
 * different IV and the output truncated to 48 bytes. Both live in
 * CvmcryptSha512.
 */

#include "cvmcrypt/hash.h"

#include "base/mem.h"
#include "base/secure.h"

enum {
    MD_KIND_SHA256 = 0,
    MD_KIND_SHA512 = 1,
};

struct CvmcryptMdAlg {
    u8 kind;
    u8 is_sha384;
    u8 digest_size;
    u8 block_size;
};

static CvmcryptMdAlg const MD_SHA256 = {
    .kind = MD_KIND_SHA256,
    .is_sha384 = 0,
    .digest_size = CVMCRYPT_SHA256_DIGEST_SIZE,
    .block_size = CVMCRYPT_SHA256_BLOCK_SIZE,
};

static CvmcryptMdAlg const MD_SHA384 = {
    .kind = MD_KIND_SHA512,
    .is_sha384 = 1,
    .digest_size = CVMCRYPT_SHA384_DIGEST_SIZE,
    .block_size = CVMCRYPT_SHA512_BLOCK_SIZE,
};

static CvmcryptMdAlg const MD_SHA512 = {
    .kind = MD_KIND_SHA512,
    .is_sha384 = 0,
    .digest_size = CVMCRYPT_SHA512_DIGEST_SIZE,
    .block_size = CVMCRYPT_SHA512_BLOCK_SIZE,
};

CvmcryptMdAlg const cvmcrypt_md_sha256 = MD_SHA256;
CvmcryptMdAlg const cvmcrypt_md_sha384 = MD_SHA384;
CvmcryptMdAlg const cvmcrypt_md_sha512 = MD_SHA512;

usize cvmcrypt_md_digest_size(CvmcryptMdAlg const* alg) {
    return alg ? alg->digest_size : 0;
}

usize cvmcrypt_md_block_size(CvmcryptMdAlg const* alg) {
    return alg ? alg->block_size : 0;
}

void cvmcrypt_md_init(CvmcryptMdCtx* ctx, CvmcryptMdAlg const* alg) {
    if (ctx == NULL || alg == NULL) {
        return;
    }
    ctx->alg = alg;
    if (alg->kind == MD_KIND_SHA256) {
        cvmcrypt_sha256_init(&ctx->u.s256);
    } else if (alg->is_sha384) {
        cvmcrypt_sha384_init(&ctx->u.s512);
    } else {
        cvmcrypt_sha512_init(&ctx->u.s512);
    }
}

void cvmcrypt_md_update(CvmcryptMdCtx* ctx, u8 const* data, usize len) {
    if (ctx == NULL || ctx->alg == NULL || len == 0) {
        return;
    }
    if (ctx->alg->kind == MD_KIND_SHA256) {
        cvmcrypt_sha256_update(&ctx->u.s256, data, len);
    } else {
        cvmcrypt_sha512_update(&ctx->u.s512, data, len);
    }
}

void cvmcrypt_md_final(CvmcryptMdCtx* ctx, u8* out) {
    if (ctx == NULL || ctx->alg == NULL || out == NULL) {
        return;
    }
    if (ctx->alg->kind == MD_KIND_SHA256) {
        cvmcrypt_sha256_final(&ctx->u.s256, out);
    } else if (ctx->alg->is_sha384) {
        cvmcrypt_sha384_final(&ctx->u.s512, out);
    } else {
        cvmcrypt_sha512_final(&ctx->u.s512, out);
    }
}

bool cvmcrypt_md_digest(CvmcryptMdAlg const* alg, u8 const* data, usize len, u8* out) {
    if (alg == NULL || out == NULL) {
        return false;
    }
    if (alg->kind == MD_KIND_SHA256) {
        cvmcrypt_sha256(data, len, out);
        return true;
    }
    if (alg->is_sha384) {
        cvmcrypt_sha384(data, len, out);
        return true;
    }
    cvmcrypt_sha512(data, len, out);
    return true;
}

/* ------------------------------------------------------------------ */
/* HMAC, generic over the descriptor                                    */
/* ------------------------------------------------------------------ */

/* Large enough for SHA-512, which is the widest thing here. */
#define HMAC_MAX_BLOCK CVMCRYPT_SHA512_BLOCK_SIZE
#define HMAC_MAX_DIGEST CVMCRYPT_SHA512_DIGEST_SIZE

typedef struct HmacCtx {
    CvmcryptMdCtx inner;
    CvmcryptMdCtx outer;
} HmacCtx;

static void hmac_init(HmacCtx* h, CvmcryptMdAlg const* alg, u8 const* key,
                      usize keylen) {
    u8 k[HMAC_MAX_BLOCK];
    u8 pad[HMAC_MAX_BLOCK];

    memset(k, 0, sizeof(k));

    /* A key longer than the block is replaced by its own digest. */
    if (keylen > alg->block_size) {
        cvmcrypt_md_digest(alg, key, keylen, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    for (usize i = 0; i < alg->block_size; i++) {
        pad[i] = (u8)(k[i] ^ 0x36);
    }
    cvmcrypt_md_init(&h->inner, alg);
    cvmcrypt_md_update(&h->inner, pad, alg->block_size);

    for (usize i = 0; i < alg->block_size; i++) {
        pad[i] = (u8)(k[i] ^ 0x5c);
    }
    cvmcrypt_md_init(&h->outer, alg);
    cvmcrypt_md_update(&h->outer, pad, alg->block_size);

    /* Stack buffers: zeroise, do not free. cvmcrypt_secure_free() also
     * calls rt_mem_free(), which on a stack address is fatal. */
    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
}

static void hmac_update(HmacCtx* h, u8 const* data, usize len) {
    cvmcrypt_md_update(&h->inner, data, len);
}

static void hmac_final(HmacCtx* h, u8* out) {
    u8 inner[HMAC_MAX_DIGEST];
    usize const dlen = cvmcrypt_md_digest_size(h->inner.alg);

    cvmcrypt_md_final(&h->inner, inner);
    cvmcrypt_md_update(&h->outer, inner, dlen);
    cvmcrypt_md_final(&h->outer, out);

    memset(inner, 0, sizeof(inner));
}

/* ------------------------------------------------------------------ */
/* HKDF                                                                 */
/* ------------------------------------------------------------------ */

bool cvmcrypt_hkdf_extract(CvmcryptMdAlg const* alg, u8* prk, u8 const* salt,
                           usize saltlen, u8 const* ikm, usize ikmlen) {
    static u8 const kZeroSalt[HMAC_MAX_DIGEST] = {0};
    HmacCtx h;

    if (alg == NULL || prk == NULL) {
        return false;
    }
    if (salt == NULL || saltlen == 0) {
        /* RFC 5869: absent salt means HashLen zeros. */
        salt = kZeroSalt;
        saltlen = alg->digest_size;
    }

    hmac_init(&h, alg, salt, saltlen);
    hmac_update(&h, ikm, ikmlen);
    hmac_final(&h, prk);

    memset(&h, 0, sizeof(h));
    return true;
}

bool cvmcrypt_hkdf_expand(CvmcryptMdAlg const* alg, u8* okm, usize okmlen,
                          u8 const* prk, u8 const* info, usize infolen) {
    HmacCtx h;
    u8 t[HMAC_MAX_DIGEST];
    usize const dlen = alg ? alg->digest_size : 0;
    usize done = 0;
    u8 counter = 1;

    if (alg == NULL || okm == NULL || (okmlen > 0 && prk == NULL)) {
        return false;
    }
    if (okmlen > 255 * dlen) {
        return false;
    }

    while (done < okmlen) {
        usize take = okmlen - done < dlen ? okmlen - done : dlen;

        hmac_init(&h, alg, prk, dlen);
        if (done > 0) {
            hmac_update(&h, t, dlen);
        }
        if (infolen > 0) {
            hmac_update(&h, info, infolen);
        }
        hmac_update(&h, &counter, 1);
        hmac_final(&h, t);

        memcpy(okm + done, t, take);
        done += take;
        counter++;
    }

    memset(t, 0, sizeof(t));
    memset(&h, 0, sizeof(h));
    return true;
}
