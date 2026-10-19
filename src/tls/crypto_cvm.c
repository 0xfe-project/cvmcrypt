/*
 * src/tls/crypto_cvm.c
 *
 * Crypto callback layer: bridges the TLS state machine's abstract
 * AEAD/Hash/Keyex interfaces to cvmcrypt's concrete implementations.
 *
 * This is the ONLY file that knows about both the TLS callback types
 * and the cvmcrypt algorithm implementations.
 */

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "aead/gcm.h"
#include "aead/chachapoly.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "kx/x25519.h"
#include "cipher/aes.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* SHA-256                                                              */
/* ------------------------------------------------------------------ */

typedef struct Sha256Tls {
    CvmTlsHash super;
    CvmcryptSha256 ctx;
} Sha256Tls;

static CvmTlsHash* cvm_sha256_create(void);
static CvmTlsHashAlgo const CVM_TLS_SHA256 = {
    .name = "sha256",
    .block_size = 64,
    .digest_size = 32,
    .create = cvm_sha256_create,
};

static void cvm_sha256_update(CvmTlsHash* _ctx, void const* src, usize len) {
    cvmcrypt_sha256_update(&((Sha256Tls*)_ctx)->ctx, src, len);
}

static void cvm_sha256_final(CvmTlsHash* _ctx, void* digest, CvmTlsHashFinalMode mode) {
    Sha256Tls* ctx = (Sha256Tls*)_ctx;
    if (digest != NULL) {
        if (mode == TLS_HASH_FINAL_SNAPSHOT) {
            /* Work on a copy — the underlying final resets the state. */
            CvmcryptSha256 copy = ctx->ctx;
            cvmcrypt_sha256_final(&copy, digest);
        } else {
            cvmcrypt_sha256_final(&ctx->ctx, digest);
        }
    }
    if (mode == TLS_HASH_FINAL_RESET)
        cvmcrypt_sha256_init(&ctx->ctx);
    else if (mode == TLS_HASH_FINAL_FREE)
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
}

static CvmTlsHash* cvm_sha256_create(void) {
    Sha256Tls* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_SHA256;
    ctx->super.update = cvm_sha256_update;
    ctx->super.final = cvm_sha256_final;
    ctx->super.clone = NULL;
    cvmcrypt_sha256_init(&ctx->ctx);
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* SHA-384                                                              */
/* ------------------------------------------------------------------ */

typedef struct Sha384Tls {
    CvmTlsHash super;
    CvmcryptSha512 ctx;
} Sha384Tls;

static CvmTlsHash* cvm_sha384_create(void);
static CvmTlsHashAlgo const CVM_TLS_SHA384 = {
    .name = "sha384",
    .block_size = 128,
    .digest_size = 48,
    .create = cvm_sha384_create,
};

static void cvm_sha384_update(CvmTlsHash* _ctx, void const* src, usize len) {
    cvmcrypt_sha512_update(&((Sha384Tls*)_ctx)->ctx, src, len);
}

static void cvm_sha384_final(CvmTlsHash* _ctx, void* digest, CvmTlsHashFinalMode mode) {
    Sha384Tls* ctx = (Sha384Tls*)_ctx;
    if (digest != NULL) {
        if (mode == TLS_HASH_FINAL_SNAPSHOT) {
            CvmcryptSha512 copy = ctx->ctx;
            cvmcrypt_sha384_final(&copy, digest);
        } else {
            cvmcrypt_sha384_final(&ctx->ctx, digest);
        }
    }
    if (mode == TLS_HASH_FINAL_RESET)
        cvmcrypt_sha384_init(&ctx->ctx);
    else if (mode == TLS_HASH_FINAL_FREE)
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
}

static CvmTlsHash* cvm_sha384_create(void) {
    Sha384Tls* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_SHA384;
    ctx->super.update = cvm_sha384_update;
    ctx->super.final = cvm_sha384_final;
    ctx->super.clone = NULL;
    cvmcrypt_sha384_init(&ctx->ctx);
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* AES-128-GCM                                                          */
/* ------------------------------------------------------------------ */

typedef struct Gcm128Tls {
    CvmTlsAead super;
    CvmcryptGcm gcm;  /* working buffer */
    u8 key[16];       /* stored key */
    u8 static_iv[12]; /* static IV */
} Gcm128Tls;

static CvmTlsAead* cvm_gcm128_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv);
static CvmTlsAeadAlgo const CVM_TLS_AES128GCM = {
    .name = "aes128gcm",
    .key_size = 16,
    .iv_size = 12,
    .tag_size = 16,
    .setup = cvm_gcm128_setup,
};

static void cvm_gcm_dispose(CvmTlsAead* _ctx) {
    cvmcrypt_secure_free(_ctx, sizeof(Gcm128Tls));
}

static void cvm_gcm_encrypt(CvmTlsAead* _ctx, u8* output, u8 const* input, usize inlen,
                            u64 seq, void const* aad, usize aadlen) {
    Gcm128Tls* ctx = (Gcm128Tls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    /* output = ciphertext || tag. Key-derived state was built once in
     * setup, so this is just the per-message work. */
    cvmcrypt_gcm_seal(&ctx->gcm, nonce, (u8 const*)aad, aadlen, input, inlen, output,
                      output + inlen);
}

static usize cvm_gcm_decrypt(CvmTlsAead* _ctx, u8* output, u8 const* input, usize inlen,
                             u64 seq, void const* aad, usize aadlen) {
    Gcm128Tls* ctx = (Gcm128Tls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    /* input = ciphertext || tag */
    bool ok = cvmcrypt_gcm_open(&ctx->gcm, nonce, (u8 const*)aad, aadlen, input,
                                inlen - 16, output, input + inlen - 16);
    return ok ? inlen - 16 : (usize)-1;
}

static CvmTlsAead* cvm_gcm128_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv) {
    (void)algo;
    (void)is_enc;
    Gcm128Tls* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_AES128GCM;
    ctx->super.dispose = cvm_gcm_dispose;
    ctx->super.do_encrypt = cvm_gcm_encrypt;
    ctx->super.do_decrypt = cvm_gcm_decrypt;
    memcpy(ctx->key, key, 16);
    memcpy(ctx->static_iv, iv, 12);
    if (!cvmcrypt_gcm_setup(&ctx->gcm, ctx->key, 16)) {
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM                                                          */
/* ------------------------------------------------------------------ */

typedef struct Gcm256Tls {
    CvmTlsAead super;
    CvmcryptGcm gcm;
    u8 key[32];
    u8 static_iv[12];
} Gcm256Tls;

static CvmTlsAead* cvm_gcm256_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv);
static CvmTlsAeadAlgo const CVM_TLS_AES256GCM = {
    .name = "aes256gcm",
    .key_size = 32,
    .iv_size = 12,
    .tag_size = 16,
    .setup = cvm_gcm256_setup,
};

static void cvm_gcm256_encrypt(CvmTlsAead* _ctx, u8* output, u8 const* input,
                               usize inlen, u64 seq, void const* aad, usize aadlen) {
    Gcm256Tls* ctx = (Gcm256Tls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    cvmcrypt_gcm_seal(&ctx->gcm, nonce, (u8 const*)aad, aadlen, input, inlen, output,
                      output + inlen);
}

static usize cvm_gcm256_decrypt(CvmTlsAead* _ctx, u8* output, u8 const* input,
                                usize inlen, u64 seq, void const* aad, usize aadlen) {
    Gcm256Tls* ctx = (Gcm256Tls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    bool ok = cvmcrypt_gcm_open(&ctx->gcm, nonce, (u8 const*)aad, aadlen, input,
                                inlen - 16, output, input + inlen - 16);
    return ok ? inlen - 16 : (usize)-1;
}

static CvmTlsAead* cvm_gcm256_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv) {
    (void)algo;
    (void)is_enc;
    Gcm256Tls* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_AES256GCM;
    ctx->super.dispose = cvm_gcm_dispose; /* same size layout */
    ctx->super.do_encrypt = cvm_gcm256_encrypt;
    ctx->super.do_decrypt = cvm_gcm256_decrypt;
    memcpy(ctx->key, key, 32);
    memcpy(ctx->static_iv, iv, 12);
    if (!cvmcrypt_gcm_setup(&ctx->gcm, ctx->key, 32)) {
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* ChaCha20-Poly1305                                                    */
/* ------------------------------------------------------------------ */

typedef struct ChaChaTls {
    CvmTlsAead super;
    u8 key[32];
    u8 static_iv[12];
} ChaChaTls;

static CvmTlsAead* cvm_chacha_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv);
static CvmTlsAeadAlgo const CVM_TLS_CHACHA20POLY1305 = {
    .name = "chacha20poly1305",
    .key_size = 32,
    .iv_size = 12,
    .tag_size = 16,
    .setup = cvm_chacha_setup,
};

static void cvm_chacha_encrypt(CvmTlsAead* _ctx, u8* output, u8 const* input,
                               usize inlen, u64 seq, void const* aad, usize aadlen) {
    ChaChaTls* ctx = (ChaChaTls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    /* cvmcrypt_chachapoly_encrypt(ctx, key, nonce, aad, aadlen, pt, ptlen, ct, tag) */
    cvmcrypt_chachapoly_encrypt(ctx->key, nonce, (u8 const*)aad, aadlen, input, inlen,
                                output, output + inlen);
}

static usize cvm_chacha_decrypt(CvmTlsAead* _ctx, u8* output, u8 const* input,
                                usize inlen, u64 seq, void const* aad, usize aadlen) {
    ChaChaTls* ctx = (ChaChaTls*)_ctx;
    u8 nonce[12];
    memcpy(nonce, ctx->static_iv, 12);
    /*
     * RFC 8446 §5.3: the 64-bit record sequence number is left-padded to the
     * IV length and XORed in. For a 12-byte IV that puts it in the LAST eight
     * bytes. XORing into the first eight is invisible at seq 0 (all zeros)
     * and breaks every record after the first.
     */
    for (int i = 0; i < 8; i++)
        nonce[4 + i] ^= (u8)(seq >> (56 - i * 8));
    bool ok =
        cvmcrypt_chachapoly_decrypt(ctx->key, nonce, (u8 const*)aad, aadlen, input,
                                    inlen - 16, output, input + inlen - 16);
    return ok ? inlen - 16 : (usize)-1;
}

static CvmTlsAead* cvm_chacha_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv) {
    (void)algo;
    (void)is_enc;
    ChaChaTls* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_CHACHA20POLY1305;
    ctx->super.dispose = cvm_gcm_dispose; /* same dispose pattern */
    ctx->super.do_encrypt = cvm_chacha_encrypt;
    ctx->super.do_decrypt = cvm_chacha_decrypt;
    memcpy(ctx->key, key, 32);
    memcpy(ctx->static_iv, iv, 12);
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* X25519 key exchange                                                  */
/* ------------------------------------------------------------------ */

typedef struct X25519Ctx {
    CvmTlsKeyexCtx super;
    u8 private_key[32];
    u8 public_key[32];
} X25519Ctx;

static void cvm_x25519_dispose(CvmTlsKeyexCtx* _ctx) {
    cvmcrypt_secure_free(_ctx, sizeof(X25519Ctx));
}

static int cvm_x25519_create(CvmTlsKeyexCtx** _ctx);
static int cvm_x25519_exchange(CvmTlsKeyexCtx* _ctx, CvmTlsVec* secret,
                               CvmTlsVec peer_pubkey);

static CvmTlsKeyexAlgo const CVM_TLS_X25519_ALGO = {
    .name = "x25519",
    .id = TLS_GROUP_X25519,
    .shared_secret_size = 32,
    .create = cvm_x25519_create,
    .exchange = cvm_x25519_exchange,
};

/* Compute shared secret: X25519(our_private, peer_public). */
static int cvm_x25519_exchange(CvmTlsKeyexCtx* _ctx, CvmTlsVec* secret,
                               CvmTlsVec peer_pubkey) {
    X25519Ctx* ctx = (X25519Ctx*)_ctx;
    if (peer_pubkey.len != 32)
        return TLS_ALERT_ILLEGAL_PARAMETER;
    u8* shared = rt_mem_alloc(32);
    if (!shared)
        return TLS_ERROR_NO_MEMORY;
    cvmcrypt_x25519_fast(shared, ctx->private_key, peer_pubkey.base);
    secret->base = shared;
    secret->len = 32;
    return 0;
}

static int cvm_x25519_create(CvmTlsKeyexCtx** _ctx) {
    X25519Ctx* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return TLS_ERROR_NO_MEMORY;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &CVM_TLS_X25519_ALGO;
    ctx->super.dispose = cvm_x25519_dispose;

    for (int i = 0; i < 32; i++)
        ctx->private_key[i] = (u8)(i * 7 + 3);
    ctx->private_key[0] &= 248;
    ctx->private_key[31] &= 127;
    ctx->private_key[31] |= 64;

    cvmcrypt_x25519_base_fast(ctx->public_key, ctx->private_key);

    /* Export the public key to the generic field. */
    memcpy(ctx->super.pubkey, ctx->public_key, 32);
    ctx->super.pubkey_len = 32;

    *_ctx = &ctx->super;
    return 0;
}

/* ------------------------------------------------------------------ */
/* cipher suites + key exchanges (the exported tables)                  */
/* ------------------------------------------------------------------ */

static CvmTlsCipherSuite const CVM_SUITE_AES128GCM_SHA256 = {
    .id = TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .aead = &CVM_TLS_AES128GCM,
    .hash = &CVM_TLS_SHA256,
    .name = "TLS_AES_128_GCM_SHA256",
};

static CvmTlsCipherSuite const CVM_SUITE_AES256GCM_SHA384 = {
    .id = TLS_CIPHER_SUITE_AES_256_GCM_SHA384,
    .aead = &CVM_TLS_AES256GCM,
    .hash = &CVM_TLS_SHA384,
    .name = "TLS_AES_256_GCM_SHA384",
};

static CvmTlsCipherSuite const CVM_SUITE_CHACHA20POLY1305_SHA256 = {
    .id = TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    .aead = &CVM_TLS_CHACHA20POLY1305,
    .hash = &CVM_TLS_SHA256,
    .name = "TLS_CHACHA20_POLY1305_SHA256",
};

/* Default cipher suite list (all three, preferred order). */
static CvmTlsCipherSuite const* const CVM_CIPHER_SUITES[] = {
    &CVM_SUITE_AES128GCM_SHA256,
    &CVM_SUITE_AES256GCM_SHA384,
    &CVM_SUITE_CHACHA20POLY1305_SHA256,
    NULL,
};

static CvmTlsKeyexAlgo const* CVM_KEY_EXCHANGES[] = {
    &CVM_TLS_X25519_ALGO,
    NULL,
};

/* Public: fill a CvmTlsContext with cvmcrypt defaults. */
void cvm_tls_context_defaults(CvmTlsContext* ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->cipher_suites = CVM_CIPHER_SUITES;
    ctx->key_exchanges = CVM_KEY_EXCHANGES;
}
