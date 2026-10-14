/*
 * tests/unit/test_tls_client.c
 *
 * TLS 1.3 client state machine: verify the state transitions work
 * by driving the handshake with mock data (no real crypto yet).
 */

#include "vendor/greatest.h"

#include <string.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "hash/sha256.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* mock backends                                                        */
/* ------------------------------------------------------------------ */

/* SHA-256 hash. */
typedef struct Sha256Ctx {
    CvmTlsHash super;
    CvmcryptSha256 ctx;
} Sha256Ctx;

static CvmTlsHash* sha256_create(void);
static CvmTlsHashAlgo const SHA256_ALGO = {
    .name = "sha256",
    .block_size = 64,
    .digest_size = 32,
    .create = sha256_create,
};

static void sha256_update(CvmTlsHash* _ctx, void const* src, usize len) {
    cvmcrypt_sha256_update(&((Sha256Ctx*)_ctx)->ctx, src, len);
}
static void sha256_final(CvmTlsHash* _ctx, void* digest, CvmTlsHashFinalMode mode) {
    Sha256Ctx* ctx = (Sha256Ctx*)_ctx;
    if (digest)
        cvmcrypt_sha256_final(&ctx->ctx, digest);
    if (mode == TLS_HASH_FINAL_FREE)
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
    else if (mode == TLS_HASH_FINAL_RESET)
        cvmcrypt_sha256_init(&ctx->ctx);
}
static CvmTlsHash* sha256_create(void) {
    Sha256Ctx* ctx = rt_mem_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &SHA256_ALGO;
    ctx->super.update = sha256_update;
    ctx->super.final = sha256_final;
    cvmcrypt_sha256_init(&ctx->ctx);
    return &ctx->super;
}

/* Dummy AEAD (pass-through for testing). */
static CvmTlsAeadAlgo const DUMMY_AEAD_ALGO; /* fwd decl */

typedef struct DummyAead {
    CvmTlsAead super;
    u8 key[16];
    u8 iv[12];
} DummyAead;

static void dummy_dispose(CvmTlsAead* _ctx) {
    cvmcrypt_secure_free(_ctx, sizeof(DummyAead));
}
static void dummy_encrypt(CvmTlsAead* _ctx, u8* out, u8 const* in, usize inlen, u64 seq,
                          void const* aad, usize aadlen) {
    (void)_ctx;
    (void)seq;
    (void)aad;
    (void)aadlen;
    /* Simple XOR "encryption" for testing. */
    for (usize i = 0; i < inlen; i++)
        out[i] = in[i] ^ 0xFF;
}
static usize dummy_decrypt(CvmTlsAead* _ctx, u8* out, u8 const* in, usize inlen,
                           u64 seq, void const* aad, usize aadlen) {
    (void)_ctx;
    (void)seq;
    (void)aad;
    (void)aadlen;
    for (usize i = 0; i < inlen; i++)
        out[i] = in[i] ^ 0xFF;
    return inlen;
}
static CvmTlsAead* dummy_aead_setup(CvmTlsAeadAlgo const* algo, bool is_enc,
                                    void const* key, void const* iv) {
    (void)algo;
    (void)is_enc;
    DummyAead* ctx = rt_mem_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &DUMMY_AEAD_ALGO;
    ctx->super.dispose = dummy_dispose;
    ctx->super.do_encrypt = dummy_encrypt;
    ctx->super.do_decrypt = dummy_decrypt;
    memcpy(ctx->key, key, 16);
    memcpy(ctx->iv, iv, 12);
    return &ctx->super;
}
static CvmTlsAeadAlgo const DUMMY_AEAD_ALGO = {
    .name = "dummy",
    .key_size = 16,
    .iv_size = 12,
    .tag_size = 0,
    .setup = dummy_aead_setup,
};

/* Dummy key exchange (pass-through). */
static void dummy_keyex_dispose(CvmTlsKeyexCtx* ctx) {
    rt_mem_free(ctx);
}
static int dummy_keyex_create(CvmTlsKeyexCtx** ctx) {
    *ctx = rt_mem_alloc(sizeof(CvmTlsKeyexCtx));
    if (*ctx == NULL)
        return TLS_ERROR_NO_MEMORY;
    memset(*ctx, 0, sizeof(**ctx));
    (*ctx)->dispose = dummy_keyex_dispose;
    return 0;
}
static CvmTlsKeyexAlgo const DUMMY_KEYEX = {
    .name = "x25519",
    .id = TLS_GROUP_X25519,
    .shared_secret_size = 32,
    .create = dummy_keyex_create,
};

static CvmTlsCipherSuite const SUITE = {
    .id = TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .aead = &DUMMY_AEAD_ALGO,
    .hash = &SHA256_ALGO,
    .name = "TLS_AES_128_GCM_SHA256",
};
static CvmTlsCipherSuite const* const SUITES[] = {&SUITE, NULL};
static CvmTlsKeyexAlgo const* KEYEXES[] = {&DUMMY_KEYEX, NULL};

static u64 dummy_get_time(CvmTlsGetTime* self) {
    (void)self;
    return 0;
}
static CvmTlsGetTime const GET_TIME = {.cb = dummy_get_time};
static void dummy_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    memset(buf, 0x42, len);
}
static CvmTlsRandomBytes const RANDOM = {.cb = dummy_random};

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST tls_new_free(void) {
    CvmTlsContext ctx = {
        .cipher_suites = SUITES,
        .key_exchanges = KEYEXES,
    };
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT(tls != NULL);
    ASSERT(!cvm_tls_is_server(tls));
    ASSERT_STR_EQ("example.com", cvm_tls_get_server_name(tls));
    ASSERT(cvm_tls_get_cipher_suite(tls) == NULL); /* not negotiated yet */
    cvm_tls_free(tls);
    PASS();
}

TEST client_hello_sent(void) {
    CvmTlsContext ctx = {
        .cipher_suites = SUITES,
        .key_exchanges = KEYEXES,
    };
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    usize inlen = 0;
    int ret = cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);
    ASSERT_EQ(TLS_ERROR_IN_PROGRESS, ret);
    ASSERT(sendbuf.off > 100); /* ClientHello is substantial */

    /* Verify it's a handshake record. */
    ASSERT_EQ(TLS_CONTENT_TYPE_HANDSHAKE, sendbuf.base[0]);

    /* Parse the ClientHello to verify. */
    CvmTlsClientHello ch;
    ret =
        cvm_tls_decode_client_hello(&ch, sendbuf.base + 9, sendbuf.base + sendbuf.off);
    ASSERT_EQ(0, ret);
    ASSERT(ch.num_cipher_suites > 0);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

TEST client_state_transitions(void) {
    CvmTlsContext ctx = {
        .cipher_suites = SUITES,
        .key_exchanges = KEYEXES,
    };
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT_EQ(TLS_STATE_CLIENT_HANDSHAKE_START, tls->state);

    /* After sending ClientHello → EXPECT_SERVER_HELLO. */
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    usize inlen = 0;
    cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);
    ASSERT_EQ(TLS_STATE_CLIENT_EXPECT_SERVER_HELLO, tls->state);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

SUITE(tls_client) {
    RUN_TEST(tls_new_free);
    RUN_TEST(client_hello_sent);
    RUN_TEST(client_state_transitions);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_client);
    GREATEST_MAIN_END();
}
