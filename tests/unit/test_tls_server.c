/*
 * tests/unit/test_tls_server.c
 *
 * TLS 1.3 server state machine: ClientHello → SH+EE+Cert+CV+Fin flow.
 */

#include "vendor/greatest.h"

#include <string.h>
#include <stdio.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "tls/handshake.h"
#include "hash/sha256.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* int cvm_tls_server_handle_message is in server.c */
int cvm_tls_server_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, CvmTlsVec message);

/* ------------------------------------------------------------------ */
/* mock backends                                                        */
/* ------------------------------------------------------------------ */

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

/* Dummy AEAD (XOR pass-through). */
static CvmTlsAeadAlgo const DUMMY_AEAD_ALGO; /* fwd */

typedef struct DummyAead {
    CvmTlsAead super;
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
    (void)key;
    (void)iv;
    DummyAead* ctx = rt_mem_alloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->super.algo = &DUMMY_AEAD_ALGO;
    ctx->super.dispose = dummy_dispose;
    ctx->super.do_encrypt = dummy_encrypt;
    ctx->super.do_decrypt = dummy_decrypt;
    return &ctx->super;
}
static CvmTlsAeadAlgo const DUMMY_AEAD_ALGO = {
    .name = "dummy",
    .key_size = 16,
    .iv_size = 12,
    .tag_size = 0,
    .setup = dummy_aead_setup,
};

static int dummy_keyex_create(CvmTlsKeyexCtx** ctx) {
    *ctx = rt_mem_alloc(sizeof(CvmTlsKeyexCtx));
    if (!*ctx)
        return TLS_ERROR_NO_MEMORY;
    memset(*ctx, 0, sizeof(**ctx));
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

static u64 dummy_time_cb(CvmTlsGetTime* self) {
    (void)self;
    return 1000000;
}
static CvmTlsGetTime const GET_TIME = {.cb = dummy_time_cb};
static void dummy_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    memset(buf, 0x42, len);
}
static CvmTlsRandomBytes const RANDOM = {.cb = dummy_random};

static u8 const TEST_CERT[] = "fake certificate DER";

static CvmTlsCert const CERTS[] = {
    {.der = {TEST_CERT, sizeof(TEST_CERT) - 1}},
    {.der = {NULL, 0}}, /* terminator */
};

/* ------------------------------------------------------------------ */
/* helper: build a ClientHello to feed the server                       */
/* ------------------------------------------------------------------ */

static void build_client_hello(CvmTlsBuf* buf) {
    u8 random[32];
    for (int i = 0; i < 32; i++)
        random[i] = (u8)(i * 3);
    u8 session_id[32] = {0};

    /* encode_client_hello already writes the handshake header. */
    cvm_tls_encode_client_hello(buf, SUITES, random, (CvmTlsVec){session_id, 32},
                                "example.com", &DUMMY_KEYEX, (CvmTlsVec){random, 32},
                                NULL, 0, (CvmTlsVec){NULL, 0});
}

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST server_full_handshake_flow(void) {
    CvmTlsContext ctx = {0};
    ctx.cipher_suites = SUITES;
    ctx.key_exchanges = KEYEXES;
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;
    ctx.certificates = (CvmTlsCert*)CERTS;

    CvmTls* tls = cvm_tls_new(&ctx, true, NULL);
    ASSERT(tls != NULL);
    ASSERT_EQ(TLS_STATE_SERVER_EXPECT_CLIENT_HELLO, tls->state);

    /* Build a ClientHello. */
    CvmTlsBuf ch_buf;
    cvm_tls_buf_init(&ch_buf, NULL, 0);
    build_client_hello(&ch_buf);
    ASSERT(ch_buf.off > 100);

    /* Feed it to the server. */
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    int ret = cvm_tls_server_handle_message(tls, &sendbuf,
                                            (CvmTlsVec){ch_buf.base, ch_buf.off});
    ASSERT_EQ(0, ret);

    /* Server should have produced: ServerHello + EE + Cert + CV + Fin. */
    ASSERT(sendbuf.off > 200);
    ASSERT_EQ(TLS_STATE_SERVER_EXPECT_FINISHED, tls->state);

    /* First record should be plaintext ServerHello. */
    ASSERT_EQ(TLS_CONTENT_TYPE_HANDSHAKE, sendbuf.base[0]);
    /* Second record onward should be encrypted (APPDATA type). */
    /* (find the second record: skip first record header+body) */
    usize first_rec_len = 5 + (sendbuf.base[3] << 8 | sendbuf.base[4]);
    ASSERT(sendbuf.off > first_rec_len);
    ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, sendbuf.base[first_rec_len]);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_buf_dispose(&ch_buf);
    cvm_tls_free(tls);
    PASS();
}

TEST server_cipher_suite_negotiated(void) {
    CvmTlsContext ctx = {0};
    ctx.cipher_suites = SUITES;
    ctx.key_exchanges = KEYEXES;
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;
    ctx.certificates = (CvmTlsCert*)CERTS;

    CvmTls* tls = cvm_tls_new(&ctx, true, NULL);

    CvmTlsBuf ch_buf;
    cvm_tls_buf_init(&ch_buf, NULL, 0);
    build_client_hello(&ch_buf);

    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    cvm_tls_server_handle_message(tls, &sendbuf, (CvmTlsVec){ch_buf.base, ch_buf.off});

    ASSERT(tls->suite != NULL);
    ASSERT_EQ(TLS_CIPHER_SUITE_AES_128_GCM_SHA256, tls->suite->id);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_buf_dispose(&ch_buf);
    cvm_tls_free(tls);
    PASS();
}

TEST server_wrong_state(void) {
    CvmTlsContext ctx = {0};
    ctx.cipher_suites = SUITES;
    ctx.key_exchanges = KEYEXES;
    ctx.get_time = (CvmTlsGetTime*)&GET_TIME;
    ctx.random_bytes = (CvmTlsRandomBytes*)&RANDOM;

    CvmTls* tls = cvm_tls_new(&ctx, true, NULL);

    /* Send a Finished message when server expects ClientHello. */
    u8 fin_msg[] = {TLS_HANDSHAKE_TYPE_FINISHED, 0, 0, 4, 1, 2, 3, 4};
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    int ret = cvm_tls_server_handle_message(tls, &sendbuf,
                                            (CvmTlsVec){fin_msg, sizeof(fin_msg)});
    ASSERT_EQ(TLS_ALERT_UNEXPECTED_MESSAGE, ret);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

SUITE(tls_server) {
    RUN_TEST(server_full_handshake_flow);
    RUN_TEST(server_cipher_suite_negotiated);
    RUN_TEST(server_wrong_state);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_server);
    GREATEST_MAIN_END();
}
