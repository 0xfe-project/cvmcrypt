/*
 * tests/unit/test_tls_quic_hooks.c
 *
 * The two pieces of QUIC surface that do not need a record layer:
 * the traffic key callback and cvm_tls_get_read_epoch.
 *
 * What is checkable without a network is narrow but not worthless: a fresh
 * session must report epoch 0, must not call the callback, and must report 0
 * after a handshake attempt that never gets a ServerHello. The end-to-end
 * behaviour (four callbacks, epochs 2,2,3,3, read epoch 3) lives in
 * tests/integration/tls_client_test.c, which needs a real server.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "base/types.h"
#include "tls/tls.h"
#include "tls/tls_internal.h"

/* ------------------------------------------------------------------ */
/* a minimal context: the handshake never starts, so nothing else is used */
/* ------------------------------------------------------------------ */

static void dummy_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    memset(buf, 0x42, len);
}

static CvmTlsRandomBytes const DUMMY_RANDOM = {.cb = dummy_random};

static int key_cb_count;
static u32 key_cb_epoch;
static int key_cb_enc;

static int on_traffic_key(struct CvmTlsTrafficKey* self, CvmTls* tls, bool is_enc,
                          u32 epoch, u8 const* secret, usize secret_len) {
    (void)self;
    (void)tls;
    (void)secret;
    (void)secret_len;
    key_cb_count++;
    key_cb_epoch = epoch;
    key_cb_enc = is_enc ? 1 : 0;
    return 0;
}

static CvmTlsTrafficKey const KEY_HOOK = {.cb = on_traffic_key};

TEST fresh_session_reads_epoch_zero(void) {
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.random_bytes = (CvmTlsRandomBytes*)&DUMMY_RANDOM;
    ctx.update_traffic_key = (CvmTlsTrafficKey*)&KEY_HOOK;

    key_cb_count = 0;

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT(tls != NULL);

    /* No keys installed yet: QUIC must treat incoming CRYPTO as Initial. */
    ASSERT_EQ(0, (int)cvm_tls_get_read_epoch(tls));
    ASSERT_EQ(0, key_cb_count);

    cvm_tls_free(tls);
    PASS();
}

TEST client_hello_does_not_install_keys(void) {
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.random_bytes = (CvmTlsRandomBytes*)&DUMMY_RANDOM;
    ctx.update_traffic_key = (CvmTlsTrafficKey*)&KEY_HOOK;

    key_cb_count = 0;

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT(tls != NULL);

    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    usize inlen = 0;
    int ret = cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);

    /* ClientHello goes out, nothing comes back: still no secrets. */
    ASSERT(ret != 0);
    ASSERT(sendbuf.off > 0);
    ASSERT_EQ(0, key_cb_count);
    ASSERT_EQ(0, (int)cvm_tls_get_read_epoch(tls));

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

TEST callback_absent_is_not_an_error(void) {
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);
    ctx.random_bytes = (CvmTlsRandomBytes*)&DUMMY_RANDOM;
    /* ctx.update_traffic_key stays NULL. */

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT(tls != NULL);

    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    usize inlen = 0;
    int ret = cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL);

    /* A record-layer session must work with no QUIC hook installed. */
    ASSERT(ret != 0);
    ASSERT(sendbuf.off > 0);
    ASSERT_EQ(0, (int)cvm_tls_get_read_epoch(tls));

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

SUITE(tls_quic_hooks) {
    RUN_TEST(fresh_session_reads_epoch_zero);
    RUN_TEST(client_hello_does_not_install_keys);
    RUN_TEST(callback_absent_is_not_an_error);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_quic_hooks);
    GREATEST_MAIN_END();
}
