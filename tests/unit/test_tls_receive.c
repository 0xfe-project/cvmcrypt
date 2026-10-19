/*
 * tests/unit/test_tls_receive.c
 *
 * The record loop behind cvm_tls_receive: framing, several records in one
 * buffer, a record split across two calls, and the close_notify path.
 *
 * The integration test proves cvm_tls_receive against real servers, but it
 * needs a network and therefore never runs in CI. This one builds the records
 * itself with the same primitives the sender uses, so the loop is covered on
 * every commit. It cannot catch a wrong key schedule — for that the peer has
 * to be someone else — but it does catch the loop getting the framing, the
 * sequence numbers or the alert handling wrong.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "base/types.h"
#include "tls/tls.h"
#include "tls/tls_conn.h"
#include "tls/tls_internal.h"

static CvmTlsAeadAlgo const* aes128gcm_algo(void) {
    static CvmTlsContext ctx;
    static bool init;
    if (!init) {
        cvm_tls_context_defaults(&ctx);
        init = true;
    }
    for (usize i = 0; ctx.cipher_suites[i] != NULL; i++) {
        if (ctx.cipher_suites[i]->id == 0x1301) {
            return ctx.cipher_suites[i]->aead;
        }
    }
    return NULL;
}

/* A session that has finished its handshake, with fixed keys on both sides.
 * Both directions use the same key here: this tests the record loop, not the
 * key schedule. */
static CvmTls* make_session(CvmTlsContext* ctx) {
    cvm_tls_context_defaults(ctx);

    CvmTls* tls = cvm_tls_new(ctx, false, "example.com");
    if (tls == NULL) {
        return NULL;
    }

    u8 key[16], iv[12];
    for (usize i = 0; i < sizeof(key); i++) {
        key[i] = (u8)(0x40 + i);
    }
    for (usize i = 0; i < sizeof(iv); i++) {
        iv[i] = (u8)(0x10 + i);
    }

    CvmTlsAeadAlgo const* algo = aes128gcm_algo();
    if (algo == NULL) {
        cvm_tls_free(tls);
        return NULL;
    }

    tls->enc.aead = algo->setup(algo, true, key, iv);
    tls->dec.aead = algo->setup(algo, false, key, iv);
    tls->enc.seq = 0;
    tls->dec.seq = 0;
    if (tls->enc.aead == NULL || tls->dec.aead == NULL) {
        cvm_tls_free(tls);
        return NULL;
    }

    tls->handshake_complete = true;
    tls->state = TLS_STATE_CLIENT_POST_HANDSHAKE;
    return tls;
}

static void drop_session(CvmTls* tls) {
    if (tls->enc.aead != NULL) {
        tls->enc.aead->dispose(tls->enc.aead);
        tls->enc.aead = NULL;
    }
    if (tls->dec.aead != NULL) {
        tls->dec.aead->dispose(tls->dec.aead);
        tls->dec.aead = NULL;
    }
    cvm_tls_free(tls);
}

TEST two_records_in_one_buffer(void) {
    CvmTlsContext ctx;
    CvmTls* tls = make_session(&ctx);
    ASSERT(tls != NULL);

    CvmTlsBuf wire;
    cvm_tls_buf_init(&wire, NULL, 0);

    ASSERT_EQ(0, cvm_tls_push_encrypted_records(&wire, TLS_CONTENT_TYPE_APPDATA,
                                                (u8 const*)"first ", 6, &tls->enc));
    ASSERT_EQ(0, cvm_tls_push_encrypted_records(&wire, TLS_CONTENT_TYPE_APPDATA,
                                                (u8 const*)"second", 6, &tls->enc));

    CvmTlsBuf plain;
    cvm_tls_buf_init(&plain, NULL, 0);

    usize consumed = wire.off;
    ASSERT_EQ(0, cvm_tls_receive(tls, &plain, wire.base, &consumed));
    ASSERT_EQ(wire.off, consumed);
    ASSERT_EQ(12, plain.off);
    ASSERT_MEM_EQ("first second", plain.base, 12);

    /* Two records consumed two sequence numbers. */
    ASSERT_EQ(2, tls->dec.seq);

    cvm_tls_buf_dispose(&plain);
    cvm_tls_buf_dispose(&wire);
    drop_session(tls);
    PASS();
}

TEST record_split_across_calls(void) {
    CvmTlsContext ctx;
    CvmTls* tls = make_session(&ctx);
    ASSERT(tls != NULL);

    CvmTlsBuf wire;
    cvm_tls_buf_init(&wire, NULL, 0);
    ASSERT_EQ(0,
              cvm_tls_push_encrypted_records(&wire, TLS_CONTENT_TYPE_APPDATA,
                                             (u8 const*)"split record", 12, &tls->enc));

    CvmTlsBuf plain;
    cvm_tls_buf_init(&plain, NULL, 0);

    /* First three bytes: a truncated header, nothing to report. */
    usize first = 3;
    ASSERT_EQ(0, cvm_tls_receive(tls, &plain, wire.base, &first));
    ASSERT_EQ(0, plain.off);

    /* The rest completes the record. */
    usize second = wire.off - 3;
    ASSERT_EQ(0, cvm_tls_receive(tls, &plain, wire.base + 3, &second));
    ASSERT_EQ(12, plain.off);
    ASSERT_MEM_EQ("split record", plain.base, 12);

    cvm_tls_buf_dispose(&plain);
    cvm_tls_buf_dispose(&wire);
    drop_session(tls);
    PASS();
}

TEST close_notify_is_reported(void) {
    CvmTlsContext ctx;
    CvmTls* tls = make_session(&ctx);
    ASSERT(tls != NULL);

    CvmTlsBuf wire;
    cvm_tls_buf_init(&wire, NULL, 0);
    ASSERT_EQ(0, cvm_tls_push_encrypted_records(&wire, TLS_CONTENT_TYPE_APPDATA,
                                                (u8 const*)"bye", 3, &tls->enc));
    ASSERT_EQ(0, cvm_tls_send_alert(tls, &wire, 1, TLS_ALERT_CLOSE_NOTIFY));

    CvmTlsBuf plain;
    cvm_tls_buf_init(&plain, NULL, 0);

    usize consumed = wire.off;
    int ret = cvm_tls_receive(tls, &plain, wire.base, &consumed);

    /* The data before the alert still comes through. */
    ASSERT_EQ(3, plain.off);
    ASSERT_MEM_EQ("bye", plain.base, 3);
    /* And the alert is reported, not swallowed. */
    ASSERT_EQ(TLS_ERROR_CLASS_ALERT | TLS_ALERT_CLOSE_NOTIFY, ret);

    cvm_tls_buf_dispose(&plain);
    cvm_tls_buf_dispose(&wire);
    drop_session(tls);
    PASS();
}

TEST tampered_record_is_rejected(void) {
    CvmTlsContext ctx;
    CvmTls* tls = make_session(&ctx);
    ASSERT(tls != NULL);

    CvmTlsBuf wire;
    cvm_tls_buf_init(&wire, NULL, 0);
    ASSERT_EQ(0, cvm_tls_push_encrypted_records(&wire, TLS_CONTENT_TYPE_APPDATA,
                                                (u8 const*)"authentic", 9, &tls->enc));

    wire.base[7] ^= 0x08; /* flip a ciphertext bit */

    CvmTlsBuf plain;
    cvm_tls_buf_init(&plain, NULL, 0);

    usize consumed = wire.off;
    ASSERT_EQ(TLS_ALERT_BAD_RECORD_MAC,
              cvm_tls_receive(tls, &plain, wire.base, &consumed));
    ASSERT_EQ(0, plain.off);

    cvm_tls_buf_dispose(&plain);
    cvm_tls_buf_dispose(&wire);
    drop_session(tls);
    PASS();
}

TEST send_alert_before_keys_is_plaintext(void) {
    CvmTlsContext ctx;
    cvm_tls_context_defaults(&ctx);

    CvmTls* tls = cvm_tls_new(&ctx, false, "example.com");
    ASSERT(tls != NULL);

    CvmTlsBuf out;
    cvm_tls_buf_init(&out, NULL, 0);
    ASSERT_EQ(0, cvm_tls_send_alert(tls, &out, 2, TLS_ALERT_HANDSHAKE_FAILURE));

    /* 5-byte header + 2-byte alert, unencrypted. */
    ASSERT_EQ(7, out.off);
    ASSERT_EQ(TLS_CONTENT_TYPE_ALERT, out.base[0]);
    ASSERT_EQ(0, out.base[3]);
    ASSERT_EQ(2, out.base[4]);
    ASSERT_EQ(2, out.base[5]);
    ASSERT_EQ(TLS_ALERT_HANDSHAKE_FAILURE, out.base[6]);

    cvm_tls_buf_dispose(&out);
    cvm_tls_free(tls);
    PASS();
}

SUITE(tls_receive) {
    RUN_TEST(two_records_in_one_buffer);
    RUN_TEST(record_split_across_calls);
    RUN_TEST(close_notify_is_reported);
    RUN_TEST(tampered_record_is_rejected);
    RUN_TEST(send_alert_before_keys_is_plaintext);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_receive);
    GREATEST_MAIN_END();
}
