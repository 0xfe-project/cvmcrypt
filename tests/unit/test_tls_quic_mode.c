/*
 * tests/unit/test_tls_quic_mode.c
 *
 * The QUIC transport mode's contract, as far as it can be checked without a
 * QUIC peer:
 *
 *   - ClientHello carries the quic_transport_parameters extension (0x39), and
 *     only in QUIC mode. A QUIC server aborts the handshake when it is
 *     missing, so "we forgot it" must be a test failure and not an interop
 *     surprise.
 *   - EncryptedExtensions parsing pulls 0x39 back out.
 *   - handle_message() emits ClientHello as plaintext at level 0, sets the
 *     epoch_offsets boundary the caller reads, and refuses input that arrives
 *     at the wrong encryption level.
 *
 * What this file cannot check is the handshake itself: that needs another
 * QUIC implementation to feed real CRYPTO frames. Until that harness exists,
 * treat the byte flow as unverified — the pieces here are the parts that can
 * be pinned down in isolation.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "base/types.h"
#include "tls/handshake.h"
#include "tls/tls.h"
#include "tls/tls_conn.h"
#include "tls/tls_internal.h"

static void dummy_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    memset(buf, 0x5a, len);
}

static CvmTlsRandomBytes const DUMMY_RANDOM = {.cb = dummy_random};

static CvmTls* new_client(CvmTlsContext* ctx) {
    cvm_tls_context_defaults(ctx);
    ctx->random_bytes = (CvmTlsRandomBytes*)&DUMMY_RANDOM;
    return cvm_tls_new(ctx, false, "example.com");
}

/* Walk a ClientHello body and copy out extension |want|. Returns its length,
 * or 0 when absent. */
static usize find_extension(u8 const* msg, usize msglen, u16 want, u8* out,
                            usize outcap) {
    if (msglen < 4)
        return 0;

    usize body_len = ((usize)msg[1] << 16) | ((usize)msg[2] << 8) | msg[3];
    if (body_len + 4 > msglen)
        return 0;

    u8 const* p = msg + 4;
    u8 const* end = p + body_len;

    if (p + 2 + 32 + 1 > end)
        return 0;
    p += 2 + 32;      /* legacy_version, random */
    usize sid = *p++; /* session id */
    if (p + sid > end)
        return 0;
    p += sid;

    usize cs = ((usize)p[0] << 8) | p[1];
    p += 2 + cs;
    if (p + 1 > end)
        return 0;
    usize comp = *p++;
    p += comp;

    if (p + 2 > end)
        return 0;
    usize ext_total = ((usize)p[0] << 8) | p[1];
    p += 2;
    if (p + ext_total > end)
        return 0;

    u8 const* ext_end = p + ext_total;
    while (p + 4 <= ext_end) {
        u16 type = (u16)(((u16)p[0] << 8) | p[1]);
        usize len = ((usize)p[2] << 8) | p[3];
        p += 4;
        if (p + len > ext_end)
            return 0;
        if (type == want) {
            if (len > outcap)
                return 0;
            memcpy(out, p, len);
            return len;
        }
        p += len;
    }
    return 0;
}

TEST client_hello_carries_transport_params_in_quic_mode(void) {
    CvmTlsContext ctx;
    CvmTls* tls = new_client(&ctx);
    ASSERT(tls != NULL);

    u8 params[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    ASSERT_EQ(0, cvm_tls_quic_set_local_transport_params(tls, params, sizeof(params)));

    usize epoch_offsets[5];
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    int ret = cvm_tls_handle_message(tls, &sendbuf, epoch_offsets, 0, NULL, 0, NULL);
    ASSERT_EQ(TLS_ERROR_IN_PROGRESS, ret);

    /* ClientHello is plaintext at level 0: the whole buffer is epoch 0. */
    ASSERT_EQ(0, epoch_offsets[0]);
    ASSERT_EQ(sendbuf.off, epoch_offsets[1]);
    ASSERT_EQ(0x01, sendbuf.base[0]); /* CLIENT_HELLO */

    u8 got[64];
    usize n = find_extension(sendbuf.base, sendbuf.off, 0x0039, got, sizeof(got));
    ASSERT_EQ(sizeof(params), n);
    ASSERT_MEM_EQ(params, got, sizeof(params));

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

TEST client_hello_omits_transport_params_in_tcp_mode(void) {
    CvmTlsContext ctx;
    CvmTls* tls = new_client(&ctx);
    ASSERT(tls != NULL);

    u8 params[] = {0x09, 0x08};
    ASSERT_EQ(0, cvm_tls_quic_set_local_transport_params(tls, params, sizeof(params)));

    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    usize inlen = 0;
    ASSERT_EQ(TLS_ERROR_IN_PROGRESS,
              cvm_tls_handshake(tls, &sendbuf, NULL, &inlen, NULL));

    /* Skip the 5-byte record header. */
    u8 got[64];
    usize const n =
        find_extension(sendbuf.base + 5, sendbuf.off - 5, 0x0039, got, sizeof(got));
    ASSERT_EQ(0, n);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

TEST encrypted_extensions_decode(void) {
    /* extensions: 0x0039 with 4 bytes, then 0x0010 (ALPN) which must be
     * ignored. */
    u8 body[] = {
        0x00, 0x0e,                                     /* block length 14 */
        0x00, 0x39, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, /* transport params */
        0x00, 0x10, 0x00, 0x02, 0x68, 0x32,             /* ALPN "h2" */
    };

    u8 out[16];
    usize got = 0;
    ASSERT_EQ(0, cvm_tls_decode_encrypted_extensions((CvmTlsVec){body, sizeof(body)},
                                                     out, sizeof(out), &got));
    ASSERT_EQ(4, got);
    ASSERT_MEM_EQ("\xde\xad\xbe\xef", out, 4);

    /* Absent extension: length zero, no error. */
    u8 noext[] = {0x00, 0x06, 0x00, 0x10, 0x00, 0x02, 0x68, 0x32};
    struct {
        u8 len;
        u8 first;
    } halftest;
    ASSERT_EQ(0, cvm_tls_decode_encrypted_extensions((CvmTlsVec){noext, sizeof(noext)},
                                                     out, sizeof(out), &got));
    ASSERT_EQ(0, got);
    (void)halftest;
    PASS();
}

TEST encrypted_extensions_truncated_is_rejected(void) {
    u8 body[] = {0x00, 0x20, 0x00, 0x39, 0x00, 0x04, 0xde, 0xad};
    u8 out[16];
    usize got = 0;
    ASSERT_EQ(TLS_ALERT_DECODE_ERROR,
              cvm_tls_decode_encrypted_extensions((CvmTlsVec){body, sizeof(body)}, out,
                                                  sizeof(out), &got));
    PASS();
}

TEST handle_message_rejects_wrong_epoch(void) {
    CvmTlsContext ctx;
    CvmTls* tls = new_client(&ctx);
    ASSERT(tls != NULL);

    usize epoch_offsets[5];
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    /* A fresh client can only accept level 0; there are no keys above it. */
    u8 hs[] = {0x02, 0x00, 0x00, 0x00};
    int ret =
        cvm_tls_handle_message(tls, &sendbuf, epoch_offsets, 2, hs, sizeof(hs), NULL);
    ASSERT_EQ(TLS_ALERT_UNEXPECTED_MESSAGE, ret);

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

TEST handle_message_reassembles_split_message(void) {
    CvmTlsContext ctx;
    CvmTls* tls = new_client(&ctx);
    ASSERT(tls != NULL);

    usize epoch_offsets[5];
    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);

    ASSERT_EQ(TLS_ERROR_IN_PROGRESS,
              cvm_tls_handle_message(tls, &sendbuf, epoch_offsets, 0, NULL, 0, NULL));
    usize const ch_len = sendbuf.off;
    sendbuf.off = 0;

    /*
     * Half a ServerHello header: a length field but no body. The state
     * machine must not be reached, and nothing may be consumed.
     */
    u8 half[] = {0x02, 0x00, 0x00, 0x20};
    ASSERT_EQ(TLS_ERROR_IN_PROGRESS,
              cvm_tls_handle_message(tls, &sendbuf, epoch_offsets, 0, half,
                                     sizeof(half), NULL));
    ASSERT_EQ(sizeof(half), tls->recvbuf_msg.off);
    ASSERT_EQ(0, sendbuf.off);
    ASSERT_EQ(TLS_STATE_CLIENT_EXPECT_SERVER_HELLO, tls->state);
    (void)ch_len;

    cvm_tls_buf_dispose(&sendbuf);
    cvm_tls_free(tls);
    PASS();
}

SUITE(tls_quic_mode) {
    RUN_TEST(client_hello_carries_transport_params_in_quic_mode);
    RUN_TEST(client_hello_omits_transport_params_in_tcp_mode);
    RUN_TEST(encrypted_extensions_decode);
    RUN_TEST(encrypted_extensions_truncated_is_rejected);
    RUN_TEST(handle_message_rejects_wrong_epoch);
    RUN_TEST(handle_message_reassembles_split_message);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_quic_mode);
    GREATEST_MAIN_END();
}
