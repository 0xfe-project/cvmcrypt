/*
 * tests/unit/test_tls_quic_server.c
 *
 * The server half of QUIC mode.
 *
 * Until this existed the QUIC support in cvmcrypt was client-only: the server
 * wrote TLS records, never set epoch_offsets, and answered a ClientHello with
 * an ACK and nothing else. This test pins down the three things that were
 * missing, using a real ClientHello from our own client rather than a
 * hand-built byte string:
 *
 *   1. ServerHello is bare bytes at the Initial level (epoch 0), and
 *      everything after it is bare bytes at the Handshake level (epoch 2) —
 *      no record headers anywhere.
 *   2. EncryptedExtensions carries quic_transport_parameters.
 *   3. The ALPN the client offered is the one the server picks and echoes.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "base/types.h"
#include "tls/handshake.h"
#include "tls/tls.h"
#include "tls/tls_conn.h"
#include "tls/tls_internal.h"

static void srv_test_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    memset(buf, 0x5a, len);
}

static CvmTlsRandomBytes const SrvRandom = {.cb = srv_test_random};

/* A signer that produces a fixed blob: this test is about the framing of the
 * handshake, not about ECDSA, which test_ecdsa covers. */
static int srv_test_sign(struct CvmTlsSignCert* self, CvmTls* tls,
                         u16* selected_algorithm, CvmTlsBuf* output, CvmTlsVec input,
                         u16 const* algorithms, usize num_algorithms) {
    (void)self;
    (void)tls;
    (void)input;
    (void)algorithms;
    (void)num_algorithms;
    *selected_algorithm = TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    for (usize i = 0; i < 64; i++) {
        if (cvm_tls_buf_push(output, (u8)(0xa0 + (i & 0x0f))) != 0)
            return -1;
    }
    return 0;
}
static CvmTlsSignCert const SrvSign = {.cb = srv_test_sign};

static u8 const FAKE_CERT[] = "not a real certificate, and this test knows it";

static CvmTlsCert const SrvCerts[] = {
    {.der = {FAKE_CERT, sizeof(FAKE_CERT) - 1}},
    {.der = {NULL, 0}},
};

/* A real client, in QUIC mode, offering one ALPN and some transport
 * parameters. */
static CvmTlsBuf make_client_hello(CvmTls** out_tls, CvmTlsContext* ctx) {
    cvm_tls_context_defaults(ctx);
    ctx->random_bytes = (CvmTlsRandomBytes*)&SrvRandom;

    CvmTls* tls = cvm_tls_new(ctx, false, "example.com");
    if (tls == NULL)
        return (CvmTlsBuf){0};

    static u8 const ALPN[] = "cvmsockets-echo";
    CvmTlsVec alpn = {(u8 const*)ALPN, sizeof(ALPN) - 1};
    cvm_tls_set_alpn(tls, &alpn, 1);

    u8 params[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    cvm_tls_quic_set_local_transport_params(tls, params, sizeof(params));

    CvmTlsBuf sendbuf;
    cvm_tls_buf_init(&sendbuf, NULL, 0);
    usize offsets[5];
    /* ASSERT is not available in a helper that returns a struct, so the
     * caller checks the buffer is non-empty instead. */
    (void)cvm_tls_handle_message(tls, &sendbuf, offsets, 0, NULL, 0, NULL);

    *out_tls = tls;
    return sendbuf;
}

TEST server_hello_is_bare_and_at_the_initial_level(void) {
    CvmTlsContext cctx;
    CvmTls* client = NULL;
    CvmTlsBuf ch = make_client_hello(&client, &cctx);
    ASSERT(ch.off > 0);

    CvmTlsContext sctx;
    cvm_tls_context_defaults(&sctx);
    sctx.random_bytes = (CvmTlsRandomBytes*)&SrvRandom;
    sctx.certificates = (CvmTlsCert*)SrvCerts;
    sctx.sign_certificate = (CvmTlsSignCert*)&SrvSign;

    CvmTls* server = cvm_tls_new(&sctx, true, NULL);
    ASSERT(server != NULL);

    static u8 const ALPN[] = "cvmsockets-echo";
    CvmTlsVec alpn = {(u8 const*)ALPN, sizeof(ALPN) - 1};
    cvm_tls_set_alpn(server, &alpn, 1);

    /* A QUIC server's own parameters; the ngtcp2 backend supplies these from
     * the connection, so the test supplies them the same way. */
    u8 srv_params[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    ASSERT_EQ(0, cvm_tls_quic_set_local_transport_params(server, srv_params,
                                                         sizeof(srv_params)));

    CvmTlsBuf out;
    cvm_tls_buf_init(&out, NULL, 0);
    usize offsets[5];

    int const ret =
        cvm_tls_handle_message(server, &out, offsets, 0, ch.base, ch.off, NULL);
    ASSERT(ret == 0 || ret == TLS_ERROR_IN_PROGRESS);

    /* The whole flight is plaintext handshake bytes: ServerHello first. */
    ASSERT(out.off > 0);
    ASSERT_EQ(TLS_HANDSHAKE_TYPE_SERVER_HELLO, out.base[0]);

    /* epoch 0 holds exactly the ServerHello, and the rest starts at the
     * Handshake level. A record header (0x16 0x03 0x03) here would mean the
     * server never took the QUIC path. */
    usize const sh_len = 4 + (((usize)out.base[1] << 16) | ((usize)out.base[2] << 8) |
                              (usize)out.base[3]);
    ASSERT_EQ(sh_len, offsets[1]);
    ASSERT_EQ(sh_len, offsets[2]);
    ASSERT(offsets[3] > offsets[2]);
    ASSERT_EQ(TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, out.base[offsets[2]]);

    /* The transport parameters are found by the same decoder the client uses
     * on a real server's EncryptedExtensions — not by a hand-rolled walker, so
     * the test cannot agree with a wrong encoder. */
    {
        u8 const* ee = out.base + offsets[2];
        usize const ee_body =
            4 + (((usize)ee[1] << 16) | ((usize)ee[2] << 8) | (usize)ee[3]);
        ASSERT(offsets[2] + ee_body <= offsets[3]);

        u8 ext[64];
        usize n = 0;
        int const dr = cvm_tls_decode_encrypted_extensions(
            (CvmTlsVec){(u8*)(ee + 4), ee_body - 4}, ext, sizeof(ext), &n);
        ASSERT_EQ(0, dr);
        ASSERT_EQ(6, n);
    }

    ASSERT_EQ(sizeof(ALPN) - 1, server->negotiated_alpn.len);
    ASSERT_MEM_EQ(ALPN, server->negotiated_alpn.base, sizeof(ALPN) - 1);
    ASSERT_EQ(6, server->remote_quic_params_len);

    cvm_tls_buf_dispose(&out);
    cvm_tls_buf_dispose(&ch);
    cvm_tls_free(server);
    cvm_tls_free(client);
    PASS();
}

/*
 * Without a common ALPN a QUIC handshake has to fail: the whole point of ALPN
 * in QUIC is that the protocol is settled before any application data, and
 * guessing one is how two implementations end up speaking different things.
 */
TEST server_requires_a_common_alpn_in_quic_mode(void) {
    CvmTlsContext cctx;
    CvmTls* client = NULL;
    CvmTlsBuf ch = make_client_hello(&client, &cctx);
    ASSERT(ch.off > 0);

    CvmTlsContext sctx;
    cvm_tls_context_defaults(&sctx);
    sctx.random_bytes = (CvmTlsRandomBytes*)&SrvRandom;
    sctx.certificates = (CvmTlsCert*)SrvCerts;
    sctx.sign_certificate = (CvmTlsSignCert*)&SrvSign;

    CvmTls* server = cvm_tls_new(&sctx, true, NULL);
    ASSERT(server != NULL);

    static u8 const OTHER[] = "something-else";
    CvmTlsVec alpn = {(u8 const*)OTHER, sizeof(OTHER) - 1};
    cvm_tls_set_alpn(server, &alpn, 1);

    CvmTlsBuf out;
    cvm_tls_buf_init(&out, NULL, 0);
    usize offsets[5];

    int const ret =
        cvm_tls_handle_message(server, &out, offsets, 0, ch.base, ch.off, NULL);
    ASSERT_EQ(TLS_ALERT_NO_APPLICATION_PROTOCOL, ret);

    cvm_tls_buf_dispose(&out);
    cvm_tls_buf_dispose(&ch);
    cvm_tls_free(server);
    cvm_tls_free(client);
    PASS();
}

SUITE(tls_quic_server) {
    RUN_TEST(server_hello_is_bare_and_at_the_initial_level);
    RUN_TEST(server_requires_a_common_alpn_in_quic_mode);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_quic_server);
    GREATEST_MAIN_END();
}
