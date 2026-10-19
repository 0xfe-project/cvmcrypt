/*
 * tests/unit/test_tls_handshake.c
 *
 * TLS 1.3 handshake message encode/decode round-trip tests.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/handshake.h"
#include "base/types.h"

/* ------------------------------------------------------------------ */
/* dummy cipher suite                                                   */
/* ------------------------------------------------------------------ */

static CvmTlsAeadAlgo const DUMMY_AEAD = {
    .name = "dummy",
    .key_size = 16,
    .iv_size = 12,
    .tag_size = 16,
    .setup = NULL,
};

static CvmTlsHashAlgo const DUMMY_HASH = {
    .name = "sha256",
    .block_size = 64,
    .digest_size = 32,
    .create = NULL,
};

static CvmTlsCipherSuite const SUITE_AES128 = {
    .id = TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .aead = &DUMMY_AEAD,
    .hash = &DUMMY_HASH,
    .name = "TLS_AES_128_GCM_SHA256",
};

static CvmTlsCipherSuite const SUITE_CHACHA = {
    .id = TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
    .aead = &DUMMY_AEAD,
    .hash = &DUMMY_HASH,
    .name = "TLS_CHACHA20_POLY1305_SHA256",
};

static CvmTlsCipherSuite const* const SUITES[] = {&SUITE_AES128, &SUITE_CHACHA, NULL};

static CvmTlsKeyexAlgo const DUMMY_KEYEX = {
    .name = "x25519",
    .id = TLS_GROUP_X25519,
    .shared_secret_size = 32,
    .create = NULL,
};

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST client_hello_roundtrip(void) {
    u8 random[32];
    for (int i = 0; i < 32; i++)
        random[i] = (u8)(i * 3);

    u8 session_id[32];
    for (int i = 0; i < 32; i++)
        session_id[i] = (u8)(i * 5);

    u8 pubkey[32];
    for (int i = 0; i < 32; i++)
        pubkey[i] = (u8)(i * 7);

    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    int ret = cvm_tls_encode_client_hello(
        &buf, SUITES, random, (CvmTlsVec){session_id, 32}, "example.com", &DUMMY_KEYEX,
        (CvmTlsVec){pubkey, 32}, NULL, 0, (CvmTlsVec){NULL, 0}, NULL, 0);
    ASSERT_EQ(0, ret);
    ASSERT(buf.off > 100); /* should be substantial */

    /* Decode. */
    CvmTlsClientHello ch;
    u8 const* src = buf.base;
    ret = cvm_tls_decode_client_hello(&ch, src + 4, src + buf.off); /* skip header */
    ASSERT_EQ(0, ret);

    /* Verify fields. */
    ASSERT(memcmp(ch.random, random, 32) == 0);
    ASSERT_EQ(32, ch.legacy_session_id.len);
    ASSERT(memcmp(ch.legacy_session_id.base, session_id, 32) == 0);
    ASSERT_EQ(2, ch.num_cipher_suites);
    ASSERT_EQ(TLS_CIPHER_SUITE_AES_128_GCM_SHA256, ch.cipher_suites[0]);
    ASSERT_EQ(TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256, ch.cipher_suites[1]);
    ASSERT_EQ(TLS_GROUP_X25519, ch.key_share.group);
    ASSERT_EQ(32, ch.key_share.key_exchange.len);
    ASSERT(memcmp(ch.key_share.key_exchange.base, pubkey, 32) == 0);
    ASSERT_EQ(TLS_PROTOCOL_VERSION_TLS13, ch.negotiated_version);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST server_hello_roundtrip(void) {
    u8 random[32];
    for (int i = 0; i < 32; i++)
        random[i] = (u8)(i * 11);
    u8 session_id[32] = {0};
    u8 server_pubkey[32];
    for (int i = 0; i < 32; i++)
        server_pubkey[i] = (u8)(i * 13);

    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    int ret = cvm_tls_encode_server_hello(&buf, &SUITE_AES128, random,
                                          (CvmTlsVec){session_id, 32}, &DUMMY_KEYEX,
                                          (CvmTlsVec){server_pubkey, 32});
    ASSERT_EQ(0, ret);

    /* Decode. */
    CvmTlsServerHello sh;
    u8 const* src = buf.base;
    ret = cvm_tls_decode_server_hello(&sh, src + 4, src + buf.off);
    ASSERT_EQ(0, ret);

    ASSERT(memcmp(sh.random, random, 32) == 0);
    ASSERT_EQ(32, sh.legacy_session_id.len);
    ASSERT_EQ(TLS_CIPHER_SUITE_AES_128_GCM_SHA256, sh.cipher_suite);
    ASSERT_EQ(TLS_GROUP_X25519, sh.key_share.group);
    ASSERT_EQ(32, sh.key_share.key_exchange.len);
    ASSERT(memcmp(sh.key_share.key_exchange.base, server_pubkey, 32) == 0);
    ASSERT_EQ(TLS_PROTOCOL_VERSION_TLS13, sh.negotiated_version);
    ASSERT(!sh.is_hello_retry_request);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST certificate_roundtrip(void) {
    u8 cert1_data[] = "fake cert 1";
    u8 cert2_data[] = "fake cert 2";
    CvmTlsVec certs[] = {
        {cert1_data, sizeof(cert1_data) - 1},
        {cert2_data, sizeof(cert2_data) - 1},
    };

    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    int ret = cvm_tls_encode_certificate(&buf, certs, 2);
    ASSERT_EQ(0, ret);

    /* Decode. */
    CvmTlsCertMsg cert;
    u8 const* src = buf.base;
    ret = cvm_tls_decode_certificate(&cert, src + 4, src + buf.off);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(0, cert.request_context.len);
    ASSERT_EQ(2, cert.num_entries);
    ASSERT_EQ(sizeof(cert1_data) - 1, cert.entries[0].data.len);
    ASSERT(memcmp(cert.entries[0].data.base, cert1_data, sizeof(cert1_data) - 1) == 0);
    ASSERT_EQ(sizeof(cert2_data) - 1, cert.entries[1].data.len);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST certificate_verify_roundtrip(void) {
    u8 sig[] = "fake signature data";
    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    int ret = cvm_tls_encode_certificate_verify(&buf, TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                                                (CvmTlsVec){sig, sizeof(sig) - 1});
    ASSERT_EQ(0, ret);

    CvmTlsCertVerify cv;
    u8 const* src = buf.base;
    ret = cvm_tls_decode_certificate_verify(&cv, src + 4, src + buf.off);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, cv.algorithm);
    ASSERT_EQ(sizeof(sig) - 1, cv.signature.len);
    ASSERT(memcmp(cv.signature.base, sig, sizeof(sig) - 1) == 0);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST finished_roundtrip(void) {
    u8 verify_data[32];
    for (int i = 0; i < 32; i++)
        verify_data[i] = (u8)(i * 3);

    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    int ret = cvm_tls_encode_finished(&buf, (CvmTlsVec){verify_data, 32});
    ASSERT_EQ(0, ret);

    /* Verify header. */
    ASSERT_EQ(TLS_HANDSHAKE_TYPE_FINISHED, buf.base[0]);
    ASSERT_EQ(32, (buf.base[1] << 16) | (buf.base[2] << 8) | buf.base[3]);

    /* Decode. */
    CvmTlsFinished fin;
    ret = cvm_tls_decode_finished(&fin, buf.base + 4, buf.base + buf.off);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(32, fin.verify_data.len);
    ASSERT(memcmp(fin.verify_data.base, verify_data, 32) == 0);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST handshake_header_decode(void) {
    /* Build a Finished and parse the header. */
    u8 verify_data[4] = {1, 2, 3, 4};
    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    cvm_tls_encode_finished(&buf, (CvmTlsVec){verify_data, 4});

    u8 type;
    CvmTlsVec body;
    u8 const* src = buf.base;
    u8 const* end = buf.base + buf.off;
    int ret = cvm_tls_decode_handshake_header(&type, &body, &src, end);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(TLS_HANDSHAKE_TYPE_FINISHED, type);
    ASSERT_EQ(4, body.len);
    ASSERT(memcmp(body.base, verify_data, 4) == 0);
    ASSERT(src == end); /* consumed all */

    cvm_tls_buf_dispose(&buf);
    PASS();
}

TEST cert_verify_data_build(void) {
    u8 transcript_hash[32];
    for (int i = 0; i < 32; i++)
        transcript_hash[i] = (u8)i;

    u8 output[160];
    usize out_len;
    int ret = cvm_tls_build_cert_verify_data(output, sizeof(output), &out_len,
                                             "TLS 1.3, server CertificateVerify",
                                             transcript_hash, 32);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(64 + 33 + 1 + 32, out_len); /* 64 spaces + ctx(33) + \0 + hash */

    /* Check first 64 bytes are 0x20. */
    for (int i = 0; i < 64; i++)
        ASSERT_EQ(0x20, output[i]);

    /* Check context string. */
    ASSERT(memcmp(output + 64, "TLS 1.3, server CertificateVerify", 33) == 0);

    /* Check separator. */
    ASSERT_EQ(0, output[64 + 33]);

    /* Check transcript hash. */
    ASSERT(memcmp(output + 64 + 33 + 1, transcript_hash, 32) == 0);

    PASS();
}

TEST new_session_ticket_roundtrip(void) {
    /* Build a NewSessionTicket manually (encode not provided; test decode). */
    u8 ticket_data[] = "session-ticket-data";
    CvmTlsBuf buf;
    cvm_tls_buf_init(&buf, NULL, 0);

    /* Manually construct: lifetime(4) + age_add(4) + nonce_len(1) + nonce +
     * ticket_len(2) + ticket + ext_len(2)=0. */
    cvm_tls_buf_push(&buf, 0x00);
    cvm_tls_buf_push(&buf, 0x00);
    cvm_tls_buf_push(&buf, 0x01);
    cvm_tls_buf_push(&buf, 0x00); /* lifetime=256 */
    cvm_tls_buf_push(&buf, 0x12);
    cvm_tls_buf_push(&buf, 0x34);
    cvm_tls_buf_push(&buf, 0x56);
    cvm_tls_buf_push(&buf, 0x78); /* age_add */
    cvm_tls_buf_push(&buf, 0x04); /* nonce_len=4 */
    cvm_tls_buf_push(&buf, 0xAA);
    cvm_tls_buf_push(&buf, 0xBB);
    cvm_tls_buf_push(&buf, 0xCC);
    cvm_tls_buf_push(&buf, 0xDD); /* nonce */
    cvm_tls_buf_push(&buf, 0x00);
    cvm_tls_buf_push(&buf, 0x13); /* ticket_len=19 */
    cvm_tls_buf_pushv(&buf, ticket_data, 19);
    cvm_tls_buf_push(&buf, 0x00);
    cvm_tls_buf_push(&buf, 0x00); /* ext_len=0 */

    /* Skip handshake header (4 bytes: type + len). Not included in manual build. */
    CvmTlsNewSessionTicket nst;
    int ret = cvm_tls_decode_new_session_ticket(&nst, buf.base, buf.base + buf.off);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(256, nst.ticket_lifetime);
    ASSERT_EQ(0x12345678, nst.ticket_age_add);
    ASSERT_EQ(4, nst.ticket_nonce.len);
    ASSERT_EQ(19, nst.ticket.len);
    ASSERT(memcmp(nst.ticket.base, ticket_data, 19) == 0);

    cvm_tls_buf_dispose(&buf);
    PASS();
}

SUITE(tls_handshake) {
    RUN_TEST(client_hello_roundtrip);
    RUN_TEST(server_hello_roundtrip);
    RUN_TEST(certificate_roundtrip);
    RUN_TEST(certificate_verify_roundtrip);
    RUN_TEST(finished_roundtrip);
    RUN_TEST(handshake_header_decode);
    RUN_TEST(cert_verify_data_build);
    RUN_TEST(new_session_ticket_roundtrip);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_handshake);
    GREATEST_MAIN_END();
}
