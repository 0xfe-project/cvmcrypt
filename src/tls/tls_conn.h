/*
 * src/tls/tls_conn.h
 *
 * Internal CvmTls connection state. Defined here (not in tls.h) to keep
 * the public API opaque.
 */

#ifndef CVMCRYPT_TLS_CONN_H
#define CVMCRYPT_TLS_CONN_H

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/keyschedule.h"
#include "tls/handshake.h"

struct CvmTls {
    CvmTlsContext const* ctx;
    CvmTlsState state;
    bool is_server;
    bool handshake_complete;

    /* Negotiated parameters. */
    CvmTlsCipherSuite const* suite;
    char const* server_name; /* SNI */

    /* Randoms (for session id / logging). */
    u8 client_random[32];
    u8 server_random[32];

    /* Key exchange (client side: our ephemeral; server side: peer's). */
    CvmTlsKeyexCtx* keyex_ctx;
    u8 keyex_pubkey[64]; /* our public key (max 64 for P-384 uncompressed) */
    usize keyex_pubkey_len;

    /* Key schedule + traffic secrets. */
    CvmTlsKeySched ks;
    u8 client_hs_secret[TLS_MAX_DIGEST_SIZE]; /* handshake traffic secret */
    u8 server_hs_secret[TLS_MAX_DIGEST_SIZE];
    u8 client_ap_secret[TLS_MAX_DIGEST_SIZE]; /* application traffic secret */
    u8 server_ap_secret[TLS_MAX_DIGEST_SIZE];

    /* Record encryption/decryption. */
    CvmTlsTrafficProt enc;
    CvmTlsTrafficProt dec;

    /* Received server certificate (DER). */
    CvmTlsCertEntry certs[4];
    usize num_certs;

    /* Legacy session ID for middlebox compat. */
    u8 legacy_session_id[32];
    usize legacy_session_id_len;

    /* Pending record buffer (partial record reassembly). */
    CvmTlsBuf recvbuf_rec;
    CvmTlsBuf recvbuf_msg; /* handshake message reassembly */

    /* Handshake retransmit buffer (for HRR). */
    CvmTlsBuf sendbuf_early; /* ClientHello bytes for transcript */

    /* Verify certificate callback data (from ctx). */
    void* verify_data;
};

#endif /* CVMCRYPT_TLS_CONN_H */
