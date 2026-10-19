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

    /* Highest level with receive keys installed; see cvm_tls_get_read_epoch. */
    u32 read_epoch;

    /* QUIC transport mode. `quic` turns off the record layer entirely:
     * handshake messages are emitted as plaintext and tagged with the
     * encryption level they belong to. */
    bool quic;
    /* epoch_offsets[5] of the current cvm_tls_handle_message() call, or NULL.
     * Entry i is the END offset of the bytes belonging to epoch i-1, so the
     * range for epoch i is [offsets[i], offsets[i+1]). */
    usize* epoch_offsets;
    /* Encryption level the next emitted handshake message belongs to. */
    usize write_epoch;
    /* Local transport parameters. Copied, not referenced: ngtcp2 hands them
     * over in a stack buffer that is gone by the time ClientHello is built. */
    u8 local_quic_params[TLS_MAX_QUIC_PARAMS_SIZE];
    usize local_quic_params_len;
    /* ALPN protocols offered in ClientHello, owned by the caller. */
    CvmTlsVec const* alpns;
    usize nalpn;
    /* Peer's transport parameters, copied out of EncryptedExtensions. */
    u8 remote_quic_params[TLS_MAX_QUIC_PARAMS_SIZE];
    usize remote_quic_params_len;

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

    /* Opaque owner pointer. QUIC backends keep their connection reference
     * here so the traffic key callback can find the connection it belongs to. */
    void* app_data;
};

#endif /* CVMCRYPT_TLS_CONN_H */
