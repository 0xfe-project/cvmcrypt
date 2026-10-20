/*
 * src/tls/handshake.h
 *
 * TLS 1.3 handshake message encode/decode (RFC 8446 §4).
 */

#ifndef CVMCRYPT_TLS_HANDSHAKE_H
#define CVMCRYPT_TLS_HANDSHAKE_H

#include "tls/tls.h"

/* Handshake message header: type(1) + length(3). */
#define TLS_HANDSHAKE_HEADER_SIZE 4

/* ------------------------------------------------------------------ */
/* message structures                                                   */
/* ------------------------------------------------------------------ */

/* KeyShareEntry: group(2) + key_exchange(<1..2^16-1>). */
typedef struct CvmTlsKeyShareEntry {
    u16 group;
    CvmTlsVec key_exchange; /* peer public key */
} CvmTlsKeyShareEntry;

/* ClientHello (RFC 8446 §4.1.2). */
typedef struct CvmTlsClientHello {
    u8 random[32];
    CvmTlsVec legacy_session_id; /* echo back for middlebox compat */
    u16 cipher_suites[16];
    usize num_cipher_suites;

    /* Extensions we care about. */
    char const* server_name; /* SNI, NULL if absent */
    /*
     * Every key_share entry the client offered, in order. A client may send
     * several — OpenSSL 4 offers X25519MLKEM768 (0x11ec) first and x25519
     * second — so the server must scan the list for a group it supports
     * instead of taking the first entry.
     */
    CvmTlsKeyShareEntry key_shares[8];
    usize num_key_shares;
    u16 negotiated_version; /* from supported_versions ext */

    /* quic_transport_parameters (extension 0x39), verbatim; empty when the
     * client is not using QUIC. Points into the message, not owned. */
    CvmTlsVec quic_params;

    /* ALPN extension body (u16 list length + length-prefixed names), verbatim.
     * A QUIC server must pick one and echo it; a TLS server may ignore it. */
    CvmTlsVec alpn_list;

    /* Raw message (including header) for transcript hash. */
    CvmTlsVec raw;
} CvmTlsClientHello;

/* ServerHello (RFC 8446 §4.1.3). */
typedef struct CvmTlsServerHello {
    u8 random[32];
    CvmTlsVec legacy_session_id; /* must match ClientHello */
    u16 cipher_suite;
    CvmTlsKeyShareEntry key_share;
    u16 negotiated_version;
    bool is_hello_retry_request; /* random == HRR_RANDOM */
    CvmTlsVec raw;
} CvmTlsServerHello;

/* Certificate entry. */
typedef struct CvmTlsCertEntry {
    CvmTlsVec data;       /* DER certificate */
    CvmTlsVec extensions; /* raw extensions, usually empty */
} CvmTlsCertEntry;

/* Certificate message (RFC 8446 §4.4.2). */
typedef struct CvmTlsCertMsg {
    CvmTlsVec request_context; /* empty for server */
    CvmTlsCertEntry entries[8];
    usize num_entries;
} CvmTlsCertMsg;

/* CertificateVerify (RFC 8446 §4.4.3). */
typedef struct CvmTlsCertVerify {
    u16 algorithm;
    CvmTlsVec signature;
} CvmTlsCertVerify;

/* Finished (RFC 8446 §4.4.4). */
typedef struct CvmTlsFinished {
    CvmTlsVec verify_data;
} CvmTlsFinished;

/* NewSessionTicket (RFC 8446 §4.6.1). */
typedef struct CvmTlsNewSessionTicket {
    u32 ticket_lifetime;
    u32 ticket_age_add;
    CvmTlsVec ticket_nonce;
    CvmTlsVec ticket;
    u32 max_early_data_size;
} CvmTlsNewSessionTicket;

/* ------------------------------------------------------------------ */
/* encode                                                               */
/* ------------------------------------------------------------------ */

/* Build a ClientHello. Returns the message (including 4-byte header) in buf. */
int cvm_tls_encode_client_hello(CvmTlsBuf* buf,
                                CvmTlsCipherSuite const* const* cipher_suites,
                                u8 const random[32], CvmTlsVec legacy_session_id,
                                char const* server_name, CvmTlsKeyexAlgo const* keyex,
                                CvmTlsVec keyex_pubkey,
                                CvmTlsVec* psk_identity, /* NULL if no PSK */
                                u32 psk_obfuscated_ticket_age,
                                CvmTlsVec quic_transport_params, /* empty if not QUIC */
                                CvmTlsVec const* alpns, usize nalpn);

/* Read the peer's QUIC transport parameters (extension 0x39) out of an
 * EncryptedExtensions body. *params_len is 0 when the extension is absent. */
int cvm_tls_decode_encrypted_extensions(CvmTlsVec body, u8* quic_params,
                                        usize params_cap, usize* params_len);

/* Build a ServerHello. */
int cvm_tls_encode_server_hello(CvmTlsBuf* buf, CvmTlsCipherSuite const* suite,
                                u8 const random[32], CvmTlsVec legacy_session_id,
                                CvmTlsKeyexAlgo const* keyex, CvmTlsVec peer_key);

/* Build EncryptedExtensions (minimal: just ALPN + supported_groups). */
int cvm_tls_encode_encrypted_extensions(CvmTlsBuf* buf, CvmTlsVec* alpn_protocol,
                                        CvmTlsVec quic_params);

/* Build a Certificate message. */
int cvm_tls_encode_certificate(CvmTlsBuf* buf, CvmTlsVec const* certs, usize num_certs);

/* Build a CertificateVerify message. */
int cvm_tls_encode_certificate_verify(CvmTlsBuf* buf, u16 algorithm,
                                      CvmTlsVec signature);

/* Build a Finished message. */
int cvm_tls_encode_finished(CvmTlsBuf* buf, CvmTlsVec verify_data);

/* ------------------------------------------------------------------ */
/* decode                                                               */
/* ------------------------------------------------------------------ */

/* Parse a handshake message header. Returns type and advances past it. */
int cvm_tls_decode_handshake_header(u8* type, CvmTlsVec* body, u8 const** src,
                                    u8 const* end);

/* Parse a ClientHello. */
int cvm_tls_decode_client_hello(CvmTlsClientHello* ch, u8 const* src, u8 const* end);

/* Parse a ServerHello. */
int cvm_tls_decode_server_hello(CvmTlsServerHello* sh, u8 const* src, u8 const* end);

/* Parse a Certificate message. */
int cvm_tls_decode_certificate(CvmTlsCertMsg* cert, u8 const* src, u8 const* end);

/* Parse a CertificateVerify message. */
int cvm_tls_decode_certificate_verify(CvmTlsCertVerify* cv, u8 const* src,
                                      u8 const* end);

/* Parse a Finished message. */
int cvm_tls_decode_finished(CvmTlsFinished* fin, u8 const* src, u8 const* end);

/* Parse a NewSessionTicket message. */
int cvm_tls_decode_new_session_ticket(CvmTlsNewSessionTicket* nst, u8 const* src,
                                      u8 const* end);

/* ------------------------------------------------------------------ */
/* CertificateVerify signing input (RFC 8446 §4.4.3)                    */
/* ------------------------------------------------------------------ */

/* Build the content to be signed/verified:
 *   0x20*64 + context_string + 0x00 + Transcript-Hash */
int cvm_tls_build_cert_verify_data(
    u8* output, usize output_cap, usize* out_len,
    char const* context_string, /* "TLS 1.3, client" or "TLS 1.3, server" */
    u8 const* transcript_hash, usize hash_len);

#endif /* CVMCRYPT_TLS_HANDSHAKE_H */
