/*
 * src/tls/tls.h
 *
 * TLS 1.3 (RFC 8446) — types and public API.
 *
 * Ported from picotls (MIT License, h2o/picotls) to cvm conventions:
 * u8/u16/u32/u64 fixed-width, const discipline, zero libc, I/O callbacks.
 *
 * TLS 1.2, ECH, logging, QUICLB, and import/export are removed.
 * QUIC transport mode (ptls_handle_message) is retained for future HTTP/3.
 */

#ifndef CVMCRYPT_TLS_H
#define CVMCRYPT_TLS_H

#include "base/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* constants                                                            */
/* ------------------------------------------------------------------ */

#define TLS_PROTOCOL_VERSION_TLS13 0x0304
#define TLS_HELLO_RANDOM_SIZE 32
#define TLS_MAX_DIGEST_SIZE 64
#define TLS_MAX_BLOCK_SIZE 128 /* SHA-512/384 block size */
#define TLS_MAX_IV_SIZE 16
#define TLS_MAX_SECRET_SIZE 64

/* record layer */
#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_TYPE_ALERT 21
#define TLS_CONTENT_TYPE_HANDSHAKE 22
#define TLS_CONTENT_TYPE_APPDATA 23

#define TLS_RECORD_HEADER_LENGTH 5
#define TLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define TLS_MAX_ENCRYPTED_RECORD_SIZE (TLS_MAX_PLAINTEXT_RECORD_SIZE + 256)

/* handshake message types (RFC 8446 §4) */
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET 4
#define TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA 5
#define TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define TLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
#define TLS_HANDSHAKE_TYPE_FINISHED 20
#define TLS_HANDSHAKE_TYPE_KEY_UPDATE 24
#define TLS_HANDSHAKE_TYPE_MESSAGE_HASH 254

/* extensions (RFC 8446 §11) */
/* How many ALPN protocols a single endpoint may offer. */
#define TLS_MAX_ALPN 8

#define TLS_EXTENSION_TYPE_SERVER_NAME 0
#define TLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define TLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define TLS_EXTENSION_TYPE_ALPN 16
#define TLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define TLS_EXTENSION_TYPE_EARLY_DATA 42
#define TLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define TLS_EXTENSION_TYPE_COOKIE 44
#define TLS_EXTENSION_TYPE_KEY_SHARE 51
#define TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS 57
#define TLS_EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES 45
#define TLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS_CERT 50

/* cipher suites (TLS 1.3 only) */
#define TLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define TLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* key exchange groups */
#define TLS_GROUP_SECP256R1 0x0017
#define TLS_GROUP_SECP384R1 0x0018
#define TLS_GROUP_X25519 0x001D

/* signature algorithms */
#define TLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define TLS_SIGNATURE_RSA_PKCS1_SHA384 0x0501
#define TLS_SIGNATURE_RSA_PKCS1_SHA512 0x0601
#define TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 0x0503
#define TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 0x0804
#define TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 0x0805
#define TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 0x0806

/* PSK key exchange modes */
#define TLS_PSK_KE_MODE_NONE 0
#define TLS_PSK_KE_MODE_PSK_DHE_KEY_EXCHANGE 1

/* alerts (RFC 8446 §6) */
#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_BAD_CERTIFICATE 42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_CERTIFICATE_REVOKED 44
#define TLS_ALERT_CERTIFICATE_EXPIRED 45
#define TLS_ALERT_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_UNKNOWN_CA 48
#define TLS_ALERT_ACCESS_DENIED 49
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK 86
#define TLS_ALERT_USER_CANCELED 90
#define TLS_ALERT_MISSING_EXTENSION 109
#define TLS_ALERT_UNSUPPORTED_EXTENSION 110
#define TLS_ALERT_UNRECOGNIZED_NAME 112
#define TLS_ALERT_CERTIFICATE_REQUIRED 116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL 120

/* ------------------------------------------------------------------ */
/* error codes                                                          */
/* ------------------------------------------------------------------ */

/*
 * Alert class must not be zero: `TLS_ERROR_CLASS_ALERT | TLS_ALERT_CLOSE_NOTIFY`
 * is the close_notify return value, and TLS_ALERT_CLOSE_NOTIFY is 0. With a
 * zero class that value collides with "success", so every caller comparing
 * against it sees close_notify where there was none — which is exactly what
 * made the sockets library hang up on the first successful read.
 */
#define TLS_ERROR_CLASS_ALERT 0x30000
#define TLS_ERROR_CLASS_EXTERNAL 0x10000
#define TLS_ERROR_CLASS_INTERNAL 0x20000

#define TLS_ERROR_NO_MEMORY (TLS_ERROR_CLASS_INTERNAL + 1)
#define TLS_ERROR_IN_PROGRESS (TLS_ERROR_CLASS_INTERNAL + 2)
#define TLS_ERROR_ALERT (TLS_ERROR_CLASS_ALERT + 0xff)
#define TLS_ERROR_EOF (TLS_ERROR_CLASS_INTERNAL + 3)
#define TLS_ERROR_STATEMENT_RETRY (TLS_ERROR_CLASS_INTERNAL + 4)
#define TLS_ERROR_ASYNC_OPERATION (TLS_ERROR_CLASS_INTERNAL + 5)

/* ------------------------------------------------------------------ */
/* basic types                                                          */
/* ------------------------------------------------------------------ */

/* Borrowed byte range (like ptls_iovec_t). */
typedef struct CvmTlsVec {
    u8 const* base;
    usize len;
} CvmTlsVec;

/* Growable output buffer (like ptls_buffer_t). */
typedef struct CvmTlsBuf {
    u8* base;
    usize capacity;
    usize off;
    bool is_allocated;
} CvmTlsBuf;

typedef struct CvmTls CvmTls; /* opaque */

/* In QUIC mode a handshake message is not a record: it is a plaintext blob
 * tagged with the encryption level it belongs to, and the caller wraps it in
 * CRYPTO frames. epoch_offsets[k] is the END offset of epoch k-1, so the range
 * for epoch e is [offsets[e], offsets[e+1]). Shared by the client and server
 * emitters so the two cannot drift. */
void cvm_tls_quic_note_emit(CvmTls* tls, CvmTlsBuf* buf, usize start);

/* Fire the caller's traffic-key hook for one direction and level. No-op when
 * the caller is not QUIC. Returns 0 or an alert to send. */
int cvm_tls_notify_traffic_key(CvmTls* tls, bool is_enc, u32 epoch, void const* secret);

void cvm_tls_buf_init(CvmTlsBuf* buf, u8* small, usize small_capacity);
int cvm_tls_buf_reserve(CvmTlsBuf* buf, usize delta);
int cvm_tls_buf_pushv(CvmTlsBuf* buf, void const* src, usize len);
int cvm_tls_buf_push(CvmTlsBuf* buf, u8 b);
void cvm_tls_buf_dispose(CvmTlsBuf* buf);

/* ------------------------------------------------------------------ */
/* crypto algorithm types                                               */
/* ------------------------------------------------------------------ */

/* AEAD context. Allocated by the backend; layout opaque to the core. */
typedef struct CvmTlsAead CvmTlsAead;

typedef struct CvmTlsAeadAlgo {
    char const* name;
    usize key_size;
    usize iv_size;
    usize tag_size;
    /* Backend: allocate and initialize a context. Returns NULL on failure. */
    CvmTlsAead* (*setup)(struct CvmTlsAeadAlgo const* algo, bool is_enc,
                         void const* key, void const* iv);
} CvmTlsAeadAlgo;

struct CvmTlsAead {
    CvmTlsAeadAlgo const* algo;
    void (*dispose)(CvmTlsAead* ctx);
    void (*do_encrypt)(CvmTlsAead* ctx, u8* output, u8 const* input, usize inlen,
                       u64 seq, void const* aad, usize aadlen);
    usize (*do_decrypt)(CvmTlsAead* ctx, u8* output, u8 const* input, usize inlen,
                        u64 seq, void const* aad, usize aadlen);
};

/* Hash context. */
typedef struct CvmTlsHash CvmTlsHash;

typedef enum {
    TLS_HASH_FINAL_FREE = 0,
    TLS_HASH_FINAL_RESET = 1,
    TLS_HASH_FINAL_SNAPSHOT = 2,
} CvmTlsHashFinalMode;

typedef struct CvmTlsHashAlgo {
    char const* name;
    usize block_size;
    usize digest_size;
    CvmTlsHash* (*create)(void);
} CvmTlsHashAlgo;

struct CvmTlsHash {
    CvmTlsHashAlgo const* algo;
    void (*update)(CvmTlsHash* ctx, void const* src, usize len);
    void (*final)(CvmTlsHash* ctx, void* digest, CvmTlsHashFinalMode mode);
    CvmTlsHash* (*clone)(CvmTlsHash const* src);
};

/* Key exchange (X25519, P-256, P-384). */
typedef struct CvmTlsKeyexCtx CvmTlsKeyexCtx;

typedef struct CvmTlsKeyexAlgo {
    char const* name;
    u16 id; /* TLS group ID */
    usize shared_secret_size;

    /* Create an exchange context; generates a keypair. */
    int (*create)(CvmTlsKeyexCtx** ctx);
    /* Derive shared secret from peer public key. Consumes and frees ctx. */
    int (*exchange)(CvmTlsKeyexCtx* ctx, CvmTlsVec* secret, CvmTlsVec pubkey);
    /* On server: derive public key from a raw private key. */
    int (*on_exchange)(CvmTlsKeyexCtx** ctx, int release, CvmTlsVec* secret,
                       CvmTlsVec peerkey);
} CvmTlsKeyexAlgo;

struct CvmTlsKeyexCtx {
    CvmTlsKeyexAlgo const* algo;
    void (*dispose)(CvmTlsKeyexCtx* ctx);
    u8 pubkey[64]; /* our ephemeral public key (uncompressed point or raw) */
    usize pubkey_len;
};

/* Cipher suite = AEAD + hash + ID. */
typedef struct CvmTlsCipherSuite {
    u16 id;
    CvmTlsAeadAlgo const* aead;
    CvmTlsHashAlgo const* hash;
    char const* name;
} CvmTlsCipherSuite;

/* ------------------------------------------------------------------ */
/* HKDF (exposed for the key schedule)                                  */
/* ------------------------------------------------------------------ */

int cvm_tls_hkdf_extract(CvmTlsHashAlgo const* hash, void* output, CvmTlsVec salt,
                         CvmTlsVec ikm);
int cvm_tls_hkdf_expand(CvmTlsHashAlgo const* hash, void* output, usize outlen,
                        CvmTlsVec prk, CvmTlsVec info);
int cvm_tls_hkdf_expand_label(CvmTlsHashAlgo const* hash, void* output, usize outlen,
                              CvmTlsVec secret, char const* label,
                              CvmTlsVec hash_value);

/* ------------------------------------------------------------------ */
/* connection state                                                     */
/* ------------------------------------------------------------------ */

typedef struct CvmTls CvmTls; /* opaque */

typedef enum {
    TLS_STATE_CLIENT_HANDSHAKE_START = 0,
    TLS_STATE_CLIENT_EXPECT_SERVER_HELLO,
    TLS_STATE_CLIENT_EXPECT_SECOND_SERVER_HELLO,
    TLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
    TLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE,
    TLS_STATE_CLIENT_EXPECT_CERTIFICATE,
    TLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY,
    TLS_STATE_CLIENT_EXPECT_FINISHED,
    TLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
    TLS_STATE_SERVER_EXPECT_SECOND_CLIENT_HELLO,
    TLS_STATE_SERVER_GENERATING_CERTIFICATE_VERIFY,
    TLS_STATE_SERVER_EXPECT_END_OF_EARLY_DATA,
    TLS_STATE_SERVER_EXPECT_FINISHED,
    TLS_STATE_POST_HANDSHAKE_MIN,
    TLS_STATE_CLIENT_POST_HANDSHAKE = TLS_STATE_POST_HANDSHAKE_MIN,
    TLS_STATE_SERVER_POST_HANDSHAKE,
} CvmTlsState;

/* ------------------------------------------------------------------ */
/* application-facing callbacks                                         */
/* ------------------------------------------------------------------ */

/* Verify a certificate chain. Client side. */
typedef struct CvmTlsVerifyCert {
    int (*cb)(struct CvmTlsVerifyCert* self, CvmTls* tls, char const* server_name,
              int (**verify_sign)(void* verify_ctx, u16 algo, CvmTlsVec data,
                                  CvmTlsVec sign),
              void** verify_data, CvmTlsVec* certs, usize num_certs);
    u16 const* algos; /* supported signature algorithms, UINT16_MAX terminated */
} CvmTlsVerifyCert;

/* Sign the CertificateVerify. Server side. */
typedef struct CvmTlsSignCert {
    int (*cb)(struct CvmTlsSignCert* self, CvmTls* tls, u16* selected_algorithm,
              CvmTlsBuf* output, CvmTlsVec input, u16 const* algorithms,
              usize num_algorithms);
    u16 const* algos;
} CvmTlsSignCert;

/* Certificate (raw DER) holder. */
typedef struct CvmTlsCert {
    CvmTlsVec der;
} CvmTlsCert;

/* Get current time in milliseconds. */
typedef struct CvmTlsGetTime {
    u64 (*cb)(struct CvmTlsGetTime* self);
} CvmTlsGetTime;

/* Generate random bytes. */
typedef struct CvmTlsRandomBytes {
    void (*cb)(struct CvmTlsRandomBytes* self, void* buf, usize len);
} CvmTlsRandomBytes;

/* Ticket lifetime / age. */
typedef struct CvmTlsTicket {
    u32 lifetime;
    u32 age_add;
    CvmTlsVec nonce;
    CvmTlsVec ticket;
    u32 max_early_data_size;
} CvmTlsTicket;

/* Client: called when a NewSessionTicket arrives. */
typedef struct CvmTlsSaveTicket {
    int (*cb)(struct CvmTlsSaveTicket* self, CvmTls* tls, CvmTlsTicket const* ticket);
} CvmTlsSaveTicket;

/* ------------------------------------------------------------------ */
/* context                                                              */
/* ------------------------------------------------------------------ */

/*
 * Traffic key callback (QUIC).
 *
 * Called once per direction per encryption level, at the moment the secret
 * becomes available — not after the handshake, because QUIC needs the
 * handshake keys to read Handshake packets long before the handshake ends.
 *
 * The callback receives the *secret*, not a derived key/iv: QUIC derives
 * packet protection keys, IV and header-protection key itself with its own
 * HKDF labels (RFC 9001 §5.1), which are not the TLS record labels.
 *
 * epoch follows TLS 1.3 / QUIC numbering: 0 initial, 1 0-RTT, 2 handshake,
 * 3 1-RTT. Epoch 0 never fires — QUIC derives the initial secrets from the
 * connection ID before TLS is involved.
 */
typedef struct CvmTlsTrafficKey {
    int (*cb)(struct CvmTlsTrafficKey* self, CvmTls* tls, bool is_enc, u32 epoch,
              u8 const* secret, usize secret_len);
} CvmTlsTrafficKey;

typedef struct CvmTlsContext {
    CvmTlsCipherSuite const* const* cipher_suites; /* NULL-terminated */
    CvmTlsKeyexAlgo const** key_exchanges;         /* NULL-terminated */

    struct {
        CvmTlsVerifyCert* verify_certificate;
        CvmTlsSignCert* sign_certificate;
        CvmTlsGetTime* get_time;
        CvmTlsRandomBytes* random_bytes;
        CvmTlsSaveTicket* save_ticket;
        /* QUIC only: keys are handed out here instead of being installed. */
        CvmTlsTrafficKey* update_traffic_key;
        /* server */
        CvmTlsCert* certificates; /* NULL-terminated array */
        u32 ticket_lifetime;      /* seconds; 0 = no tickets */
    };

    bool require_dhe_on_psk;
    bool encrypt_then_sig; /* for CSM attacks */
    bool send_change_cipher_spec;
} CvmTlsContext;

/* ------------------------------------------------------------------ */
/* handshake properties                                                 */
/* ------------------------------------------------------------------ */

typedef struct CvmTlsHandshakeProps {
    /* client */
    char const* server_name;         /* SNI */
    CvmTlsVec* negotiated_protocols; /* ALPN */
    usize negotiated_protocol_count;

    /* client: session resumption */
    struct {
        /* Find a session ticket for the given server name. */
        bool (*find)(void* ctx, char const* server_name, CvmTlsVec* psk,
                     CvmTlsCipherSuite const** suite, u32* age_add);
        /* Called when the handshake completes. */
        void (*complete)(void* ctx, CvmTlsVec session_id);
        void* userdata;
    } resumption;

    /* client: 0-RTT early data */
    CvmTlsVec early_data;
    bool max_early_data_size_required;

    /* server */
    bool enforce_psk_identity_match;

    /* misc */
    char const* client_timeout;
} CvmTlsHandshakeProps;

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

/* Fill a context with cvmcrypt's own crypto backends (AES-GCM/ChaCha20,
 * SHA-256/384, X25519/P-256) and no certificates or callbacks. Defined in
 * crypto_cvm.c. */
void cvm_tls_context_defaults(CvmTlsContext* ctx);

/* Lifecycle. */
CvmTls* cvm_tls_new(CvmTlsContext const* ctx, bool is_server, char const* server_name);
void cvm_tls_free(CvmTls* tls);

/* Handshake. Feed input bytes; get output bytes to send.
 * Returns 0 on success, TLS_ERROR_IN_PROGRESS if more input needed,
 * or a negative error code. */
int cvm_tls_handshake(CvmTls* tls, CvmTlsBuf* sendbuf, void const* input, usize* inlen,
                      CvmTlsHandshakeProps* props);

/* Send application data. */
int cvm_tls_send(CvmTls* tls, CvmTlsBuf* sendbuf, void const* input, usize inlen);

/* Receive application data. Decrypts into decryptbuf.
 * Returns number of bytes consumed from input (via *inlen). */
int cvm_tls_receive(CvmTls* tls, CvmTlsBuf* decryptbuf, void const* input,
                    usize* inlen);

/* Send an alert and close. */
int cvm_tls_send_alert(CvmTls* tls, CvmTlsBuf* sendbuf, u8 level, u8 description);

/*
 * QUIC transport mode.
 *
 * The local transport parameters must be set before the handshake reaches
 * ClientHello; ngtcp2 encodes them and hands them over through
 * ngtcp2_crypto_set_local_transport_params(). The peer's arrive in
 * EncryptedExtensions (extension 0x39) and are readable afterwards with
 * cvm_tls_quic_remote_transport_params().
 *
 * Both are opaque blobs to this layer: the contents are ngtcp2's business.
 */
int cvm_tls_quic_set_local_transport_params(CvmTls* tls, u8 const* data, usize len);
CvmTlsVec cvm_tls_quic_remote_transport_params(CvmTls const* tls);

/* ALPN protocols to offer. Must be set before the handshake starts; QUIC
 * requires at least one or the server aborts. The array is referenced, not
 * copied, so it must outlive the session. */
void cvm_tls_set_alpn(CvmTls* tls, CvmTlsVec const* alpns, usize nalpn);

/* True once the session has run in QUIC mode (no record layer). */
bool cvm_tls_is_quic(CvmTls const* tls);

/*
 * An opaque pointer owned by the embedder. Nothing in this library reads it.
 * A QUIC backend stores its connection reference here, because the traffic
 * key callback is handed the CvmTls and nothing else.
 */
void cvm_tls_set_app_data(CvmTls* tls, void* data);
void* cvm_tls_get_app_data(CvmTls const* tls);

/* QUIC transport mode: get/set handshake messages without record layer. */
int cvm_tls_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, usize epoch_offsets[5],
                           usize in_epoch, void const* input, usize inlen,
                           CvmTlsHandshakeProps* props);

/*
 * Highest encryption level whose receive keys are installed: 0 before any,
 * 2 after ServerHello, 3 after Finished. QUIC uses this to decide which
 * level the next CRYPTO frame belongs to.
 */
u32 cvm_tls_get_read_epoch(CvmTls const* tls);

/* Accessors. */
bool cvm_tls_is_server(CvmTls const* tls);
u16 cvm_tls_get_protocol_version(CvmTls const* tls);
char const* cvm_tls_get_server_name(CvmTls const* tls);
CvmTlsCipherSuite const* cvm_tls_get_cipher_suite(CvmTls const* tls);

#ifdef __cplusplus
}
#endif

#endif /* CVMCRYPT_TLS_H */
