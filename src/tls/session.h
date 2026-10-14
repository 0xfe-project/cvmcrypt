/*
 * src/tls/session.h
 *
 * TLS 1.3 session resumption types and API.
 */

#ifndef CVMCRYPT_TLS_SESSION_H
#define CVMCRYPT_TLS_SESSION_H

#include "tls/tls.h"
#include "tls/handshake.h"

/* Ticket encryption key (AES-128, server-side). */
typedef struct CvmTlsSessionKey {
    u8 key[16];
} CvmTlsSessionKey;

/* Decrypted ticket data. */
typedef struct CvmTlsSessionData {
    u16 cipher_suite_id;
    u64 creation_time;      /* unix seconds */
    u8 psk[32];             /* resumption secret */
    u8 transcript_hash[32]; /* transcript at issuance */
} CvmTlsSessionData;

/* Initialize a ticket key from raw bytes. */
void cvm_tls_session_key_init(CvmTlsSessionKey* key, u8 const key_bytes[16]);

/* Generate a random ticket key. */
void cvm_tls_session_key_generate(CvmTlsSessionKey* key, CvmTlsRandomBytes* random);

/* Server: send a NewSessionTicket after handshake completes. */
int cvm_tls_server_send_ticket(CvmTls* tls, CvmTlsBuf* sendbuf,
                               CvmTlsSessionKey const* ticket_key);

/* Server: decrypt and validate a client-presented ticket.
 * Returns 0 on success, TLS_ALERT_* on failure. */
int cvm_tls_server_decrypt_ticket(CvmTlsSessionKey const* key, CvmTlsVec ticket,
                                  CvmTlsSessionData* out);

/* Client: handle received NewSessionTicket (stores via callback). */
int cvm_tls_client_handle_ticket(struct CvmTls* tls, CvmTlsNewSessionTicket const* nst);

#endif /* CVMCRYPT_TLS_SESSION_H */
