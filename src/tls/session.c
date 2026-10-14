/*
 * src/tls/session.c
 *
 * TLS 1.3 session resumption (RFC 8446 §4.6.1, §2.2).
 *
 * Server: derive resumption secret, create NewSessionTicket.
 * Client: receive NST, cache via callback, offer PSK on reconnect.
 */

#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "tls/keyschedule.h"
#include "tls/session.h"
#include "aead/gcm.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* ticket format (self-contained, encrypted with server's ticket key)   */
/*                                                                     */
/* plaintext:                                                          */
/*   reserved (4 bytes, version tag)                                    */
/*   cipher_suite_id (2 bytes)                                          */
/*   creation_time (8 bytes, unix ms)                                   */
/*   psk (32 bytes, the resumption secret)                              */
/*   aad_hash (32 bytes, transcript hash at ticket issuance)            */
/* encrypted with AES-128-GCM:                                          */
/*   nonce (12 bytes, random)                                          */
/*   ciphertext + tag                                                  */
/* ------------------------------------------------------------------ */

#define TICKET_PLAINTEXT_SIZE (4 + 2 + 8 + 32 + 32)
#define TICKET_NONCE_SIZE 12
#define TICKET_TAG_SIZE 16
#define TICKET_OVERHEAD (TICKET_NONCE_SIZE + TICKET_TAG_SIZE)
#define TICKET_TOTAL_SIZE (TICKET_PLAINTEXT_SIZE + TICKET_OVERHEAD)

/* ------------------------------------------------------------------ */
/* server: send NewSessionTicket                                        */
/* ------------------------------------------------------------------ */

int cvm_tls_server_send_ticket(CvmTls* tls, CvmTlsBuf* sendbuf,
                               CvmTlsSessionKey const* ticket_key) {
    int ret;
    u8 psk[TLS_MAX_DIGEST_SIZE];
    u8 nonce[TICKET_NONCE_SIZE];

    /* Derive the resumption master secret. */
    ret = cvm_tls_ks_derive_secret(&tls->ks, psk, "res master");
    if (ret != 0)
        return ret;

    /* Generate random nonce for ticket encryption. */
    tls->ctx->random_bytes->cb(tls->ctx->random_bytes, nonce, TICKET_NONCE_SIZE);

    /* Build the ticket plaintext. */
    u8 pt[TICKET_PLAINTEXT_SIZE];
    memset(pt, 0, sizeof(pt));
    /* tag */
    pt[0] = 'C';
    pt[1] = 'V';
    pt[2] = 'M';
    pt[3] = 1;
    /* cipher suite id */
    pt[4] = (u8)(tls->suite->id >> 8);
    pt[5] = (u8)tls->suite->id;
    /* creation time (unix seconds, big-endian) */
    {
        u64 now = tls->ctx->get_time->cb(tls->ctx->get_time) / 1000;
        for (int i = 0; i < 8; i++)
            pt[6 + i] = (u8)(now >> (56 - i * 8));
    }
    /* PSK */
    memcpy(pt + 14, psk, 32);
    /* transcript hash at ticket issuance (for binding) */
    {
        /* Snapshot the current transcript hash. */
        tls->ks.hash_ctx->final(tls->ks.hash_ctx, pt + 46, TLS_HASH_FINAL_SNAPSHOT);
    }

    /* Encrypt the ticket with AES-128-GCM. */
    u8 ct[TICKET_PLAINTEXT_SIZE + TICKET_TAG_SIZE];
    {
        CvmcryptGcm gcm;
        cvmcrypt_gcm_encrypt(&gcm, ticket_key->key, 16, nonce, NULL,
                             0, /* no AAD for simplicity */
                             pt, TICKET_PLAINTEXT_SIZE, ct, ct + TICKET_PLAINTEXT_SIZE);
    }

    /* Build the full ticket blob: nonce || ct || tag. */
    u8 ticket[TICKET_TOTAL_SIZE];
    memcpy(ticket, nonce, TICKET_NONCE_SIZE);
    memcpy(ticket + TICKET_NONCE_SIZE, ct, TICKET_PLAINTEXT_SIZE + TICKET_TAG_SIZE);

    /* Build the NewSessionTicket handshake message. */
    u32 ticket_age_add;
    tls->ctx->random_bytes->cb(tls->ctx->random_bytes, (u8*)&ticket_age_add,
                               sizeof(ticket_age_add));

    CvmTlsBuf nst_buf;
    cvm_tls_buf_init(&nst_buf, NULL, 0);

    /* Handshake header. */
    cvm_tls_buf_push(&nst_buf, TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
    cvm_tls_buf_push(&nst_buf, 0); /* length placeholder (3 bytes) */
    cvm_tls_buf_push(&nst_buf, 0);
    cvm_tls_buf_push(&nst_buf, 0);
    usize hdr_start = 0;

    /* ticket_lifetime (4) — 24 hours. */
    cvm_tls_buf_push(&nst_buf, 0);
    cvm_tls_buf_push(&nst_buf, 0);
    cvm_tls_buf_push(&nst_buf, 0x0E);
    cvm_tls_buf_push(&nst_buf, 0x10); /* 3600 seconds */

    /* ticket_age_add (4). */
    cvm_tls_buf_push(&nst_buf, (u8)(ticket_age_add >> 24));
    cvm_tls_buf_push(&nst_buf, (u8)(ticket_age_add >> 16));
    cvm_tls_buf_push(&nst_buf, (u8)(ticket_age_add >> 8));
    cvm_tls_buf_push(&nst_buf, (u8)ticket_age_add);

    /* ticket_nonce (1 + len). */
    u8 nonce_id = 1;
    cvm_tls_buf_push(&nst_buf, 1); /* nonce length */
    cvm_tls_buf_push(&nst_buf, nonce_id);

    /* ticket (2 + len). */
    cvm_tls_buf_push(&nst_buf, (u8)(TICKET_TOTAL_SIZE >> 8));
    cvm_tls_buf_push(&nst_buf, (u8)TICKET_TOTAL_SIZE);
    cvm_tls_buf_pushv(&nst_buf, ticket, TICKET_TOTAL_SIZE);

    /* extensions (2, empty). */
    cvm_tls_buf_push(&nst_buf, 0);
    cvm_tls_buf_push(&nst_buf, 0);

    /* Fix handshake message length. */
    usize body_len = nst_buf.off - 4;
    nst_buf.base[hdr_start + 1] = (u8)(body_len >> 16);
    nst_buf.base[hdr_start + 2] = (u8)(body_len >> 8);
    nst_buf.base[hdr_start + 3] = (u8)body_len;

    /* Send as encrypted record. */
    ret = cvm_tls_push_encrypted_records(sendbuf, TLS_CONTENT_TYPE_HANDSHAKE,
                                         nst_buf.base, nst_buf.off, &tls->enc);

    cvm_tls_buf_dispose(&nst_buf);
    memset(pt, 0, sizeof(pt));
    memset(psk, 0, sizeof(psk));
    return ret;
}

/* ------------------------------------------------------------------ */
/* server: decrypt and validate a ticket                                */
/* ------------------------------------------------------------------ */

int cvm_tls_server_decrypt_ticket(CvmTlsSessionKey const* key, CvmTlsVec ticket,
                                  CvmTlsSessionData* out) {
    if (ticket.len != TICKET_TOTAL_SIZE)
        return TLS_ALERT_DECODE_ERROR;

    u8 const* nonce = ticket.base;
    u8 const* ct = ticket.base + TICKET_NONCE_SIZE;

    u8 pt[TICKET_PLAINTEXT_SIZE];
    CvmcryptGcm gcm;
    bool ok =
        cvmcrypt_gcm_decrypt(&gcm, key->key, 16, nonce, NULL, 0, ct,
                             TICKET_PLAINTEXT_SIZE, pt, ct + TICKET_PLAINTEXT_SIZE);
    if (!ok)
        return TLS_ALERT_DECRYPT_ERROR;

    /* Validate tag. */
    if (pt[0] != 'C' || pt[1] != 'V' || pt[2] != 'M' || pt[3] != 1)
        return TLS_ALERT_DECRYPT_ERROR;

    out->cipher_suite_id = (u16)(pt[4] << 8 | pt[5]);
    out->creation_time = 0;
    for (int i = 0; i < 8; i++)
        out->creation_time = (out->creation_time << 8) | pt[6 + i];
    memcpy(out->psk, pt + 14, 32);
    memcpy(out->transcript_hash, pt + 46, 32);

    memset(pt, 0, sizeof(pt));
    return 0;
}

/* ------------------------------------------------------------------ */
/* client: handle NewSessionTicket                                      */
/* ------------------------------------------------------------------ */

int cvm_tls_client_handle_ticket(CvmTls* tls, CvmTlsNewSessionTicket const* nst) {
    /* Derive PSK from resumption master secret. */
    u8 resumption_secret[TLS_MAX_DIGEST_SIZE];
    int ret = cvm_tls_ks_derive_secret(&tls->ks, resumption_secret, "res master");
    if (ret != 0)
        return ret;

    /* Call the save_ticket callback if configured. */
    if (tls->ctx->save_ticket != NULL) {
        CvmTlsTicket ticket = {
            .lifetime = nst->ticket_lifetime,
            .age_add = nst->ticket_age_add,
            .nonce = nst->ticket_nonce,
            .ticket = nst->ticket,
            .max_early_data_size = nst->max_early_data_size,
        };
        tls->ctx->save_ticket->cb(tls->ctx->save_ticket, tls, &ticket);
    }

    memset(resumption_secret, 0, sizeof(resumption_secret));
    return 0;
}

/* ------------------------------------------------------------------ */
/* ticket key management                                                */
/* ------------------------------------------------------------------ */

void cvm_tls_session_key_init(CvmTlsSessionKey* key, u8 const key_bytes[16]) {
    memcpy(key->key, key_bytes, 16);
}

void cvm_tls_session_key_generate(CvmTlsSessionKey* key, CvmTlsRandomBytes* random) {
    random->cb(random, key->key, 16);
}
