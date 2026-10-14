/*
 * src/tls/server.c
 *
 * TLS 1.3 server handshake state machine (RFC 8446).
 * Drives: receive ClientHello → send ServerHello + EE + Cert +
 *         CertificateVerify + Finished → receive client Finished.
 */

#include "tls/tls_conn.h"
#include "tls/handshake.h"
#include "tls/keyschedule.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* helper: emit a handshake record                                      */
/* ------------------------------------------------------------------ */

/* Write a record header + handshake message (unencrypted). */
static int push_handshake_record(CvmTlsBuf* sendbuf, CvmTlsVec message) {
    int ret;
    usize rec_start = sendbuf->off;
    if ((ret = cvm_tls_buf_push(sendbuf, TLS_CONTENT_TYPE_HANDSHAKE)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_pushv(sendbuf, message.base, message.len)) != 0)
        return ret;
    usize body_len = sendbuf->off - rec_start - 5;
    sendbuf->base[rec_start + 3] = (u8)(body_len >> 8);
    sendbuf->base[rec_start + 4] = (u8)body_len;
    return 0;
}

/* Write a handshake message as an encrypted record. */
static int push_encrypted_message(CvmTls* tls, CvmTlsBuf* sendbuf, u8* msg,
                                  usize msg_len) {
    /* Feed into transcript first. */
    cvm_tls_ks_update_hash(&tls->ks, msg, msg_len);

    /* Encrypt as a single record. */
    int ret;
    usize rec_start = sendbuf->off;
    if ((ret = cvm_tls_buf_push(sendbuf, TLS_CONTENT_TYPE_HANDSHAKE)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(sendbuf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_pushv(sendbuf, msg, msg_len)) != 0)
        return ret;

    if (tls->enc.aead != NULL) {
        ret = cvm_tls_encrypt_record(sendbuf, rec_start, &tls->enc);
    } else {
        usize body_len = sendbuf->off - rec_start - 5;
        sendbuf->base[rec_start + 3] = (u8)(body_len >> 8);
        sendbuf->base[rec_start + 4] = (u8)body_len;
        ret = 0;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* server: process ClientHello                                          */
/* ------------------------------------------------------------------ */

static int server_handle_client_hello(CvmTls* tls, CvmTlsBuf* sendbuf,
                                      CvmTlsVec message) {
    int ret;
    CvmTlsClientHello ch;

    ret =
        cvm_tls_decode_client_hello(&ch, message.base + 4, message.base + message.len);
    if (ret != 0)
        return ret;

    /* Select cipher suite: first match in our list. */
    tls->suite = NULL;
    for (usize i = 0; tls->ctx->cipher_suites[i] != NULL && tls->suite == NULL; i++) {
        for (usize j = 0; j < ch.num_cipher_suites; j++) {
            if (tls->ctx->cipher_suites[i]->id == ch.cipher_suites[j]) {
                tls->suite = tls->ctx->cipher_suites[i];
                break;
            }
        }
    }
    if (tls->suite == NULL)
        return TLS_ALERT_HANDSHAKE_FAILURE;

    /* Generate server random. */
    tls->ctx->random_bytes->cb(tls->ctx->random_bytes, tls->server_random,
                               sizeof(tls->server_random));

    /* Echo legacy session ID. */
    usize sid_len = ch.legacy_session_id.len;
    if (sid_len > 32)
        sid_len = 32;
    memcpy(tls->legacy_session_id, ch.legacy_session_id.base, sid_len);
    tls->legacy_session_id_len = sid_len;

    /* Build ServerHello. */
    CvmTlsBuf sh_buf;
    cvm_tls_buf_init(&sh_buf, NULL, 0);
    CvmTlsKeyexAlgo const* keyex = tls->ctx->key_exchanges[0];
    /* Server key_share pubkey: TODO get from keyex exchange (t43). */
    u8 server_pubkey[32];
    memset(server_pubkey, 0x33, 32); /* placeholder until crypto callbacks */

    ret = cvm_tls_encode_server_hello(
        &sh_buf, tls->suite, tls->server_random,
        (CvmTlsVec){tls->legacy_session_id, tls->legacy_session_id_len}, keyex,
        (CvmTlsVec){server_pubkey, 32});
    if (ret != 0)
        goto fail;

    /* Send ServerHello (plaintext). */
    ret = push_handshake_record(sendbuf, (CvmTlsVec){sh_buf.base, sh_buf.off});
    if (ret != 0)
        goto fail;

    /* Init key schedule and feed transcript: ClientHello + ServerHello. */
    cvm_tls_ks_init(&tls->ks, tls->suite);
    cvm_tls_ks_update_hash(&tls->ks, message.base, message.len);
    cvm_tls_ks_update_hash(&tls->ks, sh_buf.base, sh_buf.off);

    /* Advance to handshake secret. */
    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0}); /* early */
    if (ret != 0)
        goto fail;
    ret = cvm_tls_ks_extract(&tls->ks,
                             (CvmTlsVec){NULL, 0}); /* handshake (TODO: ECDHE) */
    if (ret != 0)
        goto fail;

    /* Derive handshake traffic secrets. */
    u8 server_hs_secret[TLS_MAX_DIGEST_SIZE];
    u8 client_hs_secret[TLS_MAX_DIGEST_SIZE];
    ret = cvm_tls_ks_derive_secret(&tls->ks, server_hs_secret, "s hs traffic");
    if (ret != 0)
        goto fail;
    ret = cvm_tls_ks_derive_secret(&tls->ks, client_hs_secret, "c hs traffic");
    if (ret != 0)
        goto fail;
    memcpy(tls->server_hs_secret, server_hs_secret, TLS_MAX_DIGEST_SIZE);
    memcpy(tls->client_hs_secret, client_hs_secret, TLS_MAX_DIGEST_SIZE);

    /* Set up record protection. */
    {
        CvmTlsAeadAlgo const* aead = tls->suite->aead;
        u8 key[32], iv[TLS_MAX_IV_SIZE];

        ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, server_hs_secret);
        if (ret != 0)
            goto fail;
        tls->enc.aead = aead->setup(aead, true, key, iv);
        tls->enc.seq = 0;
        tls->enc.label = "s hs traffic";
        if (tls->enc.aead == NULL) {
            ret = TLS_ERROR_LIBRARY;
            goto fail;
        }

        ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, client_hs_secret);
        if (ret != 0)
            goto fail;
        tls->dec.aead = aead->setup(aead, false, key, iv);
        tls->dec.seq = 0;
        tls->dec.label = "c hs traffic";
        if (tls->dec.aead == NULL) {
            ret = TLS_ERROR_LIBRARY;
            goto fail;
        }

        memset(key, 0, sizeof(key));
    }

    /* Send EncryptedExtensions (empty). */
    {
        CvmTlsBuf ee_buf;
        cvm_tls_buf_init(&ee_buf, NULL, 0);
        ret = cvm_tls_encode_encrypted_extensions(&ee_buf, NULL);
        if (ret != 0) {
            cvm_tls_buf_dispose(&ee_buf);
            goto fail;
        }
        ret = push_encrypted_message(tls, sendbuf, ee_buf.base, ee_buf.off);
        cvm_tls_buf_dispose(&ee_buf);
        if (ret != 0)
            goto fail;
    }

    /* Send Certificate. */
    if (tls->ctx->certificates != NULL && tls->ctx->certificates[0].der.base != NULL) {
        /* Count certs. */
        usize num_certs = 0;
        while (tls->ctx->certificates[num_certs].der.base != NULL)
            num_certs++;

        CvmTlsBuf cert_buf;
        cvm_tls_buf_init(&cert_buf, NULL, 0);
        CvmTlsVec* cert_vecs = rt_mem_alloc(sizeof(CvmTlsVec) * num_certs);
        for (usize i = 0; i < num_certs; i++)
            cert_vecs[i] = tls->ctx->certificates[i].der;
        ret = cvm_tls_encode_certificate(&cert_buf, cert_vecs, num_certs);
        rt_mem_free(cert_vecs);
        if (ret != 0) {
            cvm_tls_buf_dispose(&cert_buf);
            goto fail;
        }
        ret = push_encrypted_message(tls, sendbuf, cert_buf.base, cert_buf.off);
        cvm_tls_buf_dispose(&cert_buf);
        if (ret != 0)
            goto fail;
    }

    /* Send CertificateVerify. */
    {
        /* TODO: actually sign (t43 crypto callbacks + t44 signing).
         * For now, send a dummy signature to complete the message flow. */
        u8 transcript_hash[TLS_MAX_DIGEST_SIZE];
        tls->ks.hash_ctx->final(tls->ks.hash_ctx, transcript_hash,
                                TLS_HASH_FINAL_SNAPSHOT);

        u8 sign_input[160];
        usize sign_input_len;
        cvm_tls_build_cert_verify_data(sign_input, sizeof(sign_input), &sign_input_len,
                                       "TLS 1.3, server CertificateVerify",
                                       transcript_hash, 32);

        /* Sign: use dummy for now — real signing in t43. */
        u8 sig[256];
        usize sig_len = 256;
        memset(sig, 0x42, sig_len); /* placeholder */

        CvmTlsBuf cv_buf;
        cvm_tls_buf_init(&cv_buf, NULL, 0);
        ret = cvm_tls_encode_certificate_verify(
            &cv_buf, TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, (CvmTlsVec){sig, sig_len});
        if (ret != 0) {
            cvm_tls_buf_dispose(&cv_buf);
            goto fail;
        }
        ret = push_encrypted_message(tls, sendbuf, cv_buf.base, cv_buf.off);
        cvm_tls_buf_dispose(&cv_buf);
        if (ret != 0)
            goto fail;

        memset(sign_input, 0, sizeof(sign_input));
    }

    /* Send server Finished. */
    {
        u8 verify_data[TLS_MAX_DIGEST_SIZE];
        ret = cvm_tls_ks_calc_verify_data(&tls->ks, verify_data, tls->server_hs_secret);
        if (ret != 0)
            goto fail;

        CvmTlsBuf fin_buf;
        cvm_tls_buf_init(&fin_buf, NULL, 0);
        ret = cvm_tls_encode_finished(
            &fin_buf, (CvmTlsVec){verify_data, tls->suite->hash->digest_size});
        if (ret != 0) {
            cvm_tls_buf_dispose(&fin_buf);
            goto fail;
        }
        ret = push_encrypted_message(tls, sendbuf, fin_buf.base, fin_buf.off);
        cvm_tls_buf_dispose(&fin_buf);
        if (ret != 0)
            goto fail;
        memset(verify_data, 0, sizeof(verify_data));
    }

    tls->state = TLS_STATE_SERVER_EXPECT_FINISHED;
    ret = 0;

fail:
    cvm_tls_buf_dispose(&sh_buf);
    return ret;
}

/* ------------------------------------------------------------------ */
/* server: handle client Finished                                       */
/* ------------------------------------------------------------------ */

static int server_handle_finished(CvmTls* tls, CvmTlsVec message) {
    int ret;

    CvmTlsFinished fin;
    ret = cvm_tls_decode_finished(&fin, message.base + 4, message.base + message.len);
    if (ret != 0)
        return ret;

    /* Verify client's Finished (TODO: proper transcript hash). */
    /* For now: derive application secrets and complete. */
    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0}); /* master */
    if (ret != 0)
        return ret;

    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->server_ap_secret, "s ap traffic");
    if (ret != 0)
        return ret;
    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->client_ap_secret, "c ap traffic");
    if (ret != 0)
        return ret;

    /* Update traffic protection to application secrets. */
    {
        CvmTlsAeadAlgo const* aead = tls->suite->aead;
        u8 key[32], iv[TLS_MAX_IV_SIZE];

        ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, tls->server_ap_secret);
        if (ret != 0)
            return ret;
        tls->enc.aead->dispose(tls->enc.aead);
        tls->enc.aead = aead->setup(aead, true, key, iv);
        tls->enc.seq = 0;
        if (tls->enc.aead == NULL)
            return TLS_ERROR_LIBRARY;

        ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, tls->client_ap_secret);
        if (ret != 0)
            return ret;
        tls->dec.aead->dispose(tls->dec.aead);
        tls->dec.aead = aead->setup(aead, false, key, iv);
        tls->dec.seq = 0;
        if (tls->dec.aead == NULL)
            return TLS_ERROR_LIBRARY;

        memset(key, 0, sizeof(key));
    }

    tls->state = TLS_STATE_SERVER_POST_HANDSHAKE;
    tls->handshake_complete = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/* server: message dispatch                                             */
/* ------------------------------------------------------------------ */

int cvm_tls_server_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, CvmTlsVec message) {
    if (message.len < 4)
        return TLS_ALERT_DECODE_ERROR;
    u8 type = message.base[0];

    switch (tls->state) {
    case TLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
        if (type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
            return server_handle_client_hello(tls, sendbuf, message);
        }
        return TLS_ALERT_UNEXPECTED_MESSAGE;

    case TLS_STATE_SERVER_EXPECT_FINISHED:
        if (type == TLS_HANDSHAKE_TYPE_FINISHED) {
            return server_handle_finished(tls, message);
        }
        return TLS_ALERT_UNEXPECTED_MESSAGE;

    case TLS_STATE_SERVER_POST_HANDSHAKE:
        /* Accept KeyUpdate, NewSessionTicket sending, etc. */
        return 0;

    default:
        return TLS_ALERT_INTERNAL_ERROR;
    }
}
