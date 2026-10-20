/*
 * src/tls/server.c
 *
 * TLS 1.3 server handshake state machine (RFC 8446).
 * Drives: receive ClientHello → send ServerHello + EE + Cert +
 *         CertificateVerify + Finished → receive client Finished.
 */

#include "tls/tls_conn.h"

#ifdef TLS_TRACE
#include <stdio.h>
#define TRACE(...) fprintf(stderr, "[srv] " __VA_ARGS__), fprintf(stderr, "\n")
#else
#define TRACE(...) ((void)0)
#endif
#include "tls/handshake.h"
#include "tls/keyschedule.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* helper: emit a handshake record                                      */
/* ------------------------------------------------------------------ */

/* Write a record header + handshake message (unencrypted). In QUIC mode the
 * message is written bare at the Initial level instead — ServerHello is the
 * only thing this function ever carries, so the level is fixed. */
static int push_handshake_record(CvmTls* tls, CvmTlsBuf* sendbuf, CvmTlsVec message) {
    int ret;
    usize rec_start = sendbuf->off;

    if (tls->quic) {
        if ((ret = cvm_tls_buf_pushv(sendbuf, message.base, message.len)) != 0)
            return ret;
        tls->write_epoch = 0;
        cvm_tls_quic_note_emit(tls, sendbuf, rec_start);
        return 0;
    }
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

    int ret;
    usize rec_start = sendbuf->off;

    /* QUIC: no record, no AEAD here — the message is written bare at the
     * Handshake level and ngtcp2 does the packet protection. */
    if (tls->quic) {
        if ((ret = cvm_tls_buf_pushv(sendbuf, msg, msg_len)) != 0)
            return ret;
        tls->write_epoch = 2;
        cvm_tls_quic_note_emit(tls, sendbuf, rec_start);
        return 0;
    }
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

    /* ALPN: pick the first protocol the client offered that we also speak.
     * The list is the same shape the client encoder writes — u16 total length,
     * then vec8 names — so it is walked the same way. */
    tls->negotiated_alpn = (CvmTlsVec){NULL, 0};
    if (tls->alpns != NULL && ch.alpn_list.base != NULL) {
        u8 const* p = ch.alpn_list.base;
        u8 const* end = p + ch.alpn_list.len;
        if (end - p >= 2) {
            u16 list_len = (u16)(((u16)p[0] << 8) | p[1]);
            p += 2;
            if ((usize)(end - p) > list_len)
                end = p + list_len;
            while (p < end) {
                u8 nlen = *p++;
                if (p + nlen > end)
                    break;
                /* Bounded by nalpn, not by a NULL terminator: the caller's
                 * array is a count, not a sentinel list. */
                for (usize i = 0; i < tls->nalpn; i++) {
                    if (tls->alpns[i].len == nlen &&
                        memcmp(tls->alpns[i].base, p, nlen) == 0) {
                        tls->negotiated_alpn = (CvmTlsVec){p, nlen};
                        break;
                    }
                }
                if (tls->negotiated_alpn.base != NULL)
                    break;
                p += nlen;
            }
        }
        /* A QUIC client and server must agree on a protocol; none in common
         * means no_application_protocol. */
        if (tls->quic && tls->negotiated_alpn.base == NULL)
            return TLS_ALERT_NO_APPLICATION_PROTOCOL;
    }

    /* Keep the client's QUIC transport parameters verbatim; they are the QUIC
     * layer's to decode. */
    tls->remote_quic_params_len = 0;
    if (ch.quic_params.len > 0 &&
        ch.quic_params.len <= sizeof(tls->remote_quic_params)) {
        memcpy(tls->remote_quic_params, ch.quic_params.base, ch.quic_params.len);
        tls->remote_quic_params_len = ch.quic_params.len;
    }

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
    /*
     * Pick the group the client offered a key share for. Replying with a
     * group it did not offer gets the handshake rejected.
     */
    CvmTlsKeyexAlgo const* keyex = NULL;
    CvmTlsKeyShareEntry const* peer_share = NULL;
    for (usize j = 0; j < ch.num_key_shares && keyex == NULL; j++) {
        for (usize i = 0; tls->ctx->key_exchanges[i] != NULL; i++) {
            if (tls->ctx->key_exchanges[i]->id == ch.key_shares[j].group) {
                keyex = tls->ctx->key_exchanges[i];
                peer_share = &ch.key_shares[j];
                break;
            }
        }
    }
    TRACE("client offered %zu shares, picked group=%u keyex=%p", ch.num_key_shares,
          peer_share ? (unsigned)peer_share->group : 0, (void*)keyex);
    if (keyex == NULL || peer_share == NULL)
        return TLS_ALERT_HANDSHAKE_FAILURE;

    ret = keyex->create(&tls->keyex_ctx);
    TRACE("keyex create ret=%d pubkey_len=%zu", ret,
          tls->keyex_ctx ? tls->keyex_ctx->pubkey_len : 0);
    if (ret != 0)
        goto fail;
    tls->keyex_pubkey_len = tls->keyex_ctx->pubkey_len;
    if (tls->keyex_pubkey_len > sizeof(tls->keyex_pubkey))
        tls->keyex_pubkey_len = sizeof(tls->keyex_pubkey);
    memcpy(tls->keyex_pubkey, tls->keyex_ctx->pubkey, tls->keyex_pubkey_len);

    ret = cvm_tls_encode_server_hello(
        &sh_buf, tls->suite, tls->server_random,
        (CvmTlsVec){tls->legacy_session_id, tls->legacy_session_id_len}, keyex,
        (CvmTlsVec){tls->keyex_pubkey, tls->keyex_pubkey_len});
    TRACE("encode ServerHello ret=%d len=%zu", ret, sh_buf.off);
    if (ret != 0)
        goto fail;

    /* Send ServerHello (plaintext). */
    ret = push_handshake_record(tls, sendbuf, (CvmTlsVec){sh_buf.base, sh_buf.off});
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
    CvmTlsVec shared = {NULL, 0};
    ret = keyex->exchange(tls->keyex_ctx, &shared, peer_share->key_exchange);
    tls->keyex_ctx = NULL; /* exchange consumes it */
    TRACE("exchange ret=%d shared_len=%zu", ret, shared.len);
    if (ret != 0)
        goto fail;
    ret = cvm_tls_ks_extract(&tls->ks, shared);
    TRACE("ks extract (handshake) ret=%d", ret);
    if (shared.base != NULL) {
        memset((void*)shared.base, 0, shared.len);
        rt_mem_free((void*)shared.base);
    }
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
        ret = cvm_tls_encode_encrypted_extensions(
            &ee_buf, tls->negotiated_alpn.base != NULL ? &tls->negotiated_alpn : NULL,
            (CvmTlsVec){tls->local_quic_params, tls->local_quic_params_len});
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
        /* The signature is the embedder's: cvmcrypt never holds a private
         * key. The callback picks the scheme and writes the signature. */
        u8 transcript_hash[TLS_MAX_DIGEST_SIZE];
        tls->ks.hash_ctx->final(tls->ks.hash_ctx, transcript_hash,
                                TLS_HASH_FINAL_SNAPSHOT);

        u8 sign_input[160];
        usize sign_input_len;
        cvm_tls_build_cert_verify_data(sign_input, sizeof(sign_input), &sign_input_len,
                                       "TLS 1.3, server CertificateVerify",
                                       transcript_hash, 32);

        if (tls->ctx->sign_certificate == NULL ||
            tls->ctx->sign_certificate->cb == NULL) {
            TRACE("no sign_certificate callback");
            ret = TLS_ALERT_INTERNAL_ERROR;
            goto fail;
        }

        CvmTlsBuf sig_buf;
        cvm_tls_buf_init(&sig_buf, NULL, 0);
        u16 sig_alg = 0;
        ret = tls->ctx->sign_certificate->cb(
            tls->ctx->sign_certificate, tls, &sig_alg, &sig_buf,
            (CvmTlsVec){sign_input, sign_input_len}, NULL, 0);
        TRACE("sign cb ret=%d alg=%04x sig_len=%zu", ret, (unsigned)sig_alg,
              sig_buf.off);
        if (ret != 0) {
            cvm_tls_buf_dispose(&sig_buf);
            goto fail;
        }

        CvmTlsBuf cv_buf;
        cvm_tls_buf_init(&cv_buf, NULL, 0);
        ret = cvm_tls_encode_certificate_verify(&cv_buf, sig_alg,
                                                (CvmTlsVec){sig_buf.base, sig_buf.off});
        cvm_tls_buf_dispose(&sig_buf);
        TRACE("encode CV ret=%d len=%zu", ret, cv_buf.off);
        if (ret != 0) {
            cvm_tls_buf_dispose(&cv_buf);
            goto fail;
        }
        ret = push_encrypted_message(tls, sendbuf, cv_buf.base, cv_buf.off);
        TRACE("push CV ret=%d", ret);
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
        TRACE("push Finished ret=%d", ret);
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

    /* Verify the client's Finished against the transcript as it stands now,
     * which excludes this message. */
    {
        usize const dlen = tls->suite->hash->digest_size;
        u8 expected[TLS_MAX_DIGEST_SIZE];
        ret = cvm_tls_ks_calc_verify_data(&tls->ks, expected, tls->client_hs_secret);
        if (ret != 0)
            return ret;
        bool const ok = fin.verify_data.len == dlen &&
                        cvmcrypt_ct_eq(fin.verify_data.base, expected, dlen);
        memset(expected, 0, sizeof(expected));
        TRACE("client Finished verify ok=%d", (int)ok);
        if (!ok)
            return TLS_ALERT_DECRYPT_ERROR;
    }

    /*
     * The application secrets are derived from the transcript through the
     * server's Finished — the client's Finished is NOT in it (RFC 8446
     * §7.1). Hashing it first derives keys that no peer will ever use, and
     * the failure surfaces one step later as a bad record MAC on the first
     * application data record.
     */
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

    /* Only now does the client's Finished join the transcript. */
    cvm_tls_ks_update_hash(&tls->ks, message.base, message.len);

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
