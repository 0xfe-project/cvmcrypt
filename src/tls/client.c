#ifdef TLS_DEBUG
#include <stdio.h>
#endif
/*
 * src/tls/client.c
 *
 * TLS 1.3 client handshake state machine (RFC 8446).
 * Drives: ClientHello → ServerHello → EE → Certificate →
 *         CertificateVerify → Finished → application data.
 */

#include "tls/tls_conn.h"

#include "asn1/der.h"
#include "base/mem.h"
#include "base/secure.h"
#include "cvmcrypt/hash.h"
#include "tls/handshake.h"
#include "x509/x509.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* lifecycle                                                            */
/* ------------------------------------------------------------------ */

CvmTls* cvm_tls_new(CvmTlsContext const* ctx, bool is_server, char const* server_name) {
    CvmTls* tls = rt_mem_alloc(sizeof(*tls));
    if (tls == NULL)
        return NULL;
    memset(tls, 0, sizeof(*tls));
    tls->ctx = ctx;
    tls->is_server = is_server;
    tls->server_name = server_name;
    tls->state = is_server ? TLS_STATE_SERVER_EXPECT_CLIENT_HELLO
                           : TLS_STATE_CLIENT_HANDSHAKE_START;
    return tls;
}

void cvm_tls_free(CvmTls* tls) {
    if (tls == NULL)
        return;
    cvm_tls_ks_free(&tls->ks);
    if (tls->keyex_ctx != NULL) {
        tls->keyex_ctx->dispose(tls->keyex_ctx);
        tls->keyex_ctx = NULL;
    }
    if (tls->enc.aead != NULL) {
        tls->enc.aead->dispose(tls->enc.aead);
        tls->enc.aead = NULL;
    }
    if (tls->dec.aead != NULL) {
        tls->dec.aead->dispose(tls->dec.aead);
        tls->dec.aead = NULL;
    }
    cvm_tls_buf_dispose(&tls->recvbuf_rec);
    cvm_tls_buf_dispose(&tls->recvbuf_msg);
    cvm_tls_buf_dispose(&tls->sendbuf_early);
    cvmcrypt_secure_free(tls, sizeof(*tls));
}

/* ------------------------------------------------------------------ */
/* helper: emit a handshake message                                    */
/* ------------------------------------------------------------------ */

static int emit_handshake(CvmTls* tls, CvmTlsBuf* sendbuf, u8 const* msg, usize len) {
    usize const start = sendbuf->off;
    int ret;

    if (tls->quic) {
        if ((ret = cvm_tls_buf_pushv(sendbuf, msg, len)) != 0)
            return ret;
        cvm_tls_quic_note_emit(tls, sendbuf, start);
        return 0;
    }

    return cvm_tls_push_encrypted_records(sendbuf, TLS_CONTENT_TYPE_HANDSHAKE, msg, len,
                                          &tls->enc);
}

/* ------------------------------------------------------------------ */
/* helper: derive traffic keys and set up protection                   */
/* ------------------------------------------------------------------ */

static int setup_traffic_protection(CvmTls* tls, bool is_enc, u32 epoch,
                                    void const* secret, char const* label) {
    CvmTlsAeadAlgo const* aead = tls->suite->aead;
    u8 key[32]; /* max AES-256 */
    u8 iv[TLS_MAX_IV_SIZE];
    CvmTlsTrafficProt* tp = is_enc ? &tls->enc : &tls->dec;

    int ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, secret);
    if (ret != 0)
        return ret;

#ifdef TLS_DEBUG
    printf("[debug] traffic key (%s): ", label);
    for (int i = 0; i < (int)aead->key_size; i++)
        printf("%02x", ((u8*)key)[i]);
    printf("\n[debug] traffic iv  (%s): ", label);
    for (int i = 0; i < (int)aead->iv_size; i++)
        printf("%02x", ((u8*)iv)[i]);
    printf("\n");
#endif
    tp->aead = aead->setup(aead, is_enc, key, iv);
    tp->seq = 0;
    tp->label = label;

    memset(key, 0, sizeof(key));
    if (tp->aead == NULL)
        return TLS_ERROR_LIBRARY;

    /*
     * QUIC hook. Fires for every direction and level the moment the secret
     * exists, which is what ngtcp2 needs: it derives packet protection from
     * the secret itself (RFC 9001 §5.1 labels, not the record labels), so
     * the key/iv computed above are for the record layer and go unused when
     * the caller is QUIC.
     */
    {
        int const cbret = cvm_tls_notify_traffic_key(tls, is_enc, epoch, secret);
        if (cbret != 0)
            return cbret;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* client: send ClientHello                                             */
/* ------------------------------------------------------------------ */

static int client_send_client_hello(CvmTls* tls, CvmTlsBuf* sendbuf) {
    int ret;

    /* Generate client random. */
    tls->ctx->random_bytes->cb(tls->ctx->random_bytes, tls->client_random,
                               sizeof(tls->client_random));

    /* Generate legacy session ID for middlebox compat (32 random bytes). */
    tls->ctx->random_bytes->cb(tls->ctx->random_bytes, tls->legacy_session_id, 32);
    tls->legacy_session_id_len = 32;

    /* Create key exchange context. */
    CvmTlsKeyexAlgo const* keyex = tls->ctx->key_exchanges[0]; /* prefer first */
    ret = keyex->create(&tls->keyex_ctx);
    if (ret != 0)
        return ret;

    /* Get our public key from the keyex context. */
    tls->keyex_pubkey_len = tls->keyex_ctx->pubkey_len;
    if (tls->keyex_pubkey_len > sizeof(tls->keyex_pubkey))
        tls->keyex_pubkey_len = sizeof(tls->keyex_pubkey);
    memcpy(tls->keyex_pubkey, tls->keyex_ctx->pubkey, tls->keyex_pubkey_len);

    /* Record header, unless this is QUIC: there the ClientHello is a
     * plaintext handshake message carried in Initial CRYPTO frames. */
    usize rec_start = sendbuf->off;
    if (!tls->quic) {
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
    }

    /* Encode ClientHello. */
    ret = cvm_tls_encode_client_hello(
        sendbuf, tls->ctx->cipher_suites, tls->client_random,
        (CvmTlsVec){tls->legacy_session_id, 32}, tls->server_name, keyex,
        (CvmTlsVec){tls->keyex_pubkey, tls->keyex_pubkey_len}, NULL, 0,
        tls->quic ? (CvmTlsVec){tls->local_quic_params, tls->local_quic_params_len}
                  : (CvmTlsVec){NULL, 0},
        tls->alpns, tls->nalpn);
    if (ret != 0)
        return ret;

    usize body_start = rec_start + (tls->quic ? 0 : 5);
    usize body_len = sendbuf->off - body_start;

    if (tls->quic) {
        tls->write_epoch = 0;
        cvm_tls_quic_note_emit(tls, sendbuf, rec_start);
    } else {
        sendbuf->base[rec_start + 3] = (u8)(body_len >> 8);
        sendbuf->base[rec_start + 4] = (u8)body_len;
    }

    /* Save the CH handshake message (not the record header) for transcript replay. */
    cvm_tls_buf_dispose(&tls->sendbuf_early);
    cvm_tls_buf_init(&tls->sendbuf_early, NULL, 0);
    if ((ret = cvm_tls_buf_pushv(&tls->sendbuf_early, sendbuf->base + body_start,
                                 body_len)) != 0)
        return ret;

    tls->state = TLS_STATE_CLIENT_EXPECT_SERVER_HELLO;
    return 0;
}

/* ------------------------------------------------------------------ */
/* client: handle ServerHello                                           */
/* ------------------------------------------------------------------ */

static int client_handle_server_hello(CvmTls* tls, CvmTlsBuf* sendbuf,
                                      CvmTlsVec message) {
    int ret;
    (void)sendbuf;

    CvmTlsServerHello sh;
    ret =
        cvm_tls_decode_server_hello(&sh, message.base + 4, message.base + message.len);
    if (ret != 0)
        return ret;

    if (sh.is_hello_retry_request) {
        /* TODO: handle HRR (send second ClientHello with cookie). */
        return TLS_ALERT_UNEXPECTED_MESSAGE;
    }

    /* Verify legacy_session_id matches. */
    if (sh.legacy_session_id.len != tls->legacy_session_id_len ||
        memcmp(sh.legacy_session_id.base, tls->legacy_session_id,
               tls->legacy_session_id_len) != 0) {
        return TLS_ALERT_ILLEGAL_PARAMETER;
    }

    /* Find the negotiated cipher suite. */
    tls->suite = NULL;
    for (usize i = 0; tls->ctx->cipher_suites[i] != NULL; i++) {
        if (tls->ctx->cipher_suites[i]->id == sh.cipher_suite) {
            tls->suite = tls->ctx->cipher_suites[i];
            break;
        }
    }
    if (tls->suite == NULL)
        return TLS_ALERT_HANDSHAKE_FAILURE;

    /* Re-init key schedule with the negotiated suite's hash. */
    cvm_tls_ks_free(&tls->ks);
    cvm_tls_ks_init(&tls->ks, tls->suite);

    /* Replay transcript: ClientHello (from sendbuf_early) + ServerHello. */
#ifdef TLS_DEBUG
    printf("[debug] transcript CH: len=%zu, first=%02x %02x %02x %02x\n",
           tls->sendbuf_early.off, tls->sendbuf_early.base[0],
           tls->sendbuf_early.base[1], tls->sendbuf_early.base[2],
           tls->sendbuf_early.base[3]);
    printf("[debug] transcript SH: len=%zu, first=%02x %02x %02x %02x\n", message.len,
           message.base[0], message.base[1], message.base[2], message.base[3]);
#endif
    cvm_tls_ks_update_hash(&tls->ks, tls->sendbuf_early.base, tls->sendbuf_early.off);
    cvm_tls_ks_update_hash(&tls->ks, message.base, message.len);

    /* Compute ECDHE shared secret from server's key_share. */
    u8 shared_secret[64];
    usize shared_len = 0;
    if (tls->keyex_ctx != NULL && sh.key_share.key_exchange.base != NULL) {
        CvmTlsVec secret_vec = {NULL, 0};
        ret = tls->keyex_ctx->algo->exchange(tls->keyex_ctx, &secret_vec,
                                             sh.key_share.key_exchange);
        if (ret != 0)
            return ret;
        shared_len = secret_vec.len;
        if (shared_len > sizeof(shared_secret))
            shared_len = sizeof(shared_secret);
        memcpy(shared_secret, secret_vec.base, shared_len);
        rt_mem_free((void*)secret_vec.base);
#ifdef TLS_DEBUG
        printf("[debug] ECDHE server_pubkey: ");
        for (int i = 0; i < 8; i++)
            printf("%02x", sh.key_share.key_exchange.base[i]);
        printf("... (len=%zu)\n", sh.key_share.key_exchange.len);
        printf("[debug] ECDHE shared_secret: ");
        for (int i = 0; i < (int)shared_len; i++)
            printf("%02x", shared_secret[i]);
        printf("\n");
#endif
    }

    /* Advance key schedule: early secret → handshake secret. */
    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0});
    if (ret != 0)
        return ret;
    ret = cvm_tls_ks_extract(&tls->ks, shared_len > 0
                                           ? (CvmTlsVec){shared_secret, shared_len}
                                           : (CvmTlsVec){NULL, 0});
    if (ret != 0)
        return ret;

    /* Derive handshake traffic secrets. */
#ifdef TLS_DEBUG
    {
        u8 th[32];
        tls->ks.hash_ctx->final(tls->ks.hash_ctx, th, TLS_HASH_FINAL_SNAPSHOT);
        printf("[debug] transcript_hash: ");
        for (int i = 0; i < 32; i++)
            printf("%02x", th[i]);
        printf("\n");
    }
#endif
    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->server_hs_secret, "s hs traffic");
    if (ret != 0)
        return ret;
    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->client_hs_secret, "c hs traffic");
    if (ret != 0)
        return ret;
    memset(shared_secret, 0, sizeof(shared_secret));

#ifdef TLS_DEBUG
    printf("[debug] server_hs_secret: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", tls->server_hs_secret[i]);
    printf("\n[debug] client_hs_secret: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", tls->client_hs_secret[i]);
    printf("\n");
#endif

    /* Set up record protection. */
    ret =
        setup_traffic_protection(tls, false, 2, tls->server_hs_secret, "s hs traffic");
    if (ret != 0)
        return ret;
    ret = setup_traffic_protection(tls, true, 2, tls->client_hs_secret, "c hs traffic");
    if (ret != 0)
        return ret;

    tls->state = TLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS;
    return 0;
}

/* ------------------------------------------------------------------ */
/* client: verify the server's CertificateVerify                        */
/* ------------------------------------------------------------------ */

/*
 * RFC 8446 §4.4.3. The signature covers
 *
 *     0x20 x 64 || "TLS 1.3, server CertificateVerify" || 0x00 ||
 *     Transcript-Hash(ClientHello..Certificate)
 *
 * and is checked against the leaf certificate's public key with the scheme
 * named in the message. Unsupported schemes fail closed: an unknown algorithm
 * must never mean "accept".
 */
static int verify_certificate_verify(CvmTls* tls, CvmTlsCertVerify const* cv) {
    CvmX509Cert cert;
    u8 transcript[TLS_MAX_DIGEST_SIZE];
    u8 content[256];
    u8 digest[TLS_MAX_DIGEST_SIZE];
    usize content_len = 0;
    usize digest_len = 0;
    CvmcryptMdAlg const* md = NULL;
    int ret = TLS_ALERT_DECRYPT_ERROR;
    bool ok = false;

    if (tls->peer_leaf_cert_len == 0)
        return TLS_ALERT_BAD_CERTIFICATE;
    if (tls->ks.hash_ctx == NULL)
        return TLS_ALERT_INTERNAL_ERROR;

    cvmcrypt_x509_init(&cert);
    if (cvmcrypt_x509_parse(&cert, tls->peer_leaf_cert, tls->peer_leaf_cert_len) !=
        X509_OK) {
        cvmcrypt_x509_free(&cert);
        return TLS_ALERT_BAD_CERTIFICATE;
    }

    /* The transcript must end at Certificate: this branch runs before the
     * CertificateVerify message is hashed. */
    tls->ks.hash_ctx->final(tls->ks.hash_ctx, transcript, TLS_HASH_FINAL_SNAPSHOT);

    if (cvm_tls_build_cert_verify_data(content, sizeof(content), &content_len,
                                       "TLS 1.3, server CertificateVerify", transcript,
                                       tls->suite->hash->digest_size) != 0) {
        cvmcrypt_x509_free(&cert);
        return TLS_ALERT_INTERNAL_ERROR;
    }

    switch (cv->algorithm) {
    case TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
        md = &cvmcrypt_md_sha256;
        break;
    case TLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
    case TLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
        md = &cvmcrypt_md_sha384;
        break;
    case TLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
    case TLS_SIGNATURE_RSA_PKCS1_SHA256:
        md = &cvmcrypt_md_sha256;
        break;
    default:
        /* Unsupported scheme: refuse rather than guess. */
        cvmcrypt_x509_free(&cert);
        return TLS_ALERT_ILLEGAL_PARAMETER;
    }

    digest_len = cvmcrypt_md_digest_size(md);
    if (!cvmcrypt_md_digest(md, content, content_len, digest)) {
        cvmcrypt_x509_free(&cert);
        return TLS_ALERT_INTERNAL_ERROR;
    }

    if (cv->algorithm == TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 ||
        cv->algorithm == TLS_SIGNATURE_ECDSA_SECP384R1_SHA384) {
        /* ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } */
        DerCursor outer = der_cursor_init(cv->signature.base, cv->signature.len);
        DerCursor seq, r, s;
        if (cert.pk_type == X509_PK_EC && der_read_tlv(&outer, 0x30, &seq) == DER_OK &&
            der_read_tlv(&seq, 0x02, &r) == DER_OK &&
            der_read_tlv(&seq, 0x02, &s) == DER_OK) {
            ok = cvmcrypt_ecdsa_verify(&cert.ec_key, digest, digest_len, r.p,
                                       r.remaining, s.p, s.remaining);
        }
    } else {
        CvmRsaHashId const hid =
            (cv->algorithm == TLS_SIGNATURE_RSA_PKCS1_SHA256)
                ? CVMCRYPT_RSA_HASH_SHA256
                : (cv->algorithm == TLS_SIGNATURE_RSA_PSS_RSAE_SHA384
                       ? CVMCRYPT_RSA_HASH_SHA384
                       : CVMCRYPT_RSA_HASH_SHA256);
        if (cert.pk_type == X509_PK_RSA) {
            if (cv->algorithm == TLS_SIGNATURE_RSA_PKCS1_SHA256) {
                ok = cvmcrypt_rsa_verify_pkcs1_v15(&cert.rsa_key, hid, digest,
                                                   digest_len, cv->signature.base,
                                                   cv->signature.len);
            } else {
                ok = cvmcrypt_rsa_verify_pss(&cert.rsa_key, hid, digest, digest_len,
                                             cv->signature.base, cv->signature.len);
            }
        }
    }

    if (ok)
        ret = 0;

    memset(digest, 0, sizeof(digest));
    memset(transcript, 0, sizeof(transcript));
    cvmcrypt_x509_free(&cert);
    return ret;
}

/* ------------------------------------------------------------------ */
/* client: handle each handshake message                                */
/* ------------------------------------------------------------------ */

static int client_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, CvmTlsVec message) {
    if (message.len < 4)
        return TLS_ALERT_DECODE_ERROR;
    u8 type = message.base[0];
    int ret;

    switch (tls->state) {
    case TLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
        if (type == TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
            ret = client_handle_server_hello(tls, sendbuf, message);
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    case TLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
        if (type == TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS) {
            /* Pull out the QUIC transport parameters if present. ALPN is not
             * negotiated by this client. */
            usize plen = 0;
            ret = cvm_tls_decode_encrypted_extensions(
                (CvmTlsVec){message.base + 4, message.len - 4}, tls->remote_quic_params,
                sizeof(tls->remote_quic_params), &plen);
            if (ret == 0) {
                tls->remote_quic_params_len = plen;
                if (tls->quic && plen == 0) {
                    /* A QUIC peer must send them; their absence is fatal. */
                    ret = TLS_ALERT_MISSING_EXTENSION;
                } else {
                    tls->state =
                        TLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE;
                }
            }
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    case TLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE:
    case TLS_STATE_CLIENT_EXPECT_CERTIFICATE:
        if (type == TLS_HANDSHAKE_TYPE_CERTIFICATE) {
            CvmTlsCertMsg cert;
            ret = cvm_tls_decode_certificate(&cert, message.base + 4,
                                             message.base + message.len);
            if (ret == 0) {
                tls->num_certs = cert.num_entries;
                for (usize i = 0; i < cert.num_entries && i < 4; i++)
                    tls->certs[i] = cert.entries[i];

                /* Copy the leaf out of the record buffer before it is freed. */
                tls->peer_leaf_cert_len = 0;
                if (cert.num_entries > 0 &&
                    cert.entries[0].data.len <= sizeof(tls->peer_leaf_cert)) {
                    memcpy(tls->peer_leaf_cert, cert.entries[0].data.base,
                           cert.entries[0].data.len);
                    tls->peer_leaf_cert_len = cert.entries[0].data.len;
                }
                tls->state = TLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY;
            }
        } else if (type == TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST) {
            /* Server requested client cert — we don't support. */
            ret = 0;
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    case TLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY:
        if (type == TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY) {
            CvmTlsCertVerify cv;
            ret = cvm_tls_decode_certificate_verify(&cv, message.base + 4,
                                                    message.base + message.len);
            if (ret == 0)
                ret = verify_certificate_verify(tls, &cv);
            if (ret == 0)
                tls->state = TLS_STATE_CLIENT_EXPECT_FINISHED;
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    case TLS_STATE_CLIENT_EXPECT_FINISHED:
        if (type == TLS_HANDSHAKE_TYPE_FINISHED) {
            CvmTlsFinished fin;
            ret = cvm_tls_decode_finished(&fin, message.base + 4,
                                          message.base + message.len);
            if (ret == 0) {
                usize const dlen = tls->suite->hash->digest_size;

                /*
                 * 1. Verify the server's Finished against the transcript as
                 *    it stands now — which excludes this message, since the
                 *    transcript here covers everything up to but not
                 *    including it.
                 */
                u8 expected[TLS_MAX_DIGEST_SIZE];
                ret = cvm_tls_ks_calc_verify_data(&tls->ks, expected,
                                                  tls->server_hs_secret);
                if (ret == 0) {
                    if (fin.verify_data.len != dlen ||
                        !cvmcrypt_ct_eq(fin.verify_data.base, expected, dlen)) {
                        ret = TLS_ALERT_DECRYPT_ERROR;
                    }
                }
                memset(expected, 0, sizeof(expected));

                /*
                 * 2. The server's Finished now joins the transcript. The
                 *    application secrets and our own Finished are both
                 *    derived from the transcript that includes it.
                 */
                if (ret == 0) {
                    cvm_tls_ks_update_hash(&tls->ks, message.base, message.len);
                    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0});
                }
                if (ret == 0) {
                    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->server_ap_secret,
                                                   "s ap traffic");
                    if (ret == 0)
                        ret = cvm_tls_ks_derive_secret(&tls->ks, tls->client_ap_secret,
                                                       "c ap traffic");
                }

                /*
                 * 3. Our Finished, computed over the same transcript and sent
                 *    with the HANDSHAKE keys — so it must go out before the
                 *    application keys replace tls->enc below.
                 */
                if (ret == 0) {
                    u8 verify_data[TLS_MAX_DIGEST_SIZE];
                    ret = cvm_tls_ks_calc_verify_data(&tls->ks, verify_data,
                                                      tls->client_hs_secret);
                    if (ret == 0) {
                        CvmTlsBuf fin_buf;
                        cvm_tls_buf_init(&fin_buf, NULL, 0);
                        ret = cvm_tls_encode_finished(&fin_buf,
                                                      (CvmTlsVec){verify_data, dlen});
                        if (ret == 0) {
                            /* Finished belongs to the Handshake level (2). */
                            tls->write_epoch = 2;
                            ret =
                                emit_handshake(tls, sendbuf, fin_buf.base, fin_buf.off);
                        }
                        if (ret == 0) {
                            cvm_tls_ks_update_hash(&tls->ks, fin_buf.base, fin_buf.off);
                        }
                        cvm_tls_buf_dispose(&fin_buf);
                    }
                    memset(verify_data, 0, sizeof(verify_data));
                }

                /* 4. Switch to application keys. */
                if (ret == 0) {
                    ret = setup_traffic_protection(tls, false, 3, tls->server_ap_secret,
                                                   "s ap traffic");
                    if (ret == 0)
                        ret = setup_traffic_protection(
                            tls, true, 3, tls->client_ap_secret, "c ap traffic");
                }
                if (ret == 0) {
                    tls->state = TLS_STATE_CLIENT_POST_HANDSHAKE;
                    tls->handshake_complete = true;
                }
            }
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    case TLS_STATE_CLIENT_POST_HANDSHAKE:
        if (type == TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET) {
            ret = 0; /* accept and ignore for now (t47) */
        } else {
            ret = TLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;

    default:
        ret = TLS_ALERT_INTERNAL_ERROR;
        break;
    }

    /*
     * Every handshake message joins the transcript. ServerHello and Finished
     * are hashed inside their own branches because their ordering relative to
     * a key derivation matters; everything else is hashed here.
     */
    if (ret == 0 && type != TLS_HANDSHAKE_TYPE_SERVER_HELLO &&
        type != TLS_HANDSHAKE_TYPE_FINISHED) {
        cvm_tls_ks_update_hash(&tls->ks, message.base, message.len);
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/* public: handshake entry point                                        */
/* ------------------------------------------------------------------ */

int cvm_tls_handshake(CvmTls* tls, CvmTlsBuf* sendbuf, void const* input, usize* inlen,
                      CvmTlsHandshakeProps* props) {
    int ret;
    (void)props;

    if (tls->state == TLS_STATE_CLIENT_HANDSHAKE_START) {
        ret = client_send_client_hello(tls, sendbuf);
        if (ret != 0)
            return ret;
        if (input == NULL || *inlen == 0) {
            *inlen = 0;
            return TLS_ERROR_IN_PROGRESS;
        }
    }

    /* Process input records. */
    u8 const* src = input;
    usize remaining = *inlen;

    while (remaining > 0) {
        /*
         * Stop as soon as the handshake is complete and leave the rest of the
         * buffer unconsumed. A peer's first application record routinely
         * arrives in the same read as its Finished; this loop handles only
         * handshake records, so anything it consumes past this point is
         * silently dropped — which shows up much later as a protocol stream
         * missing its first few bytes.
         */
        if (tls->handshake_complete)
            break;
        CvmTlsRecord rec;
        usize consumed = remaining;
        ret = cvm_tls_parse_record(&rec, src, &consumed, &tls->recvbuf_rec);
        if (ret == TLS_ERROR_IN_PROGRESS)
            break; /* need more data */
        if (ret != 0)
            return ret;
        src += consumed;
        remaining -= consumed;

        if (rec.type == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
            /* Ignore (middlebox compat). */
            continue;
        }
#ifdef TLS_DEBUG
        printf("[debug] record type=%u len=%u dec_aead=%p\n", rec.type, rec.length,
               (void*)tls->dec.aead);
#endif
        if (rec.type == TLS_CONTENT_TYPE_ALERT) {
            if (rec.length >= 2)
                return TLS_ERROR_CLASS_ALERT | rec.fragment[1];
            return TLS_ALERT_DECODE_ERROR;
        }

        /* Decrypt if encrypted. */
        u8* plaintext = NULL;
        usize plaintext_len;
        u8 content_type;

        if (tls->dec.aead != NULL && rec.type == TLS_CONTENT_TYPE_APPDATA) {
            plaintext = rt_mem_alloc(rec.length);
            if (plaintext == NULL)
                return TLS_ERROR_NO_MEMORY;
            ret = cvm_tls_aead_decrypt(&tls->dec, plaintext, &plaintext_len,
                                       &content_type, rec.fragment, rec.length);
#ifdef TLS_DEBUG
            printf("[debug] decrypt seq=%llu len=%u ret=%d first=%02x%02x\n",
                   (unsigned long long)tls->dec.seq, rec.length, ret,
                   rec.length > 0 ? rec.fragment[0] : 0,
                   rec.length > 1 ? rec.fragment[1] : 0);
            /* Save record for offline analysis */
            {
                FILE* df = fopen("/tmp/tls_record.bin", "wb");
                if (df) {
                    fwrite(rec.fragment, 1, rec.length, df);
                    fclose(df);
                }
                /* Also save the full input including record header */
                df = fopen("/tmp/tls_raw.bin", "wb");
                if (df) {
                    fwrite(rec.fragment - 5, 1, rec.length + 5, df);
                    fclose(df);
                }
            }
#endif
#ifdef TLS_DEBUG
            if (ret != 0) {
                /* Dump for offline analysis */
                printf("[debug] DUMP: key=");
                /* We can't easily get the key here, but we have traffic iv */
                printf("iv_unknown ct=");
                for (int i = 0; i < 32 && i < (int)rec.length; i++)
                    printf("%02x", rec.fragment[i]);
                printf("... tag=");
                for (int i = 0; i < 16; i++)
                    printf("%02x", rec.fragment[rec.length - 16 + i]);
                printf("\n");
            }
#endif
            if (ret != 0) {
                rt_mem_free(plaintext);
                return ret;
            }
        } else {
            plaintext = (u8*)rec.fragment;
            plaintext_len = rec.length;
            content_type = rec.type;
        }

#ifdef TLS_DEBUG
        printf("[debug] after decrypt: content_type=%u pt_len=%zu first16=",
               content_type, plaintext_len);
        for (int i = 0; i < 16 && i < (int)plaintext_len; i++)
            printf("%02x", plaintext[i]);
        printf("\n");
#endif
        if (content_type == TLS_CONTENT_TYPE_HANDSHAKE) {
            /* Parse handshake messages. */
            u8 const* hs = plaintext;
            u8 const* hs_end = plaintext + plaintext_len;
#ifdef TLS_DEBUG
            printf("[debug] entering handshake loop: hs=%p end=%p remaining=%ld\n",
                   (void*)hs, (void*)hs_end, (long)(hs_end - hs));
#endif
            while (hs < hs_end) {
                u8 msg_type;
                CvmTlsVec body;
                ret = cvm_tls_decode_handshake_header(&msg_type, &body, &hs, hs_end);
                if (ret != 0)
                    break;

                /* Reconstruct full message for the state machine. A server
                 * runs a different machine over the same record layer; it
                 * used to fall through to the client's, hit its default arm
                 * and return INTERNAL_ERROR, which is why the server never
                 * completed a handshake with anyone. */
                CvmTlsVec msg = {hs - body.len - 4, body.len + 4};
                ret = tls->is_server ? cvm_tls_server_handle_message(tls, sendbuf, msg)
                                     : client_handle_message(tls, sendbuf, msg);
                if (ret != 0)
                    break;
            }
        }

        if (plaintext != rec.fragment)
            rt_mem_free(plaintext);

        if (ret != 0)
            return ret;
    }

    *inlen -= remaining;
    return tls->handshake_complete ? 0 : TLS_ERROR_IN_PROGRESS;
}

/* ------------------------------------------------------------------ */
/* public: application data                                             */
/* ------------------------------------------------------------------ */

int cvm_tls_send(CvmTls* tls, CvmTlsBuf* sendbuf, void const* input, usize inlen) {
    if (!tls->handshake_complete)
        return TLS_ALERT_INTERNAL_ERROR;
    return cvm_tls_push_encrypted_records(sendbuf, TLS_CONTENT_TYPE_APPDATA, input,
                                          inlen, &tls->enc);
}

int cvm_tls_receive(CvmTls* tls, CvmTlsBuf* decryptbuf, void const* input,
                    usize* inlen) {
    u8 const* src = input;
    usize remaining = *inlen;
    int ret = 0;

    if (!tls->handshake_complete)
        return TLS_ALERT_UNEXPECTED_MESSAGE;

    while (remaining > 0) {
        CvmTlsRecord rec;
        usize consumed = remaining;

        ret = cvm_tls_parse_record(&rec, src, &consumed, &tls->recvbuf_rec);
        if (ret == TLS_ERROR_IN_PROGRESS) {
            /* Partial record: keep it and wait for more bytes. */
            ret = 0;
            break;
        }
        if (ret != 0)
            break;

        src += consumed;
        remaining -= consumed;

        if (rec.type == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            continue;

        if (tls->dec.aead != NULL && rec.type == TLS_CONTENT_TYPE_APPDATA) {
            u8* plain = rt_mem_alloc(rec.length);
            if (plain == NULL) {
                ret = TLS_ERROR_NO_MEMORY;
                break;
            }

            usize ptlen = 0;
            u8 content_type = 0;
            ret = cvm_tls_aead_decrypt(&tls->dec, plain, &ptlen, &content_type,
                                       rec.fragment, rec.length);
            if (ret == 0) {
                switch (content_type) {
                case TLS_CONTENT_TYPE_APPDATA:
                    ret = cvm_tls_buf_pushv(decryptbuf, plain, ptlen);
                    break;
                case TLS_CONTENT_TYPE_ALERT:
                    /*
                     * An alert inside an encrypted record. close_notify is a
                     * clean end of stream; anything else is fatal. Both are
                     * reported the same way — the caller decides by checking
                     * the low byte against TLS_ALERT_CLOSE_NOTIFY.
                     */
                    ret = ptlen >= 2 ? (TLS_ERROR_CLASS_ALERT | plain[1])
                                     : TLS_ALERT_DECODE_ERROR;
                    break;
                default:
                    /*
                     * Post-handshake handshake messages (NewSessionTicket,
                     * KeyUpdate) are accepted and ignored. KeyUpdate is not
                     * acted on yet: a peer that actually asks for a key
                     * update would desynchronise, and that is recorded as a
                     * gap rather than silently half-implemented.
                     */
                    break;
                }
            }

            memset(plain, 0, rec.length);
            rt_mem_free(plain);
            if (ret != 0)
                break;
        } else {
            /* A plaintext record after the handshake: alerts only. */
            if (rec.type == TLS_CONTENT_TYPE_ALERT && rec.length >= 2) {
                ret = TLS_ERROR_CLASS_ALERT | rec.fragment[1];
                break;
            }
        }
    }

    *inlen -= remaining;
    return ret;
}

int cvm_tls_send_alert(CvmTls* tls, CvmTlsBuf* sendbuf, u8 level, u8 description) {
    u8 alert[2] = {level, description};

    if (sendbuf == NULL)
        return TLS_ALERT_INTERNAL_ERROR;

    /*
     * Alerts are ordinary records once keys exist. Before the handshake has
     * produced any, they go out in the clear, which is what a client that
     * rejects a ServerHello must do.
     */
    if (tls->enc.aead != NULL) {
        return cvm_tls_push_encrypted_records(sendbuf, TLS_CONTENT_TYPE_ALERT, alert,
                                              sizeof(alert), &tls->enc);
    }

    if (cvm_tls_buf_push(sendbuf, TLS_CONTENT_TYPE_ALERT) != 0)
        return TLS_ERROR_NO_MEMORY;
    if (cvm_tls_buf_push(sendbuf, 3) != 0)
        return TLS_ERROR_NO_MEMORY;
    if (cvm_tls_buf_push(sendbuf, 3) != 0)
        return TLS_ERROR_NO_MEMORY;
    if (cvm_tls_buf_push(sendbuf, 0) != 0)
        return TLS_ERROR_NO_MEMORY;
    if (cvm_tls_buf_push(sendbuf, (u8)sizeof(alert)) != 0)
        return TLS_ERROR_NO_MEMORY;
    return cvm_tls_buf_pushv(sendbuf, alert, sizeof(alert));
}

bool cvm_tls_is_server(CvmTls const* tls) {
    return tls->is_server;
}
u16 cvm_tls_get_protocol_version(CvmTls const* tls) {
    return tls->handshake_complete ? TLS_PROTOCOL_VERSION_TLS13 : 0;
}
char const* cvm_tls_get_server_name(CvmTls const* tls) {
    return tls->server_name;
}
CvmTlsCipherSuite const* cvm_tls_get_cipher_suite(CvmTls const* tls) {
    return tls->suite;
}

u32 cvm_tls_get_read_epoch(CvmTls const* tls) {
    return tls->read_epoch;
}

int cvm_tls_quic_set_local_transport_params(CvmTls* tls, u8 const* data, usize len) {
    if (tls == NULL || (data == NULL && len > 0))
        return TLS_ALERT_INTERNAL_ERROR;
    if (len > sizeof(tls->local_quic_params))
        return TLS_ALERT_ILLEGAL_PARAMETER;

    if (len > 0)
        memcpy(tls->local_quic_params, data, len);
    tls->local_quic_params_len = len;
    return 0;
}

CvmTlsVec cvm_tls_quic_remote_transport_params(CvmTls const* tls) {
    if (tls == NULL)
        return (CvmTlsVec){NULL, 0};
    return (CvmTlsVec){tls->remote_quic_params, tls->remote_quic_params_len};
}

void cvm_tls_set_alpn(CvmTls* tls, CvmTlsVec const* alpns, usize nalpn) {
    if (tls == NULL)
        return;
    tls->nalpn = 0;
    if (alpns == NULL)
        return;
    if (nalpn > TLS_MAX_ALPN)
        nalpn = TLS_MAX_ALPN;
    for (usize i = 0; i < nalpn; i++)
        tls->alpns[i] = alpns[i];
    tls->nalpn = nalpn;
}

bool cvm_tls_is_quic(CvmTls const* tls) {
    return tls != NULL && tls->quic;
}

void cvm_tls_set_app_data(CvmTls* tls, void* data) {
    if (tls != NULL)
        tls->app_data = data;
}

void* cvm_tls_get_app_data(CvmTls const* tls) {
    return tls != NULL ? tls->app_data : NULL;
}

int cvm_tls_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, usize epoch_offsets[5],
                           usize in_epoch, void const* input, usize inlen,
                           CvmTlsHandshakeProps* props) {
    int ret;

    (void)props;

    if (tls == NULL || sendbuf == NULL || epoch_offsets == NULL)
        return TLS_ALERT_INTERNAL_ERROR;

    /* QUIC mode: no records, ever. Set on the first call so a session cannot
     * be half-record, half-not. */
    tls->quic = true;
    tls->epoch_offsets = epoch_offsets;
    for (usize i = 0; i < 5; i++) {
        epoch_offsets[i] = 0;
    }

    /*
     * QUIC hands us CRYPTO data for one encryption level at a time and the
     * level must match what the key schedule expects, or messages would be
     * fed in the wrong order.
     */
    if (in_epoch != tls->read_epoch)
        return TLS_ALERT_UNEXPECTED_MESSAGE;

    /* ClientHello goes out on the first call, at the Initial level (0). */
    if (tls->state == TLS_STATE_CLIENT_HANDSHAKE_START) {
        tls->write_epoch = 0;
        ret = client_send_client_hello(tls, sendbuf);
        if (ret != 0)
            return ret;
        if (input == NULL || inlen == 0)
            return TLS_ERROR_IN_PROGRESS;
    }

    /*
     * Reassemble: a CRYPTO frame may end in the middle of a handshake
     * message. Whatever is left over is kept in recvbuf_msg for the next
     * call.
     */
    u8 const* src = input;
    usize remaining = inlen;

    if (tls->recvbuf_msg.off > 0) {
        if ((ret = cvm_tls_buf_pushv(&tls->recvbuf_msg, input, inlen)) != 0)
            return ret;
        src = tls->recvbuf_msg.base;
        remaining = tls->recvbuf_msg.off;
    }

    while (remaining >= 4) {
        usize const mlen = ((usize)src[1] << 16) | ((usize)src[2] << 8) | (usize)src[3];
        if (remaining < 4 + mlen)
            break; /* incomplete message */

        /* Anything the state machine emits while handling this message
         * belongs to the level it arrived on. */
        tls->write_epoch = in_epoch;

        CvmTlsVec msg = {(u8*)src, 4 + mlen};
        ret = tls->is_server ? cvm_tls_server_handle_message(tls, sendbuf, msg)
                             : client_handle_message(tls, sendbuf, msg);
        if (ret != 0) {
            tls->recvbuf_msg.off = 0;
            return ret;
        }

        src += 4 + mlen;
        remaining -= 4 + mlen;
    }

    /* Keep the tail for the next call. */
    if (src != tls->recvbuf_msg.base) {
        tls->recvbuf_msg.off = 0;
        if (remaining > 0) {
            if ((ret = cvm_tls_buf_pushv(&tls->recvbuf_msg, src, remaining)) != 0)
                return ret;
        }
    } else {
        /* Nothing consumed: keep the buffer as it is. */
        tls->recvbuf_msg.off = remaining;
    }

    return tls->handshake_complete ? 0 : TLS_ERROR_IN_PROGRESS;
}
