/*
 * src/tls/client.c
 *
 * TLS 1.3 client handshake state machine (RFC 8446).
 * Drives: ClientHello → ServerHello → EE → Certificate →
 *         CertificateVerify → Finished → application data.
 */

#include "tls/tls_conn.h"
#include "base/mem.h"
#include "base/secure.h"

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
/* helper: derive traffic keys and set up protection                   */
/* ------------------------------------------------------------------ */

static int setup_traffic_protection(CvmTls* tls, bool is_enc, void const* secret,
                                    char const* label) {
    CvmTlsAeadAlgo const* aead = tls->suite->aead;
    u8 key[32]; /* max AES-256 */
    u8 iv[TLS_MAX_IV_SIZE];
    CvmTlsTrafficProt* tp = is_enc ? &tls->enc : &tls->dec;

    int ret = cvm_tls_ks_get_traffic_keys(&tls->ks, key, aead->key_size, iv,
                                          aead->iv_size, secret);
    if (ret != 0)
        return ret;

    tp->aead = aead->setup(aead, is_enc, key, iv);
    tp->seq = 0;
    tp->label = label;

    cvmcrypt_secure_free(key, sizeof(key));
    if (tp->aead == NULL)
        return TLS_ERROR_LIBRARY;
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

    /* Get our public key. */
    /* The create callback generates a keypair; we need the public key.
     * For X25519, the public key is stored in the context. */
    /* HACK: for now, use a zero pubkey — the crypto layer (t43) will fix this. */
    memset(tls->keyex_pubkey, 0, 32);
    tls->keyex_pubkey_len = 32;

    /* Write record header. */
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

    /* Encode ClientHello. */
    ret = cvm_tls_encode_client_hello(
        sendbuf, tls->ctx->cipher_suites, tls->client_random,
        (CvmTlsVec){tls->legacy_session_id, 32}, tls->server_name, keyex,
        (CvmTlsVec){tls->keyex_pubkey, tls->keyex_pubkey_len}, NULL, 0);
    if (ret != 0)
        return ret;

    /* Fix record length. */
    usize body_len = sendbuf->off - rec_start - 5;
    sendbuf->base[rec_start + 3] = (u8)(body_len >> 8);
    sendbuf->base[rec_start + 4] = (u8)body_len;

    /* Save for transcript. */
    cvm_tls_ks_init(&tls->ks, tls->ctx->cipher_suites[0]); /* default suite for now */
    cvm_tls_ks_update_hash(&tls->ks, sendbuf->base + rec_start + 5, body_len);

    /* Early secret. */
    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0});
    if (ret != 0)
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

    /* Replay transcript: ClientHello + ServerHello.
     * NOTE: We saved ClientHello in ks (via update_hash above).
     * But we re-init'd the ks, so we need to re-feed. For now this
     * is incomplete — proper handling needs saving the CH bytes. */
    /* TODO: save CH bytes in tls->sendbuf_early for replay. */

    /* Advance to handshake secret. */
    ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0}); /* early */
    if (ret != 0)
        return ret;
    ret = cvm_tls_ks_extract(&tls->ks,
                             (CvmTlsVec){NULL, 0}); /* handshake (no ECDHE yet) */
    if (ret != 0)
        return ret;

    /* Derive handshake traffic secrets. */
    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->server_hs_secret, "s hs traffic");
    if (ret != 0)
        return ret;
    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->client_hs_secret, "c hs traffic");
    if (ret != 0)
        return ret;

    /* Set up record protection. */
    ret = setup_traffic_protection(tls, false, tls->server_hs_secret, "s hs traffic");
    if (ret != 0)
        return ret;
    ret = setup_traffic_protection(tls, true, tls->client_hs_secret, "c hs traffic");
    if (ret != 0)
        return ret;

    tls->state = TLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS;
    return 0;
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
            /* Accept — we don't negotiate ALPN for now. */
            tls->state = TLS_STATE_CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE;
            ret = 0;
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
            if (ret == 0) {
                /* TODO: verify signature against server cert (t46). */
                tls->state = TLS_STATE_CLIENT_EXPECT_FINISHED;
            }
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
                /* TODO: verify Finished (needs proper transcript). */
                /* Derive application traffic secrets. */
                ret = cvm_tls_ks_extract(&tls->ks, (CvmTlsVec){NULL, 0}); /* master */
                if (ret == 0) {
                    ret = cvm_tls_ks_derive_secret(&tls->ks, tls->server_ap_secret,
                                                   "s ap traffic");
                    if (ret == 0)
                        ret = cvm_tls_ks_derive_secret(&tls->ks, tls->client_ap_secret,
                                                       "c ap traffic");
                }
                if (ret == 0) {
                    ret = setup_traffic_protection(tls, false, tls->server_ap_secret,
                                                   "s ap traffic");
                    if (ret == 0)
                        ret = setup_traffic_protection(tls, true, tls->client_ap_secret,
                                                       "c ap traffic");
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
            if (ret != 0) {
                rt_mem_free(plaintext);
                return ret;
            }
        } else {
            plaintext = (u8*)rec.fragment;
            plaintext_len = rec.length;
            content_type = rec.type;
        }

        if (content_type == TLS_CONTENT_TYPE_HANDSHAKE) {
            /* Parse handshake messages. */
            u8 const* hs = plaintext;
            u8 const* hs_end = plaintext + plaintext_len;
            while (hs < hs_end) {
                u8 msg_type;
                CvmTlsVec body;
                ret = cvm_tls_decode_handshake_header(&msg_type, &body, &hs, hs_end);
                if (ret != 0)
                    break;

                /* Reconstruct full message for the state machine. */
                CvmTlsVec msg = {hs - body.len - 4, body.len + 4};
                ret = client_handle_message(tls, sendbuf, msg);
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
    /* TODO: decrypt app data records. */
    (void)tls;
    (void)decryptbuf;
    (void)input;
    *inlen = 0;
    return TLS_ERROR_NOT_AVAILABLE;
}

int cvm_tls_send_alert(CvmTls* tls, CvmTlsBuf* sendbuf, u8 level, u8 description) {
    (void)tls;
    (void)sendbuf;
    (void)level;
    (void)description;
    return TLS_ERROR_NOT_AVAILABLE;
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

int cvm_tls_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, usize epoch_offsets[5],
                           usize in_epoch, void const* input, usize inlen,
                           CvmTlsHandshakeProps* props) {
    (void)tls;
    (void)sendbuf;
    (void)epoch_offsets;
    (void)in_epoch;
    (void)input;
    (void)inlen;
    (void)props;
    return TLS_ERROR_NOT_AVAILABLE;
}
