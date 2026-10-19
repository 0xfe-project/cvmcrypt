/*
 * src/tls/handshake.c
 *
 * TLS 1.3 handshake message encode/decode (RFC 8446 §4).
 * Ported from picotls, simplified for TLS 1.3-only.
 */

#include "tls/handshake.h"
#include "tls/tls_internal.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* HelloRetryRequest random value (RFC 8446 §4.1.3). */
static u8 const HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/* ------------------------------------------------------------------ */
/* encode helpers                                                       */
/* ------------------------------------------------------------------ */

static int push_handshake_header(CvmTlsBuf* buf, u8 type, usize body_len) {
    int ret;
    if ((ret = cvm_tls_buf_push(buf, type)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)(body_len >> 16))) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)(body_len >> 8))) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)body_len)) != 0)
        return ret;
    return 0;
}

/* Fix the 3-byte handshake message length (after body is written). */
static void fix_handshake_length(CvmTlsBuf* buf, usize header_start) {
    usize body_len = buf->off - header_start - 4;
    buf->base[header_start + 1] = (u8)(body_len >> 16);
    buf->base[header_start + 2] = (u8)(body_len >> 8);
    buf->base[header_start + 3] = (u8)body_len;
}

static int push_block16(CvmTlsBuf* buf, usize* start) {
    int ret;
    *start = buf->off;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;
    return 0;
}

static void fix_block16(CvmTlsBuf* buf, usize start) {
    usize len = buf->off - start - 2;
    buf->base[start] = (u8)(len >> 8);
    buf->base[start + 1] = (u8)len;
}

static int push_block24(CvmTlsBuf* buf, usize* start) {
    int ret;
    *start = buf->off;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;
    return 0;
}

static void fix_block24(CvmTlsBuf* buf, usize start) {
    usize len = buf->off - start - 3;
    buf->base[start] = (u8)(len >> 16);
    buf->base[start + 1] = (u8)(len >> 8);
    buf->base[start + 2] = (u8)len;
}

static int push_vec8(CvmTlsBuf* buf, CvmTlsVec v) {
    int ret;
    if (v.len > 255)
        return TLS_ERROR_LIBRARY;
    if ((ret = cvm_tls_buf_push(buf, (u8)v.len)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_pushv(buf, v.base, v.len)) != 0)
        return ret;
    return 0;
}

static int push_vec16(CvmTlsBuf* buf, CvmTlsVec v) {
    int ret;
    if (v.len > 65535)
        return TLS_ERROR_LIBRARY;
    if ((ret = cvm_tls_buf_push(buf, (u8)(v.len >> 8))) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)v.len)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_pushv(buf, v.base, v.len)) != 0)
        return ret;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ClientHello encode                                                   */
/* ------------------------------------------------------------------ */

int cvm_tls_encode_client_hello(
    CvmTlsBuf* buf, CvmTlsCipherSuite const* const* cipher_suites, u8 const random[32],
    CvmTlsVec legacy_session_id, char const* server_name, CvmTlsKeyexAlgo const* keyex,
    CvmTlsVec keyex_pubkey, CvmTlsVec* psk_identity, u32 psk_obfuscated_ticket_age,
    CvmTlsVec quic_transport_params, CvmTlsVec const* alpns, usize nalpn) {
    int ret;
    usize hdr_start, ext_start;
    (void)psk_identity;
    (void)psk_obfuscated_ticket_age;

    /* Reserve: header (4) + legacy_version (2) + random (32) + ... */
    if ((ret = cvm_tls_buf_reserve(buf, 1024)) != 0)
        return ret;

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_CLIENT_HELLO, 0)) != 0)
        return ret;
    /* legacy_version = 0x0303 (TLS 1.2 for compat). */
    if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
        return ret;

    /* random (32 bytes). */
    if ((ret = cvm_tls_buf_pushv(buf, random, 32)) != 0)
        return ret;

    /* legacy_session_id. */
    if ((ret = push_vec8(buf, legacy_session_id)) != 0)
        return ret;

    /* cipher_suites. */
    {
        usize cs_start;
        if ((ret = push_block16(buf, &cs_start)) != 0)
            return ret;
        for (usize i = 0; cipher_suites[i] != NULL; i++) {
            if ((ret = cvm_tls_buf_push(buf, (u8)(cipher_suites[i]->id >> 8))) != 0)
                return ret;
            if ((ret = cvm_tls_buf_push(buf, (u8)cipher_suites[i]->id)) != 0)
                return ret;
        }
        fix_block16(buf, cs_start);
    }

    /* compression_methods: [1, 0] (null only). */
    if ((ret = cvm_tls_buf_push(buf, 1)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;

    /* extensions. */
    if ((ret = push_block16(buf, &ext_start)) != 0)
        return ret;

    /* server_name (SNI) — extension 0. */
    if (server_name != NULL) {
        usize sni_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret; /* ext type 0 */
        if ((ret = push_block16(buf, &sni_start)) != 0)
            return ret; /* ext body */
        {
            usize list_start;
            if ((ret = push_block16(buf, &list_start)) != 0)
                return ret; /* ServerNameList */
            if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
                return ret; /* type = host_name */
            usize name_len = 0;
            while (server_name[name_len] != 0)
                name_len++;
            if ((ret = push_vec16(buf,
                                  (CvmTlsVec){(u8 const*)server_name, name_len})) != 0)
                return ret;
            fix_block16(buf, list_start);
        }
        fix_block16(buf, sni_start);
    }

    /* supported_versions — extension 43: [0x0304]. */
    {
        usize sv_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 43)) != 0)
            return ret;
        if ((ret = push_block16(buf, &sv_start)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 2)) != 0)
            return ret; /* list byte length */
        if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
            return ret; /* 0x0304 */
        if ((ret = cvm_tls_buf_push(buf, 4)) != 0)
            return ret;
        fix_block16(buf, sv_start);
    }

    /* key_share — extension 51: [{group, pubkey}]. */
    if (keyex != NULL && keyex_pubkey.base != NULL) {
        usize ks_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 51)) != 0)
            return ret;
        if ((ret = push_block16(buf, &ks_start)) != 0)
            return ret;
        {
            usize list_start;
            if ((ret = push_block16(buf, &list_start)) != 0)
                return ret;
            /* KeyShareEntry: group(2) + key_exchange(2+len). */
            if ((ret = cvm_tls_buf_push(buf, (u8)(keyex->id >> 8))) != 0)
                return ret;
            if ((ret = cvm_tls_buf_push(buf, (u8)keyex->id)) != 0)
                return ret;
            if ((ret = push_vec16(buf, keyex_pubkey)) != 0)
                return ret;
            fix_block16(buf, list_start);
        }
        fix_block16(buf, ks_start);
    }

    /* signature_algorithms — extension 13. */
    {
        usize sa_start;
        static u16 const ALGOS[] = {
            TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,    TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
            TLS_SIGNATURE_ECDSA_SECP256R1_SHA256, TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
            TLS_SIGNATURE_RSA_PKCS1_SHA256,
        };
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 13)) != 0)
            return ret;
        if ((ret = push_block16(buf, &sa_start)) != 0)
            return ret;
        {
            usize list_start;
            if ((ret = push_block16(buf, &list_start)) != 0)
                return ret;
            for (usize i = 0; i < sizeof(ALGOS) / sizeof(ALGOS[0]); i++) {
                if ((ret = cvm_tls_buf_push(buf, (u8)(ALGOS[i] >> 8))) != 0)
                    return ret;
                if ((ret = cvm_tls_buf_push(buf, (u8)ALGOS[i])) != 0)
                    return ret;
            }
            fix_block16(buf, list_start);
        }
        fix_block16(buf, sa_start);
    }

    /* supported_groups — extension 10. */
    {
        usize sg_start;
        static u16 const GROUPS[] = {TLS_GROUP_X25519, TLS_GROUP_SECP256R1,
                                     TLS_GROUP_SECP384R1};
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 10)) != 0)
            return ret;
        if ((ret = push_block16(buf, &sg_start)) != 0)
            return ret;
        {
            usize list_start;
            if ((ret = push_block16(buf, &list_start)) != 0)
                return ret;
            for (usize i = 0; i < sizeof(GROUPS) / sizeof(GROUPS[0]); i++) {
                if ((ret = cvm_tls_buf_push(buf, (u8)(GROUPS[i] >> 8))) != 0)
                    return ret;
                if ((ret = cvm_tls_buf_push(buf, (u8)GROUPS[i])) != 0)
                    return ret;
            }
            fix_block16(buf, list_start);
        }
        fix_block16(buf, sg_start);
    }

    /* psk_key_exchange_modes — extension 45: [psk_dhe_ke(1)]. */
    {
        usize pk_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 45)) != 0)
            return ret;
        if ((ret = push_block16(buf, &pk_start)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 1)) != 0)
            return ret; /* list len */
        if ((ret = cvm_tls_buf_push(buf, TLS_PSK_KE_MODE_PSK_DHE_KEY_EXCHANGE)) != 0)
            return ret;
        fix_block16(buf, pk_start);
    }

    /* ALPN — extension 16. QUIC requires it; a server configured with a
     * protocol list aborts the handshake when the client offers none. */
    if (alpns != NULL && nalpn > 0) {
        usize alpn_start, list_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 16)) != 0)
            return ret;
        if ((ret = push_block16(buf, &alpn_start)) != 0)
            return ret;
        if ((ret = push_block16(buf, &list_start)) != 0)
            return ret;
        for (usize i = 0; i < nalpn; i++) {
            if ((ret = push_vec8(buf, alpns[i])) != 0)
                return ret;
        }
        fix_block16(buf, list_start);
        fix_block16(buf, alpn_start);
    }

    /* quic_transport_parameters — extension 57 (0x39). A QUIC peer aborts the
     * handshake when it is missing, so it must be here in QUIC mode and absent
     * otherwise. */
    if (quic_transport_params.base != NULL && quic_transport_params.len > 0) {
        usize qp_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 0x39)) != 0)
            return ret;
        if ((ret = push_block16(buf, &qp_start)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_pushv(buf, quic_transport_params.base,
                                     quic_transport_params.len)) != 0)
            return ret;
        fix_block16(buf, qp_start);
    }

    fix_block16(buf, ext_start);
    fix_handshake_length(buf, hdr_start);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ServerHello encode                                                   */
/* ------------------------------------------------------------------ */

int cvm_tls_encode_server_hello(CvmTlsBuf* buf, CvmTlsCipherSuite const* suite,
                                u8 const random[32], CvmTlsVec legacy_session_id,
                                CvmTlsKeyexAlgo const* keyex, CvmTlsVec peer_key) {
    int ret;
    usize hdr_start, ext_start;
    (void)keyex;
    (void)peer_key; /* key_share is in extensions below */

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_SERVER_HELLO, 0)) != 0)
        return ret;

    /* legacy_version = 0x0303. */
    if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
        return ret;

    /* random. */
    if ((ret = cvm_tls_buf_pushv(buf, random, 32)) != 0)
        return ret;

    /* legacy_session_id (echo). */
    if ((ret = push_vec8(buf, legacy_session_id)) != 0)
        return ret;

    /* cipher_suite. */
    if ((ret = cvm_tls_buf_push(buf, (u8)(suite->id >> 8))) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)suite->id)) != 0)
        return ret;

    /* compression_method = 0. */
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;

    /* extensions. */
    if ((ret = push_block16(buf, &ext_start)) != 0)
        return ret;

    /* supported_versions. */
    {
        usize sv_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 43)) != 0)
            return ret;
        if ((ret = push_block16(buf, &sv_start)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 4)) != 0)
            return ret;
        fix_block16(buf, sv_start);
    }

    /* key_share (server's ephemeral public key). */
    if (keyex != NULL && peer_key.base != NULL) {
        usize ks_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 51)) != 0)
            return ret;
        if ((ret = push_block16(buf, &ks_start)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, (u8)(keyex->id >> 8))) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, (u8)keyex->id)) != 0)
            return ret;
        if ((ret = push_vec16(buf, peer_key)) != 0)
            return ret;
        fix_block16(buf, ks_start);
    }

    fix_block16(buf, ext_start);
    fix_handshake_length(buf, hdr_start);
    return 0;
}

/* ------------------------------------------------------------------ */
/* other message encodes                                                */
/* ------------------------------------------------------------------ */

int cvm_tls_encode_encrypted_extensions(CvmTlsBuf* buf, CvmTlsVec* alpn_protocol) {
    int ret;
    usize hdr_start, ext_start;

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
                                     0)) != 0)
        return ret;

    if ((ret = push_block16(buf, &ext_start)) != 0)
        return ret;

    /* ALPN — extension 16. */
    if (alpn_protocol != NULL && alpn_protocol->base != NULL) {
        usize alpn_start, list_start;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 16)) != 0)
            return ret;
        if ((ret = push_block16(buf, &alpn_start)) != 0)
            return ret;
        if ((ret = push_block16(buf, &list_start)) != 0)
            return ret;
        if ((ret = push_vec16(buf, *alpn_protocol)) != 0)
            return ret;
        fix_block16(buf, list_start);
        fix_block16(buf, alpn_start);
    }

    fix_block16(buf, ext_start);
    fix_handshake_length(buf, hdr_start);
    return 0;
}

int cvm_tls_encode_certificate(CvmTlsBuf* buf, CvmTlsVec const* certs,
                               usize num_certs) {
    int ret;
    usize hdr_start, list_start;

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_CERTIFICATE, 0)) != 0)
        return ret;

    /* certificate_request_context (empty for server). */
    if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
        return ret;

    /* certificate_list. */
    if ((ret = push_block24(buf, &list_start)) != 0)
        return ret;
    for (usize i = 0; i < num_certs; i++) {
        usize entry_start;
        if ((ret = push_block24(buf, &entry_start)) != 0)
            return ret; /* cert data */
        if ((ret = cvm_tls_buf_pushv(buf, certs[i].base, certs[i].len)) != 0)
            return ret;
        fix_block24(buf, entry_start);
        /* extensions (empty). */
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            return ret;
    }
    fix_block24(buf, list_start);

    fix_handshake_length(buf, hdr_start);
    return 0;
}

int cvm_tls_encode_certificate_verify(CvmTlsBuf* buf, u16 algorithm,
                                      CvmTlsVec signature) {
    int ret;
    usize hdr_start;

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, 0)) !=
        0)
        return ret;

    if ((ret = cvm_tls_buf_push(buf, (u8)(algorithm >> 8))) != 0)
        return ret;
    if ((ret = cvm_tls_buf_push(buf, (u8)algorithm)) != 0)
        return ret;
    if ((ret = push_vec16(buf, signature)) != 0)
        return ret;

    fix_handshake_length(buf, hdr_start);
    return 0;
}

int cvm_tls_encode_finished(CvmTlsBuf* buf, CvmTlsVec verify_data) {
    int ret;
    usize hdr_start;

    hdr_start = buf->off;
    if ((ret = push_handshake_header(buf, TLS_HANDSHAKE_TYPE_FINISHED, 0)) != 0)
        return ret;

    if ((ret = cvm_tls_buf_pushv(buf, verify_data.base, verify_data.len)) != 0)
        return ret;

    fix_handshake_length(buf, hdr_start);
    return 0;
}

/* ------------------------------------------------------------------ */
/* decode                                                               */
/* ------------------------------------------------------------------ */

int cvm_tls_decode_handshake_header(u8* type, CvmTlsVec* body, u8 const** src,
                                    u8 const* end) {
    u32 len;
    if (end - *src < 4)
        return TLS_ERROR_DECODE;
    *type = *(*src)++;
    if (tls_decode24(&len, src, end) != 0)
        return TLS_ERROR_DECODE;
    if (*src + len > end)
        return TLS_ERROR_DECODE;
    body->base = *src;
    body->len = len;
    *src += len;
    return 0;
}

static int decode_key_share(CvmTlsKeyShareEntry* ks, u8 const** src, u8 const* end) {
    u16 len;
    if (tls_decode16(&ks->group, src, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode16(&len, src, end) != 0)
        return TLS_ERROR_DECODE;
    if (*src + len > end)
        return TLS_ERROR_DECODE;
    ks->key_exchange.base = *src;
    ks->key_exchange.len = len;
    *src += len;
    return 0;
}

int cvm_tls_decode_client_hello(CvmTlsClientHello* ch, u8 const* src, u8 const* end) {
    memset(ch, 0, sizeof(*ch));
    u16 len;
    u8 comp_len;
    u8 const* p = src;

    { /* legacy_version */
        u16 v;
        if (tls_decode16(&v, &p, end) != 0)
            return TLS_ERROR_DECODE;
    }
    if (end - p < 32)
        return TLS_ERROR_DECODE;
    memcpy(ch->random, p, 32);
    p += 32;
    { /* legacy_session_id (1-byte length) */
        u8 sid_len;
        if (tls_decode8(&sid_len, &p, end) != 0)
            return TLS_ERROR_DECODE;
        if (p + sid_len > end)
            return TLS_ERROR_DECODE;
        ch->legacy_session_id.base = p;
        ch->legacy_session_id.len = sid_len;
        p += sid_len;
    }
    if (tls_decode16(&len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    for (usize i = 0; i < len / 2 && i < 16; i++) {
        if (tls_decode16(&ch->cipher_suites[i], &p, end) != 0)
            return TLS_ERROR_DECODE;
        ch->num_cipher_suites++;
    }
    if (len & 1)
        p++; /* skip odd byte */
    if (tls_decode8(&comp_len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    p += comp_len;
    if (tls_decode16(&len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    u8 const* ext_end = p + len;
    if (ext_end > end)
        return TLS_ERROR_DECODE;

    while (p < ext_end) {
        u16 ext_type, ext_len;
        if (tls_decode16(&ext_type, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        if (tls_decode16(&ext_len, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        u8 const* eb = p;
        u8 const* eb_end = eb + ext_len;
        p += ext_len;

        switch (ext_type) {
        case TLS_EXTENSION_TYPE_SERVER_NAME: {
            u16 list_len;
            u8 name_type;
            u16 name_len;
            if (tls_decode16(&list_len, &eb, eb_end) != 0)
                break;
            if (tls_decode8(&name_type, &eb, eb_end) != 0)
                break;
            if (name_type == 0 && tls_decode16(&name_len, &eb, eb_end) == 0) {
                ch->server_name = (char const*)eb;
            }
            break;
        }
        case TLS_EXTENSION_TYPE_SUPPORTED_VERSIONS: {
            u8 sv_list_len;
            if (tls_decode8(&sv_list_len, &eb, eb_end) == 0 && sv_list_len >= 2) {
                tls_decode16(&ch->negotiated_version, &eb, eb_end);
            }
            break;
        }
        case TLS_EXTENSION_TYPE_KEY_SHARE: {
            u16 ks_list_len;
            if (tls_decode16(&ks_list_len, &eb, eb_end) == 0) {
                u8 const* list_end = eb + ks_list_len;
                if (list_end > eb_end)
                    list_end = eb_end;
                while (eb < list_end && ch->num_key_shares < 8) {
                    if (decode_key_share(&ch->key_shares[ch->num_key_shares], &eb,
                                         list_end) != 0)
                        break;
                    ch->num_key_shares++;
                }
            }
            break;
        }
        }
    }
    return 0;
}

int cvm_tls_decode_server_hello(CvmTlsServerHello* sh, u8 const* src, u8 const* end) {
    memset(sh, 0, sizeof(*sh));
    u16 len;
    u8 comp;
    u8 const* p = src;

    { /* legacy_version */
        u16 v;
        if (tls_decode16(&v, &p, end) != 0)
            return TLS_ERROR_DECODE;
    }
    if (end - p < 32)
        return TLS_ERROR_DECODE;
    memcpy(sh->random, p, 32);
    p += 32;
    sh->is_hello_retry_request = memcmp(sh->random, HRR_RANDOM, 32) == 0;
    { /* legacy_session_id (1-byte length) */
        u8 sid_len;
        if (tls_decode8(&sid_len, &p, end) != 0)
            return TLS_ERROR_DECODE;
        if (p + sid_len > end)
            return TLS_ERROR_DECODE;
        sh->legacy_session_id.base = p;
        sh->legacy_session_id.len = sid_len;
        p += sid_len;
    }
    if (tls_decode16(&sh->cipher_suite, &p, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode8(&comp, &p, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode16(&len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    u8 const* ext_end = p + len;
    if (ext_end > end)
        return TLS_ERROR_DECODE;

    while (p < ext_end) {
        u16 ext_type, ext_len;
        if (tls_decode16(&ext_type, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        if (tls_decode16(&ext_len, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        u8 const* eb = p;
        p += ext_len;

        switch (ext_type) {
        case TLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            tls_decode16(&sh->negotiated_version, &eb, p);
            break;
        case TLS_EXTENSION_TYPE_KEY_SHARE:
            decode_key_share(&sh->key_share, &eb, p);
            break;
        }
    }
    return 0;
}

int cvm_tls_decode_certificate(CvmTlsCertMsg* cert, u8 const* src, u8 const* end) {
    memset(cert, 0, sizeof(*cert));
    u8 ctx_len;
    u32 list_len;
    u8 const* p = src;

    if (tls_decode8(&ctx_len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    cert->request_context.base = p;
    cert->request_context.len = ctx_len;
    p += ctx_len;
    if (tls_decode24(&list_len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    u8 const* list_end = p + list_len;
    if (list_end > end)
        return TLS_ERROR_DECODE;

    while (p < list_end && cert->num_entries < 8) {
        u32 cert_len;
        u16 ext_len;
        if (tls_decode24(&cert_len, &p, list_end) != 0)
            return TLS_ERROR_DECODE;
        if (p + cert_len > list_end)
            return TLS_ERROR_DECODE;
        cert->entries[cert->num_entries].data.base = p;
        cert->entries[cert->num_entries].data.len = cert_len;
        p += cert_len;
        if (tls_decode16(&ext_len, &p, list_end) != 0)
            return TLS_ERROR_DECODE;
        cert->entries[cert->num_entries].extensions.base = p;
        cert->entries[cert->num_entries].extensions.len = ext_len;
        p += ext_len;
        cert->num_entries++;
    }
    return 0;
}

int cvm_tls_decode_certificate_verify(CvmTlsCertVerify* cv, u8 const* src,
                                      u8 const* end) {
    u16 len;
    if (tls_decode16(&cv->algorithm, &src, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode16(&len, &src, end) != 0)
        return TLS_ERROR_DECODE;
    if (src + len > end)
        return TLS_ERROR_DECODE;
    cv->signature.base = src;
    cv->signature.len = len;
    return 0;
}

int cvm_tls_decode_finished(CvmTlsFinished* fin, u8 const* src, u8 const* end) {
    fin->verify_data.base = src;
    fin->verify_data.len = (usize)(end - src);
    return 0;
}

int cvm_tls_decode_new_session_ticket(CvmTlsNewSessionTicket* nst, u8 const* src,
                                      u8 const* end) {
    memset(nst, 0, sizeof(*nst));
    u16 len;
    u8 nonce_len;
    u8 const* p = src;

    if (tls_decode32(&nst->ticket_lifetime, &p, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode32(&nst->ticket_age_add, &p, end) != 0)
        return TLS_ERROR_DECODE;
    if (tls_decode8(&nonce_len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    nst->ticket_nonce.base = p;
    nst->ticket_nonce.len = nonce_len;
    p += nonce_len;
    if (tls_decode16(&len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    if (p + len > end)
        return TLS_ERROR_DECODE;
    nst->ticket.base = p;
    nst->ticket.len = len;
    p += len;

    /* extensions (may contain early_data). */
    if (tls_decode16(&len, &p, end) != 0)
        return TLS_ERROR_DECODE;
    u8 const* ext_end = p + len;
    if (ext_end > end)
        return TLS_ERROR_DECODE;
    while (p < ext_end) {
        u16 ext_type, ext_len;
        if (tls_decode16(&ext_type, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        if (tls_decode16(&ext_len, &p, ext_end) != 0)
            return TLS_ERROR_DECODE;
        if (ext_type == TLS_EXTENSION_TYPE_EARLY_DATA && ext_len == 4) {
            tls_decode32(&nst->max_early_data_size, &p, ext_end);
        } else {
            p += ext_len;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* CertificateVerify signing input                                      */
/* ------------------------------------------------------------------ */

int cvm_tls_build_cert_verify_data(u8* output, usize output_cap, usize* out_len,
                                   char const* context_string,
                                   u8 const* transcript_hash, usize hash_len) {
    usize ctx_len = 0;
    while (context_string[ctx_len] != 0)
        ctx_len++;

    usize total = 64 + ctx_len + 1 + hash_len;
    if (total > output_cap)
        return TLS_ERROR_NO_MEMORY;

    /* 64 × 0x20. */
    memset(output, 0x20, 64);
    /* context_string. */
    memcpy(output + 64, context_string, ctx_len);
    /* separator 0x00. */
    output[64 + ctx_len] = 0;
    /* Transcript-Hash. */
    memcpy(output + 64 + ctx_len + 1, transcript_hash, hash_len);

    *out_len = total;
    return 0;
}

/* ------------------------------------------------------------------ */
/* EncryptedExtensions decoding                                         */
/* ------------------------------------------------------------------ */

/*
 * Walk the extension block and copy out the QUIC transport parameters
 * (0x39). Everything else is ignored, including ALPN: this client does not
 * negotiate a protocol today.
 *
 * Returns 0 even when 0x39 is absent; QUIC mode checks for that itself,
 * because "absent" is only an error when the caller is QUIC.
 */
int cvm_tls_decode_encrypted_extensions(CvmTlsVec body, u8* quic_params,
                                        usize params_cap, usize* params_len) {
    if (params_len != NULL)
        *params_len = 0;
    if (body.len < 2)
        return TLS_ALERT_DECODE_ERROR;

    usize ext_total = ((usize)body.base[0] << 8) | body.base[1];
    if (ext_total + 2 > body.len)
        return TLS_ALERT_DECODE_ERROR;

    u8 const* p = body.base + 2;
    u8 const* end = p + ext_total;

    while (p + 4 <= end) {
        u16 type = (u16)(((u16)p[0] << 8) | p[1]);
        usize len = ((usize)p[2] << 8) | p[3];
        p += 4;
        if (p + len > end)
            return TLS_ALERT_DECODE_ERROR;

        if (type == 0x0039) {
            if (params_len == NULL)
                return TLS_ALERT_DECODE_ERROR;
            if (len > params_cap)
                return TLS_ALERT_ILLEGAL_PARAMETER;
            memcpy(quic_params, p, len);
            *params_len = len;
        }
        p += len;
    }

    return 0;
}
