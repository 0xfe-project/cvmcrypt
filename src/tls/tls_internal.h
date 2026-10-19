/*
 * src/tls/tls_internal.h
 *
 * Internal types shared between TLS implementation files. Not part of
 * the public API.
 */

#ifndef CVMCRYPT_TLS_INTERNAL_H
#define CVMCRYPT_TLS_INTERNAL_H

#include "tls/tls.h"
#include "base/types.h"

/* ------------------------------------------------------------------ */
/* internal error codes                                                 */
/* ------------------------------------------------------------------ */

#define TLS_ERROR_DECODE (TLS_ERROR_CLASS_INTERNAL + 10)
#define TLS_ERROR_LIBRARY (TLS_ERROR_CLASS_INTERNAL + 11)
#define TLS_ERROR_SESSION_NOT_FOUND (TLS_ERROR_CLASS_INTERNAL + 12)
#define TLS_ERROR_NOT_AVAILABLE (TLS_ERROR_CLASS_INTERNAL + 13)

/* ------------------------------------------------------------------ */
/* decode helpers                                                       */
/* ------------------------------------------------------------------ */

CVM_INLINE int tls_decode8(u8* value, u8 const** src, u8 const* end) {
    if (*src >= end)
        return TLS_ERROR_DECODE;
    *value = *(*src)++;
    return 0;
}

CVM_INLINE int tls_decode16(u16* value, u8 const** src, u8 const* end) {
    if (end - *src < 2)
        return TLS_ERROR_DECODE;
    *value = (u16)((*src)[0] << 8 | (*src)[1]);
    *src += 2;
    return 0;
}

CVM_INLINE int tls_decode24(u32* value, u8 const** src, u8 const* end) {
    if (end - *src < 3)
        return TLS_ERROR_DECODE;
    *value = (u32)((*src)[0] << 16 | (*src)[1] << 8 | (*src)[2]);
    *src += 3;
    return 0;
}

CVM_INLINE int tls_decode32(u32* value, u8 const** src, u8 const* end) {
    if (end - *src < 4)
        return TLS_ERROR_DECODE;
    *value = (u32)((*src)[0] << 24 | (*src)[1] << 16 | (*src)[2] << 8 | (*src)[3]);
    *src += 4;
    return 0;
}

/* ------------------------------------------------------------------ */
/* record                                                               */
/* ------------------------------------------------------------------ */

typedef struct CvmTlsRecord {
    u8 type;
    u16 length;
    u8 const* fragment;
} CvmTlsRecord;

int cvm_tls_parse_record_header(CvmTlsRecord* rec, u8 const* src);
int cvm_tls_parse_record(CvmTlsRecord* rec, u8 const* src, usize* len,
                         CvmTlsBuf* pending);

/* ------------------------------------------------------------------ */
/* traffic protection                                                   */
/* ------------------------------------------------------------------ */

typedef struct CvmTlsTrafficProt {
    CvmTlsAead* aead;
    u64 seq;
    char const* label;
} CvmTlsTrafficProt;

/* QUIC transport parameters are a few hundred bytes at most; ngtcp2's own
 * encoder produces well under this. */
#define TLS_MAX_QUIC_PARAMS_SIZE 512

/* Leaf certificates are a few KB at most; anything larger is refused rather
 * than truncated. */
#define TLS_MAX_LEAF_CERT_SIZE 4096

CVM_INLINE void tls_build_aad(u8 aad[5], usize reclen) {
    aad[0] = TLS_CONTENT_TYPE_APPDATA;
    aad[1] = 3;
    aad[2] = 3;
    aad[3] = (u8)(reclen >> 8);
    aad[4] = (u8)reclen;
}

/* The server's state machine. Same record layer, different machine. */
int cvm_tls_server_handle_message(CvmTls* tls, CvmTlsBuf* sendbuf, CvmTlsVec message);

usize cvm_tls_aead_encrypt(CvmTlsTrafficProt* ctx, u8* output, u8 const* input,
                           usize inlen, u8 content_type);
int cvm_tls_aead_decrypt(CvmTlsTrafficProt* ctx, u8* output, usize* outlen,
                         u8* content_type, u8 const* input, usize inlen);
int cvm_tls_push_encrypted_records(CvmTlsBuf* buf, u8 type, u8 const* src, usize len,
                                   CvmTlsTrafficProt* enc);
int cvm_tls_encrypt_record(CvmTlsBuf* buf, usize rec_start, CvmTlsTrafficProt* enc);

#endif /* CVMCRYPT_TLS_INTERNAL_H */
