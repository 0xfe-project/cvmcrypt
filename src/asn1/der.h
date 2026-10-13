/*
 * src/asn1/der.h
 *
 * ASN.1 DER decoder. Minimal set for x509 certificate parsing:
 * SEQUENCE, SET, INTEGER, BIT STRING, OCTET STRING, OID, NULL,
 * BOOLEAN, UTCTime, GeneralizedTime, context tags.
 *
 * Written from the DER spec (X.690), not carried from ltc (whose
 * DER library is spread across 59 files). This is a cursor-based
 * zero-allocation parser: all output is either scalars or borrowed
 * pointers into the input buffer.
 */

#ifndef CVMCRYPT_ASN1_DER_H
#define CVMCRYPT_ASN1_DER_H

#include "base/types.h"
#include "math/bignum.h"

/* ------------------------------------------------------------------ */
/* error codes                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    DER_OK = 0,
    DER_ERR_BAD_TAG,
    DER_ERR_BAD_LENGTH,
    DER_ERR_OVERFLOW,
    DER_ERR_TRUNCATED,
    DER_ERR_INVALID,
} DerStatus;

/* ------------------------------------------------------------------ */
/* cursor                                                               */
/* ------------------------------------------------------------------ */

typedef struct DerCursor {
    u8 const* p;     /* current position */
    usize remaining; /* bytes left */
} DerCursor;

/* Initialise a cursor over a buffer. */
CVM_INLINE DerCursor der_cursor_init(u8 const* buf, usize len) {
    return (DerCursor){.p = buf, .remaining = len};
}

/* ------------------------------------------------------------------ */
/* tag and length parsing                                              */
/* ------------------------------------------------------------------ */

/* Read the ASN.1 tag (single byte; no multi-byte tags needed for x509).
 * Returns DER_OK or error. */
DerStatus der_read_tag(DerCursor* c, u8* tag);

/* Read the ASN.1 length (short form or long form).
 * Returns DER_OK or error. */
DerStatus der_read_length(DerCursor* c, usize* length);

/* Read tag + length, returning the content as a new cursor. */
DerStatus der_read_tlv(DerCursor* c, u8 expected_tag, DerCursor* content);

/* ------------------------------------------------------------------ */
/* primitive decoders                                                   */
/* ------------------------------------------------------------------ */

/* INTEGER: positive or negative, arbitrary size. */
DerStatus der_read_integer(DerCursor* c, CvmMpi* out);

/* Small positive INTEGER (fits in u32). */
DerStatus der_read_u32(DerCursor* c, u32* out);

/* BOOLEAN. */
DerStatus der_read_boolean(DerCursor* c, bool* out);

/* NULL (zero-length). */
DerStatus der_read_null(DerCursor* c);

/* OID: returns the raw content bytes (borrowed). */
DerStatus der_read_oid(DerCursor* c, u8 const** oid, usize* oid_len);

/* OCTET STRING: returns borrowed pointer. */
DerStatus der_read_octet_string(DerCursor* c, u8 const** data, usize* len);

/* BIT STRING: returns borrowed pointer + unused-bit count. */
DerStatus der_read_bit_string(DerCursor* c, u8 const** data, usize* len,
                              u8* unused_bits);

/* UTCTime / GeneralizedTime: borrowed pointer to the raw content. */
DerStatus der_read_time(DerCursor* c, u8 const** time, usize* len);

/* Any TLV: skip over it without parsing (for extensions we don't care about). */
DerStatus der_skip_tlv(DerCursor* c);

/* ------------------------------------------------------------------ */
/* constructed type helpers                                             */
/* ------------------------------------------------------------------ */

/* SEQUENCE: returns cursor over the content. */
CVM_INLINE DerStatus der_read_sequence(DerCursor* c, DerCursor* content) {
    return der_read_tlv(c, 0x30, content);
}

/* SET: returns cursor over the content. */
CVM_INLINE DerStatus der_read_set(DerCursor* c, DerCursor* content) {
    return der_read_tlv(c, 0x31, content);
}

/* Context-specific [n] constructed: tag = 0xA0 + n. */
CVM_INLINE DerStatus der_read_ctx(DerCursor* c, u8 n, DerCursor* content) {
    return der_read_tlv(c, (u8)(0xA0 + n), content);
}

#endif /* CVMCRYPT_ASN1_DER_H */
