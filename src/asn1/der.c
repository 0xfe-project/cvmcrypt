/*
 * src/asn1/der.c
 *
 * ASN.1 DER decoder, written from X.690. Zero allocation: all output
 * is scalars or borrowed pointers into the input buffer, except
 * INTEGER which writes into a caller-provided CvmMpi.
 */

#include "asn1/der.h"

#include "base/mem.h"

/* ------------------------------------------------------------------ */
/* tag and length                                                       */
/* ------------------------------------------------------------------ */

DerStatus der_read_tag(DerCursor* c, u8* tag) {
    if (c->remaining < 1)
        return DER_ERR_TRUNCATED;
    *tag = c->p[0];
    c->p++;
    c->remaining--;
    return DER_OK;
}

DerStatus der_read_length(DerCursor* c, usize* length) {
    if (c->remaining < 1)
        return DER_ERR_TRUNCATED;

    u8 b = c->p[0];
    c->p++;
    c->remaining--;

    if (b < 0x80) {
        /* Short form: length is the byte itself. */
        *length = b;
        return DER_OK;
    }

    /* Long form: b & 0x7F = number of length bytes. */
    usize nbytes = b & 0x7F;
    if (nbytes == 0)
        return DER_ERR_BAD_LENGTH; /* indefinite not allowed in DER */
    if (nbytes > sizeof(usize))
        return DER_ERR_OVERFLOW;
    if (c->remaining < nbytes)
        return DER_ERR_TRUNCATED;

    usize len = 0;
    for (usize i = 0; i < nbytes; i++) {
        len = (len << 8) | c->p[i];
    }
    c->p += nbytes;
    c->remaining -= nbytes;

    *length = len;
    return DER_OK;
}

DerStatus der_read_tlv(DerCursor* c, u8 expected_tag, DerCursor* content) {
    u8 tag;
    usize len;
    DerStatus st;

    if ((st = der_read_tag(c, &tag)) != DER_OK)
        return st;
    if (tag != expected_tag)
        return DER_ERR_BAD_TAG;
    if ((st = der_read_length(c, &len)) != DER_OK)
        return st;
    if (c->remaining < len)
        return DER_ERR_TRUNCATED;

    if (content) {
        content->p = c->p;
        content->remaining = len;
    }
    c->p += len;
    c->remaining -= len;
    return DER_OK;
}

/* ------------------------------------------------------------------ */
/* primitives                                                           */
/* ------------------------------------------------------------------ */

DerStatus der_read_integer(DerCursor* c, CvmMpi* out) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x02, &content);
    if (st != DER_OK)
        return st;

    if (content.remaining == 0)
        return DER_ERR_INVALID;

    /* Check for non-minimal encoding (leading 0x00 followed by a byte
     * that doesn't need the sign bit). DER requires minimal encoding. */
    if (content.remaining > 1 && content.p[0] == 0x00 && (content.p[1] & 0x80) == 0) {
        return DER_ERR_INVALID;
    }

    /* Sign: the FIRST byte (before stripping) determines sign.
     * 0x00 prefix = positive (sign bit set on significant byte).
     * No 0x00 prefix + high bit set = negative (unsupported). */
    bool has_sign_zero = (content.remaining > 1 && content.p[0] == 0x00);
    bool negative = !has_sign_zero && (content.p[0] & 0x80) != 0;
    if (negative)
        return DER_ERR_INVALID;

    u8 const* data = content.p;
    usize len = content.remaining;
    if (has_sign_zero) {
        data++;
        len--;
    }

    if (!cvmcrypt_mpi_read_binary(out, data, len))
        return DER_ERR_OVERFLOW;
    return DER_OK;
}

DerStatus der_read_u32(DerCursor* c, u32* out) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x02, &content);
    if (st != DER_OK)
        return st;

    if (content.remaining == 0 || content.remaining > 5)
        return DER_ERR_INVALID;

    /* Skip leading zero. */
    u8 const* p = content.p;
    usize len = content.remaining;
    if (len > 1 && p[0] == 0x00) {
        p++;
        len--;
    }

    if (len > 4)
        return DER_ERR_OVERFLOW;

    u32 val = 0;
    for (usize i = 0; i < len; i++) {
        val = (val << 8) | p[i];
    }
    *out = val;
    return DER_OK;
}

DerStatus der_read_boolean(DerCursor* c, bool* out) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x01, &content);
    if (st != DER_OK)
        return st;
    if (content.remaining != 1)
        return DER_ERR_INVALID;
    *out = content.p[0] != 0;
    return DER_OK;
}

DerStatus der_read_null(DerCursor* c) {
    return der_read_tlv(c, 0x05, &(DerCursor){0});
}

DerStatus der_read_oid(DerCursor* c, u8 const** oid, usize* oid_len) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x06, &content);
    if (st != DER_OK)
        return st;
    if (content.remaining == 0)
        return DER_ERR_INVALID;
    *oid = content.p;
    *oid_len = content.remaining;
    return DER_OK;
}

DerStatus der_read_octet_string(DerCursor* c, u8 const** data, usize* len) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x04, &content);
    if (st != DER_OK)
        return st;
    *data = content.p;
    *len = content.remaining;
    return DER_OK;
}

DerStatus der_read_bit_string(DerCursor* c, u8 const** data, usize* len,
                              u8* unused_bits) {
    DerCursor content;
    DerStatus st = der_read_tlv(c, 0x03, &content);
    if (st != DER_OK)
        return st;
    if (content.remaining < 1)
        return DER_ERR_INVALID;

    *unused_bits = content.p[0];
    if (*unused_bits > 7)
        return DER_ERR_INVALID;
    *data = content.p + 1;
    *len = content.remaining - 1;
    return DER_OK;
}

DerStatus der_read_time(DerCursor* c, u8 const** time, usize* len) {
    /* UTCTime (0x17) or GeneralizedTime (0x18). Read either. */
    u8 tag;
    usize length;
    DerStatus st;

    if (c->remaining < 1)
        return DER_ERR_TRUNCATED;
    tag = c->p[0];
    if (tag != 0x17 && tag != 0x18)
        return DER_ERR_BAD_TAG;

    c->p++;
    c->remaining--;
    if ((st = der_read_length(c, &length)) != DER_OK)
        return st;
    if (c->remaining < length)
        return DER_ERR_TRUNCATED;

    *time = c->p;
    *len = length;
    c->p += length;
    c->remaining -= length;
    return DER_OK;
}

DerStatus der_skip_tlv(DerCursor* c) {
    /* Read and discard a single TLV (any tag). */
    u8 tag;
    usize len;
    DerStatus st;

    if ((st = der_read_tag(c, &tag)) != DER_OK)
        return st;
    if ((st = der_read_length(c, &len)) != DER_OK)
        return st;
    if (c->remaining < len)
        return DER_ERR_TRUNCATED;
    c->p += len;
    c->remaining -= len;
    return DER_OK;
}
