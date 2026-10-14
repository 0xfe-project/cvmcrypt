/*
 * src/tls/record.c
 *
 * TLS 1.3 record layer (RFC 8446 §5).
 * Ported from picotls to cvm conventions. TLS 1.2 paths removed.
 */

#include "tls/tls_internal.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* buffer                                                               */
/* ------------------------------------------------------------------ */

void cvm_tls_buf_init(CvmTlsBuf* buf, u8* small, usize small_capacity) {
    buf->base = small;
    buf->capacity = small_capacity;
    buf->off = 0;
    buf->is_allocated = false;
}

int cvm_tls_buf_reserve(CvmTlsBuf* buf, usize delta) {
    if (buf->capacity < buf->off + delta) {
        usize new_capacity = buf->capacity * 2;
        if (new_capacity < buf->off + delta)
            new_capacity = buf->off + delta;
        u8* new_base = rt_mem_alloc(new_capacity);
        if (new_base == NULL)
            return TLS_ERROR_NO_MEMORY;
        memcpy(new_base, buf->base, buf->off);
        if (buf->is_allocated)
            rt_mem_free(buf->base);
        buf->base = new_base;
        buf->capacity = new_capacity;
        buf->is_allocated = true;
    }
    return 0;
}

int cvm_tls_buf_pushv(CvmTlsBuf* buf, void const* src, usize len) {
    int ret;
    if ((ret = cvm_tls_buf_reserve(buf, len)) != 0)
        return ret;
    memcpy(buf->base + buf->off, src, len);
    buf->off += len;
    return 0;
}

int cvm_tls_buf_push(CvmTlsBuf* buf, u8 b) {
    return cvm_tls_buf_pushv(buf, &b, 1);
}

void cvm_tls_buf_dispose(CvmTlsBuf* buf) {
    if (buf->is_allocated) {
        cvmcrypt_secure_free(buf->base, buf->capacity);
        buf->is_allocated = false;
    }
    buf->base = NULL;
    buf->capacity = 0;
    buf->off = 0;
}

/* ------------------------------------------------------------------ */
/* record parsing                                                       */
/* ------------------------------------------------------------------ */

int cvm_tls_parse_record_header(CvmTlsRecord* rec, u8 const* src) {
    rec->type = src[0];
    rec->length = (u16)(src[3] << 8 | src[4]);
    rec->fragment = NULL;
    /* length is 16-bit; check for oversized */
    if (rec->length > TLS_MAX_ENCRYPTED_RECORD_SIZE)
        return TLS_ALERT_RECORD_OVERFLOW;
    return 0;
}

int cvm_tls_parse_record(CvmTlsRecord* rec, u8 const* src, usize* len,
                         CvmTlsBuf* pending) {
    int ret;

    /* Validate content type first. */
    if (pending->base == NULL || pending->off == 0) {
        switch (src[0]) {
        case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        case TLS_CONTENT_TYPE_ALERT:
        case TLS_CONTENT_TYPE_HANDSHAKE:
        case TLS_CONTENT_TYPE_APPDATA:
            break;
        default:
            return TLS_ALERT_DECODE_ERROR;
        }
    }

    /* Fast path: complete record in the input. */
    if ((pending->base == NULL || pending->off == 0) && *len >= 5) {
        if ((ret = cvm_tls_parse_record_header(rec, src)) != 0)
            return ret;
        if (5 + rec->length <= *len) {
            rec->fragment = src + 5;
            *len = rec->length + 5;
            return 0;
        }
    }

    /* Slow path: buffer partial record. */
    u8 const* end = src + *len;
    rec->type = 0;
    rec->length = 0;
    rec->fragment = NULL;

    if (pending->base == NULL || pending->off == 0) {
        cvm_tls_buf_init(pending, NULL, 0);
        if ((ret = cvm_tls_buf_reserve(pending, 5)) != 0)
            return ret;
    }

    /* Fill header. */
    while (pending->off < 5) {
        if (src == end)
            return TLS_ERROR_IN_PROGRESS;
        pending->base[pending->off++] = *src++;
    }
    if ((ret = cvm_tls_parse_record_header(rec, pending->base)) != 0)
        return ret;

    /* Fill fragment. */
    usize addlen = rec->length + 5 - pending->off;
    if (addlen != 0) {
        if ((ret = cvm_tls_buf_reserve(pending, addlen)) != 0)
            return ret;
        if (addlen > (usize)(end - src))
            addlen = (usize)(end - src);
        if (addlen != 0) {
            memcpy(pending->base + pending->off, src, addlen);
            pending->off += addlen;
            src += addlen;
        }
    }

    /* Complete? */
    if (pending->off == rec->length + 5) {
        rec->fragment = pending->base + 5;
        ret = 0;
    } else {
        ret = TLS_ERROR_IN_PROGRESS;
    }

    *len -= (usize)(end - src);
    return ret;
}

/* ------------------------------------------------------------------ */
/* AEAD encrypt/decrypt                                                 */
/* ------------------------------------------------------------------ */

usize cvm_tls_aead_encrypt(CvmTlsTrafficProt* ctx, u8* output, u8 const* input,
                           usize inlen, u8 content_type) {
    /* Build AAD: [23, 3, 3, len_hi, len_lo] */
    u8 aad[5];
    usize encrypted_len = inlen + 1 + ctx->aead->algo->tag_size;
    tls_build_aad(aad, encrypted_len);

    /* Build the plaintext: input || content_type. */
    /* Copy into output then encrypt in-place. */
    memcpy(output, input, inlen);
    output[inlen] = content_type;

    ctx->aead->do_encrypt(ctx->aead, output, output, inlen + 1, ctx->seq++, aad, 5);
    return encrypted_len;
}

int cvm_tls_aead_decrypt(CvmTlsTrafficProt* ctx, u8* output, usize* outlen,
                         u8* content_type, u8 const* input, usize inlen) {
    u8 aad[5];
    tls_build_aad(aad, inlen);

    usize ptlen =
        ctx->aead->do_decrypt(ctx->aead, output, input, inlen, ctx->seq, aad, 5);
    if (ptlen == (usize)-1)
        return TLS_ALERT_BAD_RECORD_MAC;
    ctx->seq++;

    if (ptlen == 0)
        return TLS_ALERT_DECODE_ERROR;

    /* Strip the content type byte. */
    *content_type = output[ptlen - 1];
    *outlen = ptlen - 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* record emission                                                      */
/* ------------------------------------------------------------------ */

int cvm_tls_push_encrypted_records(CvmTlsBuf* buf, u8 type, u8 const* src, usize len,
                                   CvmTlsTrafficProt* enc) {
    int ret = 0;

    while (len != 0) {
        usize chunk_size = len;
        if (chunk_size > TLS_MAX_PLAINTEXT_RECORD_SIZE)
            chunk_size = TLS_MAX_PLAINTEXT_RECORD_SIZE;

        /* Write record header (placeholder length, will fix). */
        if ((ret = cvm_tls_buf_push(buf, TLS_CONTENT_TYPE_APPDATA)) != 0)
            goto Exit;
        if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
            goto Exit;
        if ((ret = cvm_tls_buf_push(buf, 3)) != 0)
            goto Exit;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            goto Exit;
        if ((ret = cvm_tls_buf_push(buf, 0)) != 0)
            goto Exit;

        /* Encrypt the body. */
        usize overhead = 1 + enc->aead->algo->tag_size;
        if ((ret = cvm_tls_buf_reserve(buf, chunk_size + overhead)) != 0)
            goto Exit;
        usize enc_len =
            cvm_tls_aead_encrypt(enc, buf->base + buf->off, src, chunk_size, type);
        buf->off += enc_len;

        /* Fix the record length field. */
        buf->base[buf->off - enc_len - 2] = (u8)(enc_len >> 8);
        buf->base[buf->off - enc_len - 1] = (u8)enc_len;

        src += chunk_size;
        len -= chunk_size;
    }

Exit:
    return ret;
}

int cvm_tls_encrypt_record(CvmTlsBuf* buf, usize rec_start, CvmTlsTrafficProt* enc) {
    usize bodylen = buf->off - rec_start - 5;
    u8 type = buf->base[rec_start];
    int ret;

    /* Fast path: single record, encrypt in-place. */
    if (bodylen <= TLS_MAX_PLAINTEXT_RECORD_SIZE) {
        usize overhead = 1 + enc->aead->algo->tag_size;
        if ((ret = cvm_tls_buf_reserve(buf, overhead)) != 0)
            return ret;
        usize enc_len = cvm_tls_aead_encrypt(enc, buf->base + rec_start + 5,
                                             buf->base + rec_start + 5, bodylen, type);
        buf->off += overhead;
        buf->base[rec_start] = TLS_CONTENT_TYPE_APPDATA;
        buf->base[rec_start + 3] = (u8)(enc_len >> 8);
        buf->base[rec_start + 4] = (u8)enc_len;
        return 0;
    }

    /* Slow path: multiple records. Copy to temp, re-emit. */
    u8* tmp = rt_mem_alloc(bodylen);
    if (tmp == NULL)
        return TLS_ERROR_NO_MEMORY;
    memcpy(tmp, buf->base + rec_start + 5, bodylen);
    cvmcrypt_secure_free(buf->base + rec_start, bodylen + 5);
    buf->off = rec_start;

    ret = cvm_tls_push_encrypted_records(buf, type, tmp, bodylen, enc);

    cvmcrypt_secure_free(tmp, bodylen);
    return ret;
}
