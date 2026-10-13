/*
 * src/x509/x509.c
 *
 * X.509 certificate parser (RFC 5280 subset). Written from the spec,
 * using cvmcrypt's DER decoder, bignum, and RSA verify.
 */

#include "x509/x509.h"

#include "base/mem.h"
#include "base/secure.h"
#include "asn1/der.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

/* strlen replacement (no libc in freestanding). */
static usize xstrlen(char const* s) {
    usize n = 0;
    while (s[n] != 0)
        n++;
    return n;
}

void cvmcrypt_x509_init(CvmX509Cert* cert) {
    memset(cert, 0, sizeof(*cert));
    cert->path_len = -1;
    cvmcrypt_rsa_init(&cert->rsa_key);
}

void cvmcrypt_x509_free(CvmX509Cert* cert) {
    cvmcrypt_rsa_free(&cert->rsa_key);
    memset(cert, 0, sizeof(*cert));
    cert->path_len = -1;
}

static X509SigAlg parse_sig_alg(u8 const* oid, usize oid_len) {
    if (oid_len == 9 && memcmp(oid, "\x2a\x86\x48\x86\xf7\x0d\x01\x01", 8) == 0) {
        switch (oid[8]) {
        case 0x0b:
            return X509_SIG_RSA_SHA256;
        case 0x0c:
            return X509_SIG_RSA_SHA384;
        case 0x0d:
            return X509_SIG_RSA_SHA512;
        }
    }
    if (oid_len == 8 && memcmp(oid, "\x2a\x86\x48\xce\x3d\x04\x03", 7) == 0) {
        switch (oid[7]) {
        case 2:
            return X509_SIG_ECDSA_SHA256;
        case 3:
            return X509_SIG_ECDSA_SHA384;
        }
    }
    return X509_SIG_UNKNOWN;
}

static i64 parse_time(u8 const* time, usize len) {
    if (len < 10)
        return 0;
    i32 year, month, day, hour, min, sec = 0;
    if (len == 13 && time[12] == 'Z') {
        year = (time[0] - '0') * 10 + (time[1] - '0');
        if (year < 50)
            year += 2000;
        else
            year += 1900;
        time += 2;
    } else if (len == 15 && time[14] == 'Z') {
        year = (time[0] - '0') * 1000 + (time[1] - '0') * 100 + (time[2] - '0') * 10 +
               (time[3] - '0');
        time += 4;
    } else {
        return 0;
    }
    month = (time[0] - '0') * 10 + (time[1] - '0');
    day = (time[2] - '0') * 10 + (time[3] - '0');
    hour = (time[4] - '0') * 10 + (time[5] - '0');
    min = (time[6] - '0') * 10 + (time[7] - '0');
    if (len >= 12)
        sec = (time[8] - '0') * 10 + (time[9] - '0');

    i64 days = (i64)(year - 1970) * 365;
    for (i32 y = 1970; y < year; y++) {
        if ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)
            days++;
    }
    static i32 const cum[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    if (month >= 1 && month <= 12)
        days += cum[month - 1];
    if (month > 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0))
        days++;
    days += day - 1;
    return days * 86400 + hour * 3600 + min * 60 + sec;
}

/* Capture the raw DER of a TLV (tag + length + content). */
static usize der_tlv_span(DerCursor* c, u8 const** start) {
    *start = c->p;
    return der_skip_tlv(c) == DER_OK ? (usize)(c->p - *start) : 0;
}

X509Status cvmcrypt_x509_parse(CvmX509Cert* cert, u8 const* der, usize derlen) {
    DerCursor c = der_cursor_init(der, derlen);
    DerCursor seq, tbs, cur;

    if (der_read_sequence(&c, &seq) != DER_OK)
        return cert->status = X509_ERR_PARSE;
    if (der_read_sequence(&seq, &tbs) != DER_OK)
        return cert->status = X509_ERR_PARSE;

    /* Record TBS full TLV span (tag+length+content). */
    cert->tbs_start = tbs.p;
    /* After reading SEQUENCE, tbs.p is the content start and tbs.remaining
     * is the content length. The full TLV adds the tag and length bytes. */
    {
        usize tbs_content_len = tbs.remaining;
        usize hdr = (tbs_content_len < 0x80)      ? 2
                    : (tbs_content_len < 0x100)   ? 3
                    : (tbs_content_len < 0x10000) ? 4
                                                  : 5;
        cert->tbs_start = tbs.p - hdr;
        cert->tbs_len = hdr + tbs_content_len;
    }

    cur = tbs;

    /* version [0] EXPLICIT (optional) */
    {
        DerCursor sv = cur;
        if (der_read_ctx(&cur, 0, NULL) != DER_OK)
            cur = sv;
    }

    /* serialNumber — raw bytes */
    {
        u8 tag;
        usize len;
        if (der_read_tag(&cur, &tag) != DER_OK || tag != 0x02)
            return cert->status = X509_ERR_PARSE;
        if (der_read_length(&cur, &len) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        cert->serial = cur.p;
        cert->serial_len = len;
        cur.p += len;
        cur.remaining -= len;
    }

    /* signature AlgorithmIdentifier — skip */
    if (der_skip_tlv(&cur) != DER_OK)
        return cert->status = X509_ERR_PARSE;

    /* issuer Name — raw DER */
    cert->issuer_der_len = der_tlv_span(&cur, &cert->issuer_der);

    /* validity — parse times */
    {
        DerCursor val;
        if (der_read_sequence(&cur, &val) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        u8 const* t1;
        usize l1;
        if (der_read_time(&val, &t1, &l1) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        cert->not_before = parse_time(t1, l1);
        u8 const* t2;
        usize l2;
        if (der_read_time(&val, &t2, &l2) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        cert->not_after = parse_time(t2, l2);
    }

    /* subject Name — raw DER */
    cert->subject_der_len = der_tlv_span(&cur, &cert->subject_der);

    /* subjectPublicKeyInfo — raw DER */
    cert->spki_der_len = der_tlv_span(&cur, &cert->spki_der);

    /* issuerUniqueID [1] (optional) */
    {
        DerCursor sv = cur;
        if (der_read_ctx(&cur, 1, NULL) != DER_OK)
            cur = sv;
    }
    /* subjectUniqueID [2] (optional) */
    {
        DerCursor sv = cur;
        if (der_read_ctx(&cur, 2, NULL) != DER_OK)
            cur = sv;
    }

    /* extensions [3] EXPLICIT (optional) */
    {
        DerCursor ext_seq;
        if (der_read_ctx(&cur, 3, &ext_seq) == DER_OK) {
            DerCursor ext;
            if (der_read_sequence(&ext_seq, &ext) == DER_OK) {
                while (ext.remaining > 0) {
                    DerCursor item;
                    if (der_read_sequence(&ext, &item) != DER_OK)
                        break;
                    u8 const* oid;
                    usize oid_len;
                    if (der_read_oid(&item, &oid, &oid_len) != DER_OK)
                        break;
                    {
                        bool b;
                        DerCursor sv = item;
                        if (der_read_boolean(&item, &b) != DER_OK)
                            item = sv;
                    }
                    u8 const* val;
                    usize val_len;
                    if (der_read_octet_string(&item, &val, &val_len) != DER_OK)
                        break;

                    /* SAN: 2.5.29.17 */
                    if (oid_len == 3 && memcmp(oid, "\x55\x1d\x11", 3) == 0) {
                        cert->san_der = val;
                        cert->san_der_len = val_len;
                    }
                    /* basicConstraints: 2.5.29.19 */
                    else if (oid_len == 3 && memcmp(oid, "\x55\x1d\x13", 3) == 0) {
                        DerCursor bc = der_cursor_init(val, val_len);
                        DerCursor bc_seq;
                        if (der_read_sequence(&bc, &bc_seq) == DER_OK) {
                            bool cA = false;
                            DerCursor sv = bc_seq;
                            if (der_read_boolean(&bc_seq, &cA) == DER_OK)
                                cert->is_ca = cA;
                            else
                                bc_seq = sv;
                            u32 pl;
                            sv = bc_seq;
                            if (der_read_u32(&bc_seq, &pl) == DER_OK)
                                cert->path_len = (i32)pl;
                        }
                    }
                }
            }
        }
    }

    /* signatureAlgorithm */
    {
        DerCursor algo;
        if (der_read_sequence(&seq, &algo) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        u8 const* oid;
        usize oid_len;
        if (der_read_oid(&algo, &oid, &oid_len) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        cert->sig_alg = parse_sig_alg(oid, oid_len);
    }

    /* signature BIT STRING */
    {
        u8 const* sig;
        usize sig_len;
        u8 unused;
        if (der_read_bit_string(&seq, &sig, &sig_len, &unused) != DER_OK)
            return cert->status = X509_ERR_PARSE;
        cert->sig = sig;
        cert->sig_len = sig_len;
    }

    /* Parse the RSA public key. */
    if (cert->spki_der != NULL && cert->spki_der_len > 0) {
        if (cvmcrypt_rsa_import_spki(&cert->rsa_key, cert->spki_der,
                                     cert->spki_der_len)) {
            cert->pk_type = X509_PK_RSA;
        } else {
            cert->pk_type = X509_PK_UNKNOWN;
        }
    }

    return cert->status = X509_OK;
}

X509Status cvmcrypt_x509_verify_signature(CvmX509Cert const* cert,
                                          CvmX509Cert const* issuer) {
    if (cert->sig_alg == X509_SIG_UNKNOWN)
        return X509_ERR_UNSUPPORTED_ALG;
    if (issuer->pk_type != X509_PK_RSA)
        return X509_ERR_UNSUPPORTED_ALG;

    u8 hash[64];
    usize hash_len;
    CvmRsaHashId hash_id;

    switch (cert->sig_alg) {
    case X509_SIG_RSA_SHA256: {
        hash_id = CVMCRYPT_RSA_HASH_SHA256;
        hash_len = 32;
        CvmcryptSha256 h;
        cvmcrypt_sha256_init(&h);
        cvmcrypt_sha256_update(&h, cert->tbs_start, cert->tbs_len);
        cvmcrypt_sha256_final(&h, hash);
        break;
    }
    case X509_SIG_RSA_SHA384: {
        hash_id = CVMCRYPT_RSA_HASH_SHA384;
        hash_len = 48;
        CvmcryptSha512 h;
        cvmcrypt_sha384_init(&h);
        cvmcrypt_sha512_update(&h, cert->tbs_start, cert->tbs_len);
        cvmcrypt_sha384_final(&h, hash);
        break;
    }
    case X509_SIG_RSA_SHA512: {
        hash_id = CVMCRYPT_RSA_HASH_SHA512;
        hash_len = 64;
        CvmcryptSha512 h;
        cvmcrypt_sha512_init(&h);
        cvmcrypt_sha512_update(&h, cert->tbs_start, cert->tbs_len);
        cvmcrypt_sha512_final(&h, hash);
        break;
    }
    default:
        return X509_ERR_UNSUPPORTED_ALG;
    }

    return cvmcrypt_rsa_verify_pkcs1_v15(&issuer->rsa_key, hash_id, hash, hash_len,
                                         cert->sig, cert->sig_len)
               ? X509_OK
               : X509_ERR_BAD_SIGNATURE;
}

X509Status cvmcrypt_x509_check_validity(CvmX509Cert const* cert, i64 now) {
    if (now < cert->not_before)
        return X509_ERR_NOT_YET_VALID;
    if (now > cert->not_after)
        return X509_ERR_EXPIRED;
    return X509_OK;
}

static bool hostname_match(u8 const* pat, usize plen, char const* host, usize hlen) {
    if (plen == hlen) {
        for (usize i = 0; i < plen; i++) {
            u8 p = pat[i];
            char h = (char)host[i];
            if (p >= 'A' && p <= 'Z')
                p += 32;
            if (h >= 'A' && h <= 'Z')
                h += 32;
            if (p != (u8)h)
                return false;
        }
        return true;
    }
    /* Wildcard: *.example.com */
    if (plen >= 3 && pat[0] == '*' && pat[1] == '.') {
        pat += 2;
        plen -= 2;
        char const* suffix = host;
        while (*suffix && *suffix != '.')
            suffix++;
        if (*suffix)
            suffix++;
        usize slen = xstrlen(suffix);
        if (slen != plen)
            return false;
        for (usize i = 0; i < plen; i++) {
            u8 p = pat[i];
            char h = suffix[i];
            if (p >= 'A' && p <= 'Z')
                p += 32;
            if (h >= 'A' && h <= 'Z')
                h += 32;
            if (p != (u8)h)
                return false;
        }
        return true;
    }
    return false;
}

X509Status cvmcrypt_x509_check_hostname(CvmX509Cert const* cert, char const* hostname) {
    usize hlen = xstrlen(hostname);
    if (cert->san_der != NULL && cert->san_der_len > 0) {
        DerCursor san = der_cursor_init(cert->san_der, cert->san_der_len);
        DerCursor seq;
        if (der_read_sequence(&san, &seq) == DER_OK) {
            while (seq.remaining > 0) {
                DerCursor t = seq;
                u8 tag;
                usize len;
                if (der_read_tag(&t, &tag) != DER_OK ||
                    der_read_length(&t, &len) != DER_OK)
                    break;
                if (tag == 0x82) { /* dNSName */
                    if (hostname_match(t.p, len, hostname, hlen))
                        return X509_OK;
                }
                t.p += len;
                t.remaining -= len;
                seq = t;
            }
            return X509_ERR_HOSTNAME_MISMATCH;
        }
    }
    return X509_ERR_HOSTNAME_MISMATCH;
}

X509Status cvmcrypt_x509_verify(CvmX509Cert const* cert, CvmX509Cert const* issuer,
                                char const* hostname, i64 now) {
    X509Status st;
    if ((st = cvmcrypt_x509_check_validity(cert, now)) != X509_OK)
        return st;
    if (hostname != NULL) {
        if ((st = cvmcrypt_x509_check_hostname(cert, hostname)) != X509_OK)
            return st;
    }
    if (issuer != NULL) {
        if (!issuer->is_ca)
            return X509_ERR_NOT_CA;
        if (cert->issuer_der_len != issuer->subject_der_len ||
            memcmp(cert->issuer_der, issuer->subject_der, cert->issuer_der_len) != 0)
            return X509_ERR_NO_TRUST_ANCHOR;
        if ((st = cvmcrypt_x509_verify_signature(cert, issuer)) != X509_OK)
            return st;
    }
    return X509_OK;
}
