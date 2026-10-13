/*
 * src/x509/x509.h
 *
 * X.509 certificate parser and chain verifier (RFC 5280 subset).
 * Zero-allocation: all data is borrowed pointers into the input DER.
 * Written from RFC 5280, using cvmcrypt's DER decoder and bignum.
 */

#ifndef CVMCRYPT_X509_H
#define CVMCRYPT_X509_H

#include "base/types.h"
#include "math/bignum.h"
#include "pk/rsa.h"
#include "ecc/p256.h"

/* ------------------------------------------------------------------ */
/* types                                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    X509_OK = 0,
    X509_ERR_PARSE,
    X509_ERR_EXPIRED,
    X509_ERR_NOT_YET_VALID,
    X509_ERR_HOSTNAME_MISMATCH,
    X509_ERR_BAD_SIGNATURE,
    X509_ERR_NO_TRUST_ANCHOR,
    X509_ERR_NOT_CA,
    X509_ERR_UNSUPPORTED_ALG,
} X509Status;

/* Signature algorithm identifiers (what we can verify). */
typedef enum {
    X509_SIG_RSA_SHA256,   /* 1.2.840.113549.1.1.11 */
    X509_SIG_RSA_SHA384,   /* 1.2.840.113549.1.1.12 */
    X509_SIG_RSA_SHA512,   /* 1.2.840.113549.1.1.13 */
    X509_SIG_ECDSA_SHA256, /* 1.2.840.10045.4.3.2 */
    X509_SIG_ECDSA_SHA384, /* 1.2.840.10045.4.3.3 */
    X509_SIG_UNKNOWN,
} X509SigAlg;

/* Public key type. */
typedef enum {
    X509_PK_RSA,
    X509_PK_EC,
    X509_PK_UNKNOWN,
} X509PkType;

/* A parsed certificate. All byte ranges are BORROWED from the input DER. */
typedef struct CvmX509Cert {
    /* Raw DER fields (borrowed pointers). */
    u8 const* tbs_start; /* start of TBSCertificate content */
    usize tbs_len;       /* length of TBSCertificate content */
    u8 const* serial;    /* serial number bytes */
    usize serial_len;
    u8 const* issuer_der; /* raw DER of the issuer Name */
    usize issuer_der_len;
    u8 const* subject_der; /* raw DER of the subject Name */
    usize subject_der_len;
    u8 const* spki_der; /* raw DER of SubjectPublicKeyInfo */
    usize spki_der_len;
    u8 const* sig; /* signature value bytes */
    usize sig_len;

    /* Parsed validity (Unix timestamps, seconds since epoch). */
    i64 not_before;
    i64 not_after;

    /* Signature algorithm. */
    X509SigAlg sig_alg;

    /* Parsed public key (RSA only for now; EC is a stub). */
    X509PkType pk_type;
    CvmRsaKey rsa_key; /* valid if pk_type == X509_PK_RSA */
    CvmEcPoint ec_key; /* valid if pk_type == X509_PK_EC */

    /* Extension data (borrowed). */
    bool is_ca;        /* basicConstraints CA flag */
    i32 path_len;      /* pathLenConstraint, -1 if absent */
    u8 const* san_der; /* raw DER of SAN extension (may be NULL) */
    usize san_der_len;

    /* Error context. */
    X509Status status;
} CvmX509Cert;

/* ------------------------------------------------------------------ */
/* parse                                                                */
/* ------------------------------------------------------------------ */

/* Parse a DER certificate. Returns X509_OK or error.
 * The cert struct must be initialised with cvmcrypt_x509_init before use. */
void cvmcrypt_x509_init(CvmX509Cert* cert);
void cvmcrypt_x509_free(CvmX509Cert* cert);
X509Status cvmcrypt_x509_parse(CvmX509Cert* cert, u8 const* der, usize derlen);

/* ------------------------------------------------------------------ */
/* verify                                                               */
/* ------------------------------------------------------------------ */

/* Verify cert's signature using the issuer's public key. */
X509Status cvmcrypt_x509_verify_signature(CvmX509Cert const* cert,
                                          CvmX509Cert const* issuer);

/* Check validity period (not_before <= now <= not_after). */
X509Status cvmcrypt_x509_check_validity(CvmX509Cert const* cert, i64 now);

/* Check hostname against the certificate's SAN (dNSName) or CN. */
X509Status cvmcrypt_x509_check_hostname(CvmX509Cert const* cert, char const* hostname);

/* Full chain check: signature + validity + hostname. */
X509Status cvmcrypt_x509_verify(CvmX509Cert const* cert,
                                CvmX509Cert const* issuer, /* NULL = self-signed */
                                char const* hostname, i64 now);

#endif /* CVMCRYPT_X509_H */
