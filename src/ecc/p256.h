/*
 * src/ecc/p256.h
 *
 * NIST P-256 / P-384 elliptic curve operations + ECDSA verify.
 * Written from SEC 2 / FIPS 186-4, using cvmcrypt bignum.
 * Points in Jacobian coordinates: (x,y) = (X/Z^2, Y/Z^3).
 */

#ifndef CVMCRYPT_ECC_P256_H
#define CVMCRYPT_ECC_P256_H

#include "base/types.h"
#include "math/bignum.h"

typedef enum {
    EC_CURVE_P256 = 0, /* secp256r1, 32-byte coords */
    EC_CURVE_P384,     /* secp384r1, 48-byte coords */
} CvmEcCurveId;

/* ECDSA public key (affine point on the curve). */
typedef struct CvmEcPoint {
    CvmEcCurveId curve;
    CvmMpi x;
    CvmMpi y;
} CvmEcPoint;

typedef enum {
    EC_OK = 0,
    EC_ERR_PARSE,
    EC_ERR_BAD_POINT,
    EC_ERR_BAD_SIG,
    EC_ERR_MATH,
} EcStatus;

void cvmcrypt_ec_init(CvmEcPoint* pt);
void cvmcrypt_ec_free(CvmEcPoint* pt);

/* Import uncompressed EC point (04 || X || Y). Detects curve from size:
 * 65 bytes → P-256, 97 bytes → P-384. */
EcStatus cvmcrypt_ec_import_point(CvmEcPoint* pt, u8 const* buf, usize buflen);

/* ECDSA verify (FIPS 186-4). Uses the curve from `q->curve`. */
bool cvmcrypt_ecdsa_verify(CvmEcPoint const* q, u8 const* hash, usize hash_len,
                           u8 const* r, usize r_len, u8 const* s, usize s_len);

/* EC SPKI import: parse SubjectPublicKeyInfo, extract the point.
 * Accepts P-256 (1.2.840.10045.3.1.7) and P-384 (1.3.132.0.34). */
EcStatus cvmcrypt_ec_import_spki(CvmEcPoint* pt, u8 const* der, usize derlen);

#endif /* CVMCRYPT_ECC_P256_H */

/* ------------------------------------------------------------------ */
/* ECDSA sign (server side)                                             */
/* ------------------------------------------------------------------ */

typedef struct CvmEcPriv {
    CvmEcCurveId curve;
    CvmMpi d; /* private scalar */
} CvmEcPriv;

void cvmcrypt_ec_priv_init(CvmEcPriv* key);
void cvmcrypt_ec_priv_free(CvmEcPriv* key);

/* Import EC private key from PKCS#8 DER (contains ECPrivateKey). */
EcStatus cvmcrypt_ec_priv_import_pkcs8(CvmEcPriv* key, u8 const* der, usize derlen);

/* ECDSA sign (FIPS 186-4). Caller provides the random k (nonce).
 * r/s output buffers must be coord_len bytes (32 for P-256, 48 for P-384).
 * Returns true on success. */
bool cvmcrypt_ecdsa_sign(CvmEcPriv const* key, u8 const* hash, usize hash_len,
                         u8 const* k, usize k_len, /* random nonce */
                         u8* r_out, u8* s_out);    /* coord_len each */
