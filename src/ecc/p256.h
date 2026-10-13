/*
 * src/ecc/p256.h
 *
 * NIST P-256 (secp256r1) elliptic curve operations + ECDSA verify.
 * Written from SEC 2 / FIPS 186-4, using cvmcrypt bignum.
 * Points in Jacobian coordinates: (x,y) = (X/Z^2, Y/Z^3).
 */

#ifndef CVMCRYPT_ECC_P256_H
#define CVMCRYPT_ECC_P256_H

#include "base/types.h"
#include "math/bignum.h"

#define P256_BYTES 32

/* ECDSA public key (affine point on the curve). */
typedef struct CvmEcPoint {
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

/* Import uncompressed EC point from SPKI BIT STRING (04 || X || Y, 65 bytes). */
EcStatus cvmcrypt_ec_import_point(CvmEcPoint* pt, u8 const* buf, usize buflen);

/* ECDSA verify (FIPS 186-4):
 * Check that (r,s) is a valid signature of `hash` (hash_len bytes)
 * under public key `q` on P-256. */
bool cvmcrypt_ecdsa_verify(CvmEcPoint const* q, u8 const* hash, usize hash_len,
                           u8 const* r, usize r_len, u8 const* s, usize s_len);

/* EC SPKI import: parse SubjectPublicKeyInfo, extract the point. */
EcStatus cvmcrypt_ec_import_spki(CvmEcPoint* pt, u8 const* der, usize derlen);

#endif /* CVMCRYPT_ECC_P256_H */
