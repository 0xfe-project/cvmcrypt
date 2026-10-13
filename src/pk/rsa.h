/*
 * src/pk/rsa.h
 *
 * RSA public key operations: import (SPKI/DER), verify (PKCS#1 v1.5
 * and PSS). Written from PKCS#1 v2.2 (RFC 8017).
 *
 * Only verify-side: no key generation, no signing, no decryption
 * (we are a TLS client, not a server).
 */

#ifndef CVMCRYPT_PK_RSA_H
#define CVMCRYPT_PK_RSA_H

#include "base/types.h"
#include "math/bignum.h"

typedef struct CvmRsaKey {
    CvmMpi n; /* modulus */
    CvmMpi e; /* public exponent */
} CvmRsaKey;

typedef enum {
    CVMCRYPT_RSA_HASH_SHA256 = 0,
    CVMCRYPT_RSA_HASH_SHA384,
    CVMCRYPT_RSA_HASH_SHA512,
} CvmRsaHashId;

/* Initialise / free. */
void cvmcrypt_rsa_init(CvmRsaKey* key);
void cvmcrypt_rsa_free(CvmRsaKey* key);

/* Import a public key from SPKI DER (the format in x509 SPKI field).
 * Returns false on parse error. */
bool cvmcrypt_rsa_import_spki(CvmRsaKey* key, u8 const* der, usize derlen);

/* Verify PKCS#1 v1.5 signature (RSASSA-PKCS1-V1_5-VERIFY, RFC 8017 §8.2.2).
 * hash_id selects the hash; hash is the pre-computed digest.
 * Returns true if the signature is valid. */
bool cvmcrypt_rsa_verify_pkcs1_v15(CvmRsaKey const* key, CvmRsaHashId hash_id,
                                   u8 const* hash, usize hashlen, u8 const* sig,
                                   usize siglen);

/* Verify PSS signature (RSASSA-PSS-VERIFY, RFC 8017 §8.1.2).
 * Uses MGF1 with the same hash, salt_len = hash_len.
 * Returns true if the signature is valid. */
bool cvmcrypt_rsa_verify_pss(CvmRsaKey const* key, CvmRsaHashId hash_id, u8 const* hash,
                             usize hashlen, u8 const* sig, usize siglen);

/* Compute RSA operation: result = sig^e mod n. Used by both verify paths. */
bool cvmcrypt_rsa_public(CvmMpi* result, CvmMpi const* sig, CvmRsaKey const* key);

#endif /* CVMCRYPT_PK_RSA_H */
