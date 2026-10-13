/*
 * src/aead/gcm.h
 *
 * AES-GCM per NIST SP 800-38D.
 *
 * Written for cvmcrypt following the spec, not carried from ltc (whose
 * GCM is spread across 10 files with a state machine for incremental
 * feeding). cvmcrypt's GCM is one-shot: set up, encrypt, tag. The
 * GHASH uses the aarch64 PMULL instruction where available, scalar
 * bit-by-bit elsewhere.
 */

#ifndef CVMCRYPT_AEAD_GCM_H
#define CVMCRYPT_AEAD_GCM_H

#include "base/types.h"
#include "cipher/aes.h"

#define CVMCRYPT_GCM_TAG_SIZE ((usize)16)
#define CVMCRYPT_GCM_IV_SIZE ((usize)12)

typedef struct CvmcryptGcm {
    CvmcryptAesKey aes;
    /* Hash subkey H = AES_K(0^128), in GCM byte order. */
    u8 H[16];
    /* Running GHASH accumulator. */
    u8 X[16];
    /* The counter block: J0 padded to 16 bytes. */
    u8 counter[16];
    /* Buffered partial block. */
    u8 buf[16];
    usize buflen;
    /* Total AAD length in bits. */
    u64 aadlen;
    /* Total plaintext length in bits. */
    u64 ptlen;
    /* Which GHASH implementation. */
    u8 impl;
} CvmcryptGcm;

enum {
    CVMCRYPT_GCM_IMPL_SCALAR = 0,
    CVMCRYPT_GCM_IMPL_PMULL = 1, /* aarch64 polynomial multiply */
};

/*
 * One-shot AES-GCM encrypt. Produces ciphertext and a 16-byte tag.
 * iv is 12 bytes (the TLS 1.3 case); other lengths hash the IV.
 * Returns false on failure (bad key length).
 */
bool cvmcrypt_gcm_encrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* pt, usize ptlen,
                          u8* ct, u8 tag[16]);

/*
 * One-shot AES-GCM decrypt. Verifies the tag and produces plaintext.
 * Returns false if the tag does not match (plaintext is zeroised).
 */
bool cvmcrypt_gcm_decrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* ct, usize ctlen,
                          u8* pt, u8 const tag[16]);

#endif /* CVMCRYPT_AEAD_GCM_H */
