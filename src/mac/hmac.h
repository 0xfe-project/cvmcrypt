/*
 * src/mac/hmac.h
 *
 * HMAC (RFC 2104) over SHA-256 and SHA-512.
 *
 * Carried over from libtomcrypt's mac/hmac/  (Unlicense), rewritten
 * to cvm's conventions. libtomcrypt routes through a descriptor table
 * and allocates its scratch buffers; cvmcrypt has exactly two hashes
 * to support and does it on the stack.
 *
 * HMAC is: inner = H(key^0x36 pad || msg); outer = H(key^0x5C pad || inner).
 * The key is hashed first when longer than the block size.
 */

#ifndef CVMCRYPT_MAC_HMAC_H
#define CVMCRYPT_MAC_HMAC_H

#include "base/types.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

/* ------------------------------------------------------------------ */
/* HMAC-SHA-256                                                        */
/* ------------------------------------------------------------------ */

typedef struct CvmcryptHmacSha256 {
    CvmcryptSha256 inner;
    u8 key[64]; /* SHA-256 block size */
} CvmcryptHmacSha256;

void cvmcrypt_hmac_sha256_init(CvmcryptHmacSha256* h, u8 const* key, usize keylen);
void cvmcrypt_hmac_sha256_update(CvmcryptHmacSha256* h, u8 const* data, usize len);
void cvmcrypt_hmac_sha256_final(CvmcryptHmacSha256* h, u8 out[32]);
void cvmcrypt_hmac_sha256(u8 const* key, usize keylen, u8 const* data, usize len,
                          u8 out[32]);

/* ------------------------------------------------------------------ */
/* HMAC-SHA-512                                                        */
/* ------------------------------------------------------------------ */

typedef struct CvmcryptHmacSha512 {
    CvmcryptSha512 inner;
    u8 key[128]; /* SHA-512 block size */
} CvmcryptHmacSha512;

void cvmcrypt_hmac_sha512_init(CvmcryptHmacSha512* h, u8 const* key, usize keylen);
void cvmcrypt_hmac_sha512_update(CvmcryptHmacSha512* h, u8 const* data, usize len);
void cvmcrypt_hmac_sha512_final(CvmcryptHmacSha512* h, u8 out[64]);
void cvmcrypt_hmac_sha512(u8 const* key, usize keylen, u8 const* data, usize len,
                          u8 out[64]);

#endif /* CVMCRYPT_MAC_HMAC_H */
