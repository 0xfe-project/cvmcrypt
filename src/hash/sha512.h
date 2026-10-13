/*
 * src/hash/sha512.h
 *
 * SHA-512 and SHA-384, per FIPS 180-4. SHA-384 is SHA-512 with a
 * different IV and a truncated digest; the compression function and
 * the padding are shared, so one struct and one set of functions.
 *
 * Carried over from libtomcrypt's sha512.c and sha384_desc.c
 * (Unlicense), rewritten to cvm's conventions.
 *
 * SIMD: aarch64 has SHA512H/SHA512H2/SHA512SU0/SHA512SU1 (FEAT_SHA512,
 * ARMv8.2); clang has no intrinsic so we use inline asm like mbedtls
 * does. x86 has no widely-available SHA-512 instruction, so scalar
 * only there.
 */

#ifndef CVMCRYPT_HASH_SHA512_H
#define CVMCRYPT_HASH_SHA512_H

#include "base/types.h"

#define CVMCRYPT_SHA512_BLOCK_SIZE ((usize)128)
#define CVMCRYPT_SHA512_DIGEST_SIZE ((usize)64)
#define CVMCRYPT_SHA384_DIGEST_SIZE ((usize)48)

typedef struct CvmcryptSha512 {
    u64 state[8];
    u64 length;
    usize curlen;
    u8 buf[128];
    u8 impl;
} CvmcryptSha512;

enum {
    CVMCRYPT_SHA512_IMPL_SCALAR = 0,
    CVMCRYPT_SHA512_IMPL_ARM64 = 1, /* FEAT_SHA512, ARMv8.2+ */
};

/* SHA-512 */
void cvmcrypt_sha512_init(CvmcryptSha512* md);
void cvmcrypt_sha512_update(CvmcryptSha512* md, u8 const* data, usize len);
void cvmcrypt_sha512_final(CvmcryptSha512* md, u8 out[64]);
void cvmcrypt_sha512(u8 const* data, usize len, u8 out[64]);

/* SHA-384: shared state, different IV and digest length */
void cvmcrypt_sha384_init(CvmcryptSha512* md);
void cvmcrypt_sha384_final(CvmcryptSha512* md, u8 out[48]);
void cvmcrypt_sha384(u8 const* data, usize len, u8 out[48]);

/* update is the same for both */
#define cvmcrypt_sha384_update cvmcrypt_sha512_update

#endif /* CVMCRYPT_HASH_SHA512_H */
