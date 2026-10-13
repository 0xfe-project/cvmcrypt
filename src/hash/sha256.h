/*
 * src/hash/sha256.h
 *
 * SHA-256, per FIPS 180-4.
 *
 * Carried over from libtomcrypt's src/hashes/sha2/sha256.c and
 * sha256_desc.c (Unlicense), rewritten to cvm's conventions:
 *   — u32/u64/usize instead of ulong32/ulong64/unsigned long
 *   — no hash_state union: this hash owns its struct
 *   — no descriptor table: the API is direct
 *   — no X* macros, no LTC_ARGCHK
 *
 * The SIMD layer is not carried from anywhere — libtomcrypt has no
 * aarch64 SHA-256 — it is written here per platform:
 *   aarch64  vsha256hq_u32 / vsha256h2q_u32 / vsha256su0q_u32 / vsha256su1q_u32
 *   x86_64   _mm_sha256rnds2_epu32 / _mm_sha256msg1_epu32 / _mm_sha256msg2_epu32
 * chosen once at init, stored in the state.
 */

#ifndef CVMCRYPT_HASH_SHA256_H
#define CVMCRYPT_HASH_SHA256_H

#include "base/types.h"

#define CVMCRYPT_SHA256_BLOCK_SIZE ((usize)64)
#define CVMCRYPT_SHA256_DIGEST_SIZE ((usize)32)

typedef struct CvmcryptSha256 {
    /* Running state, big-endian words as FIPS 180-4 specifies. */
    u32 state[8];
    /* Total message length in bits. */
    u64 length;
    /* Bytes buffered in buf that are not yet a full block. */
    usize curlen;
    /* The tail of the message, at most one block. */
    u8 buf[64];
    /* Which compress implementation init chose. */
    u8 impl;
} CvmcryptSha256;

/*
 * Which compression implementation this state will use.
 * Chosen once at init from what the CPU supports; not a runtime choice
 * per block, which would put a branch in the hot loop.
 */
enum {
    CVMCRYPT_SHA256_IMPL_SCALAR = 0,
    CVMCRYPT_SHA256_IMPL_ARM64 = 1, /* aarch64 crypto extension (mandatory) */
    CVMCRYPT_SHA256_IMPL_SHANI = 2, /* x86 SHA extensions (cpuid-detected) */
};

/* Initialise the state. Always succeeds; there is nothing to allocate. */
void cvmcrypt_sha256_init(CvmcryptSha256* md);

/* Absorb data. Always succeeds; the length check is the caller's. */
void cvmcrypt_sha256_update(CvmcryptSha256* md, u8 const* data, usize len);

/* Finish and write the 32-byte digest. The state is zeroised after. */
void cvmcrypt_sha256_final(CvmcryptSha256* md, u8 out[32]);

/* One-shot helper. */
void cvmcrypt_sha256(u8 const* data, usize len, u8 out[32]);

#endif /* CVMCRYPT_HASH_SHA256_H */
