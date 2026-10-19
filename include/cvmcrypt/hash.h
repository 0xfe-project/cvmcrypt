/*
 * include/cvmcrypt/hash.h
 *
 * Hash and HKDF, algorithm-polymorphic.
 *
 * Why a descriptor rather than one function per hash: HKDF has to be written
 * once, not three times, and QUIC picks the hash from the negotiated cipher
 * suite at run time. The descriptor carries what HKDF needs — block size for
 * HMAC's ipad/opad, digest size for the PRK length — so the KDF code has no
 * switch in it.
 *
 * SHA-384 shares SHA-512's compression function and differs only in the IV
 * and the truncation, which is why there is no CvmcryptSha384 type.
 */

#ifndef CVMCRYPT_HASH_H
#define CVMCRYPT_HASH_H

#include "base/types.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

typedef struct CvmcryptMdAlg CvmcryptMdAlg;

extern CvmcryptMdAlg const cvmcrypt_md_sha256;
extern CvmcryptMdAlg const cvmcrypt_md_sha384;
extern CvmcryptMdAlg const cvmcrypt_md_sha512;

usize cvmcrypt_md_digest_size(CvmcryptMdAlg const* alg);
usize cvmcrypt_md_block_size(CvmcryptMdAlg const* alg);

typedef struct CvmcryptMdCtx {
    CvmcryptMdAlg const* alg;
    union {
        CvmcryptSha256 s256;
        CvmcryptSha512 s512;
    } u;
} CvmcryptMdCtx;

void cvmcrypt_md_init(CvmcryptMdCtx* ctx, CvmcryptMdAlg const* alg);
void cvmcrypt_md_update(CvmcryptMdCtx* ctx, u8 const* data, usize len);

/* Writes cvmcrypt_md_digest_size() bytes and resets the context. */
void cvmcrypt_md_final(CvmcryptMdCtx* ctx, u8* out);

/* One-shot, for the many places that hash a single buffer. */
bool cvmcrypt_md_digest(CvmcryptMdAlg const* alg, u8 const* data, usize len, u8* out);

/*
 * HKDF (RFC 5869).
 *
 * extract: prk = HMAC(salt, ikm). prk receives digest_size bytes; an empty
 *          salt is the caller's signal for HashLen zeros, as the RFC says.
 * expand:  okm from prk and optional info. Fails if okmlen > 255 * digest_size.
 *
 * The TLS 1.3 expand-label wrapper is not here: it is a label encoding, not a
 * KDF, and cvmcrypt's TLS layer already has it.
 */
bool cvmcrypt_hkdf_extract(CvmcryptMdAlg const* alg, u8* prk, u8 const* salt, usize saltlen,
                           u8 const* ikm, usize ikmlen);

bool cvmcrypt_hkdf_expand(CvmcryptMdAlg const* alg, u8* okm, usize okmlen, u8 const* prk,
                          u8 const* info, usize infolen);

#endif /* CVMCRYPT_HASH_H */
