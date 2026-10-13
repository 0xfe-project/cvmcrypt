/*
 * src/kdf/hkdf.h
 *
 * HKDF (RFC 5869): extract-then-expand key derivation, built on
 * HMAC-SHA-256 and HMAC-SHA-512.
 */

#ifndef CVMCRYPT_KDF_HKDF_H
#define CVMCRYPT_KDF_HKDF_H

#include "base/types.h"

/* HKDF-SHA-256: extract 32-byte PRK from salt+IKM. */
void cvmcrypt_hkdf_sha256_extract(u8 prk[32], u8 const* salt, usize saltlen,
                                  u8 const* ikm, usize ikmlen);

/* HKDF-SHA-256: expand PRK into okmlen bytes (max 255*32). */
bool cvmcrypt_hkdf_sha256_expand(u8* okm, usize okmlen, u8 const prk[32],
                                 u8 const* info, usize infolen);

/* HKDF-SHA-256 one-shot. */
bool cvmcrypt_hkdf_sha256(u8* okm, usize okmlen, u8 const* salt, usize saltlen,
                          u8 const* ikm, usize ikmlen, u8 const* info, usize infolen);

/* HKDF-SHA-512: extract 64-byte PRK from salt+IKM. */
void cvmcrypt_hkdf_sha512_extract(u8 prk[64], u8 const* salt, usize saltlen,
                                  u8 const* ikm, usize ikmlen);

/* HKDF-SHA-512: expand PRK into okmlen bytes (max 255*64). */
bool cvmcrypt_hkdf_sha512_expand(u8* okm, usize okmlen, u8 const prk[64],
                                 u8 const* info, usize infolen);

/* HKDF-SHA-512 one-shot. */
bool cvmcrypt_hkdf_sha512(u8* okm, usize okmlen, u8 const* salt, usize saltlen,
                          u8 const* ikm, usize ikmlen, u8 const* info, usize infolen);

#endif
