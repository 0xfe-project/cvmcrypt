/*
 * src/aead/chachapoly.h
 *
 * ChaCha20-Poly1305 AEAD, RFC 8439 §2.8.
 *
 * The composition: one ChaCha20 block generates the Poly1305 key
 * (bytes 0-31 of the keystream), and the rest of the keystream
 * encrypts the plaintext starting from block counter 1. The
 * Poly1305 tag covers AAD || pad || ciphertext || pad || lengths.
 *
 * One-shot API, same shape as GCM.
 */

#ifndef CVMCRYPT_AEAD_CHACHAPOLY_H
#define CVMCRYPT_AEAD_CHACHAPOLY_H

#include "base/types.h"

#define CVMCRYPT_CHACHAPOLY_KEY_SIZE ((usize)32)
#define CVMCRYPT_CHACHAPOLY_NONCE_SIZE ((usize)12)
#define CVMCRYPT_CHACHAPOLY_TAG_SIZE ((usize)16)

/*
 * One-shot encrypt. key is 32 bytes, nonce is 12 bytes.
 * Returns the ciphertext (same length as plaintext) and 16-byte tag.
 */
void cvmcrypt_chachapoly_encrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* pt, usize ptlen, u8* ct,
                                 u8 tag[16]);

/*
 * One-shot decrypt. Verifies the tag (constant-time).
 * Returns false if the tag does not match (plaintext is zeroised).
 */
bool cvmcrypt_chachapoly_decrypt(u8 const key[32], u8 const nonce[12], u8 const* aad,
                                 usize aadlen, u8 const* ct, usize ctlen, u8* pt,
                                 u8 const tag[16]);

#endif
