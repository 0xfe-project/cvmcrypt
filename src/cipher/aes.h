/*
 * src/cipher/aes.h
 *
 * AES-128/192/256 block cipher, FIPS 197.
 *
 * Key schedule is portable C. Encryption and decryption use the aarch64
 * dedicated instructions (AESE/AESD/AESMC/AESIMC) on arm64, the scalar
 * S-box path elsewhere.
 *
 * The S-box scalar path is slower than ltc's T-table path; on any CPU
 * with the AES extension it is never taken.
 */

#ifndef CVMCRYPT_CIPHER_AES_H
#define CVMCRYPT_CIPHER_AES_H

#include "base/types.h"

#define CVMCRYPT_AES_BLOCK_SIZE ((usize)16)
#define CVMCRYPT_AES_MAX_ROUNDS 14

typedef struct CvmcryptAesKey {
    /* Round keys: (rounds+1) × 4 words, in FIPS 197 word order (big-endian
     * representation stored as host u32). */
    u32 enc[4 * (CVMCRYPT_AES_MAX_ROUNDS + 1)];
    u32 dec[4 * (CVMCRYPT_AES_MAX_ROUNDS + 1)];
    u32 rounds;
} CvmcryptAesKey;

/*
 * Expand a 16/24/32-byte key. Returns false on invalid key length.
 * Both the encryption and the equivalent decryption schedule are computed.
 */
bool cvmcrypt_aes_setup(CvmcryptAesKey* key, u8 const* user_key, usize keylen);

/* Encrypt/decrypt one 16-byte block. */
void cvmcrypt_aes_encrypt_block(CvmcryptAesKey const* key, u8 const in[16], u8 out[16]);
void cvmcrypt_aes_decrypt_block(CvmcryptAesKey const* key, u8 const in[16], u8 out[16]);

#endif /* CVMCRYPT_CIPHER_AES_H */
