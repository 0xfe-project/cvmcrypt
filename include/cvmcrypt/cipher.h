/*
 * include/cvmcrypt/cipher.h
 *
 * The block cipher, used for one thing: QUIC header protection (RFC 9001
 * §5.4). Both families reduce to the same primitive, a 16-byte keystream
 * block over a 16-byte input:
 *
 *   AES      out = AES-ECB_K(in)
 *   ChaCha20 in[0..3] is the block counter (little-endian), in[4..15] the
 *            nonce; out is the keystream block
 *
 * The mask is the first 5 bytes of that block. Exposing the block rather than
 * only the mask keeps the primitive visible and makes it testable against
 * RFC 9001's own vectors.
 *
 * This is deliberately not a general-purpose cipher interface: there is no
 * CBC, no CTR, no decryption. Encryption is all header protection needs, and
 * an interface nobody calls is an interface nobody tests.
 */

#ifndef CVMCRYPT_CIPHER_H
#define CVMCRYPT_CIPHER_H

#include "base/types.h"
#include "cipher/aes.h"
#include "stream/chacha20.h"

typedef struct CvmcryptCipherAlg CvmcryptCipherAlg;

extern CvmcryptCipherAlg const cvmcrypt_cipher_aes128;
extern CvmcryptCipherAlg const cvmcrypt_cipher_aes192;
extern CvmcryptCipherAlg const cvmcrypt_cipher_aes256;
extern CvmcryptCipherAlg const cvmcrypt_cipher_chacha20;

usize cvmcrypt_cipher_key_size(CvmcryptCipherAlg const* alg);

typedef struct CvmcryptCipherCtx {
    CvmcryptCipherAlg const* alg;
    union {
        CvmcryptAesKey aes;
        u8 chacha_key[CVMCRYPT_CHACHA20_KEY_SIZE];
    } u;
} CvmcryptCipherCtx;

bool cvmcrypt_cipher_init(CvmcryptCipherCtx* ctx, CvmcryptCipherAlg const* alg,
                          u8 const* key);

/* One 16-byte keystream block. in may alias out. */
bool cvmcrypt_cipher_keystream(CvmcryptCipherCtx* ctx, u8 const in[16], u8 out[16]);

/* QUIC header protection mask: the first 5 bytes of the keystream block. */
bool cvmcrypt_cipher_hp_mask(CvmcryptCipherCtx* ctx, u8 const sample[16], u8 mask[5]);

void cvmcrypt_cipher_clear(CvmcryptCipherCtx* ctx);

#endif /* CVMCRYPT_CIPHER_H */
