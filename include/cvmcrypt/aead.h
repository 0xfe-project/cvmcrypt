/*
 * include/cvmcrypt/aead.h
 *
 * AEAD in the shape QUIC and TLS need it: one key installed once, then one
 * seal/open per message with an explicit nonce.
 *
 * The nonce is the caller's. For TLS records it is the record sequence
 * number XOR the write IV; for QUIC it is the packet number XOR the IV. Doing
 * that here would mean keeping a counter this layer does not own, so it does
 * not: the caller passes the 12 bytes it computed.
 *
 * Contexts are by value. A context is roughly 1.3 KB (the AES key schedule
 * and the GHASH table dominate), which is fine on a stack frame and lets the
 * caller decide where it lives. There is no allocation in this header on
 * purpose — cvmcrypt is freestanding.
 */

#ifndef CVMCRYPT_AEAD_H
#define CVMCRYPT_AEAD_H

#include "aead/chachapoly.h"
#include "aead/gcm.h"
#include "base/types.h"

/*
 * Algorithm descriptors. The objects have static storage duration, so a
 * pointer to one is valid for the life of the program and can be kept.
 */
typedef struct CvmcryptAeadAlg CvmcryptAeadAlg;

extern CvmcryptAeadAlg const cvmcrypt_aead_aes128gcm;
extern CvmcryptAeadAlg const cvmcrypt_aead_aes256gcm;
extern CvmcryptAeadAlg const cvmcrypt_aead_chacha20poly1305;

usize cvmcrypt_aead_key_size(CvmcryptAeadAlg const* alg);
usize cvmcrypt_aead_nonce_size(CvmcryptAeadAlg const* alg);
usize cvmcrypt_aead_tag_size(CvmcryptAeadAlg const* alg);

typedef struct CvmcryptAeadCtx {
    CvmcryptAeadAlg const* alg;
    union {
        CvmcryptGcm gcm;
        /* ChaCha20-Poly1305 as carried today is one-shot over the key, so
         * the key itself is the whole state. */
        u8 chacha_key[CVMCRYPT_CHACHAPOLY_KEY_SIZE];
    } u;
} CvmcryptAeadCtx;

/* Install a key. Returns false on a wrong key length or an unknown alg. */
bool cvmcrypt_aead_init(CvmcryptAeadCtx* ctx, CvmcryptAeadAlg const* alg, u8 const* key);

/*
 * Encrypt pt into ct and write the tag. ct may alias pt. ct has ptlen bytes;
 * tag has cvmcrypt_aead_tag_size() bytes.
 */
bool cvmcrypt_aead_seal(CvmcryptAeadCtx* ctx, u8 const* nonce, u8 const* aad, usize aadlen,
                        u8 const* pt, usize ptlen, u8* ct, u8* tag);

/*
 * Decrypt ct into pt, verifying the tag in constant time. Returns false if it
 * does not match, in which case pt has been zeroised.
 */
bool cvmcrypt_aead_open(CvmcryptAeadCtx* ctx, u8 const* nonce, u8 const* aad, usize aadlen,
                        u8 const* ct, usize ctlen, u8* pt, u8 const* tag);

/* Zeroise everything key-derived. Call before the context goes out of scope. */
void cvmcrypt_aead_clear(CvmcryptAeadCtx* ctx);

#endif /* CVMCRYPT_AEAD_H */
