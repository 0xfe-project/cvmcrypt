/*
 * src/mac/poly1305.h
 *
 * Poly1305 one-time authenticator, RFC 8439 §2.5.
 *
 * A polynomial-evaluation MAC over the prime 2^130 - 5. The key is
 * 32 bytes: r (clamped) and s. The tag is 16 bytes.
 *
 * The implementation uses 26-bit limbs (5 limbs of 26 bits, 130 bits
 * total), which is the representation from the original Poly1305-AES
 * paper and is what most portable implementations use.
 */

#ifndef CVMCRYPT_MAC_POLY1305_H
#define CVMCRYPT_MAC_POLY1305_H

#include "base/types.h"

#define CVMCRYPT_POLY1305_KEY_SIZE ((usize)32)
#define CVMCRYPT_POLY1305_TAG_SIZE ((usize)16)

typedef struct CvmcryptPoly1305 {
    /* r in 26-bit limbs (clamped). */
    u32 r[5];
    /* h (accumulator) in 26-bit limbs. */
    u32 h[5];
    /* s (the pad), stored as two 64-bit words. */
    u32 s[4];
    /* Partial block buffer. */
    u8 buf[16];
    usize buflen;
} CvmcryptPoly1305;

/* Initialise with a 32-byte key (r || s). */
void cvmcrypt_poly1305_init(CvmcryptPoly1305* p, u8 const key[32]);

/* Absorb data. */
void cvmcrypt_poly1305_update(CvmcryptPoly1305* p, u8 const* data, usize len);

/* Finalise and write the 16-byte tag. State is zeroised. */
void cvmcrypt_poly1305_final(CvmcryptPoly1305* p, u8 tag[16]);

/* One-shot. */
void cvmcrypt_poly1305(u8 const key[32], u8 const* data, usize len, u8 tag[16]);

#endif /* CVMCRYPT_MAC_POLY1305_H */
