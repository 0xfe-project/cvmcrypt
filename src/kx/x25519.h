/*
 * src/kx/x25519.h
 *
 * X25519 elliptic curve Diffie-Hellman, RFC 7748.
 *
 * Curve25519 Montgomery ladder over GF(2^255 - 19). Field elements
 * are 255 bits, stored as five 51-bit limbs (u64 each). The ladder
 * is constant-time: every step processes both branches, and the
 * conditional swap uses arithmetic (not branches).
 */

#ifndef CVMCRYPT_KX_X25519_H
#define CVMCRYPT_KX_X25519_H

#include "base/types.h"

#define CVMCRYPT_X25519_SCALAR_SIZE ((usize)32)
#define CVMCRYPT_X25519_POINT_SIZE ((usize)32)
#define CVMCRYPT_X25519_SHARED_SIZE ((usize)32)

/*
 * Compute the X25519 function: scalar * u_coordinate.
 * Both arrays are 32 bytes, little-endian.
 */
void cvmcrypt_x25519(u8 out[32], u8 const scalar[32], u8 const u_point[32]);

/*
 * Generate a public key from a private scalar.
 * The scalar is clamped per RFC 7748 §5.
 */
void cvmcrypt_x25519_base(u8 public_key[32], u8 const scalar[32]);

/*
 * Derive a shared secret from a private scalar and peer public key.
 * Returns the 32-byte shared secret, or all zeros on invalid input.
 */
void cvmcrypt_x25519_shared(u8 shared[32], u8 const scalar[32],
                            u8 const peer_public[32]);

/* Fast implementation using 5x51-bit limbs (ARM64). */
void cvmcrypt_x25519_fast(u8 out[32], u8 const scalar[32], u8 const point[32]);
void cvmcrypt_x25519_base_fast(u8 public_key[32], u8 const scalar[32]);

#endif /* CVMCRYPT_KX_X25519_H */
