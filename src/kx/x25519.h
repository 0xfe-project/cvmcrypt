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
 * X25519 (RFC 7748), 5x51-bit limbs with __int128 multiplication.
 *
 * Both arrays are 32 bytes, little-endian. The scalar is clamped internally
 * per RFC 7748 §5.
 *
 * This is the only X25519 in the tree. The tweetnacl 16-limb ladder that used
 * to sit beside it was unused by the library, was not what TLS called, and
 * produced wrong public keys roughly one run in fifteen under AddressSanitizer
 * — a layout-dependent bug that was never root-caused. It was deleted rather
 * than left as a second, unreliable answer to the same question.
 */
void cvmcrypt_x25519_fast(u8 out[32], u8 const scalar[32], u8 const point[32]);
void cvmcrypt_x25519_base_fast(u8 public_key[32], u8 const scalar[32]);

#endif /* CVMCRYPT_KX_X25519_H */
