/*
 * src/stream/chacha20.h
 *
 * ChaCha20 stream cipher, RFC 8439 §2.4.
 *
 * The SIMD layer uses compiler vector extensions
 * (__attribute__((vector_size(16)))) — one source, both platforms,
 * no intrinsics, no #if. ChaCha is pure ARX (add-rotate-XOR), which
 * the compiler maps to NEON on aarch64 and SSE2 on x86_64 without
 * any per-platform code. 16-byte vectors need no -march flag on
 * either platform: SSE2 is baseline on x86_64, NEON is baseline on
 * aarch64.
 */

#ifndef CVMCRYPT_STREAM_CHACHA20_H
#define CVMCRYPT_STREAM_CHACHA20_H

#include "base/types.h"

#define CVMCRYPT_CHACHA20_KEY_SIZE ((usize)32)
#define CVMCRYPT_CHACHA20_NONCE_SIZE ((usize)12)
#define CVMCRYPT_CHACHA20_BLOCK_SIZE ((usize)64)

typedef struct CvmcryptChaCha20 {
    /* The 16-word state (constants, key, counter, nonce). */
    u32 state[16];
    /* Partial keystream block. */
    u8 buf[64];
    /* Bytes consumed from buf. pos == 64 means buf is empty. */
    usize pos;
} CvmcryptChaCha20;

/* RFC 8439 §2.4: 32-byte key, 12-byte nonce, 32-bit block counter. */
void cvmcrypt_chacha20_init(CvmcryptChaCha20* c, u8 const key[32], u32 counter,
                            u8 const nonce[12]);

/* XOR `len` bytes of keystream into data, in place or out-of-place. */
void cvmcrypt_chacha20_xor(CvmcryptChaCha20* c, u8 const* in, usize len, u8* out);

#endif /* CVMCRYPT_STREAM_CHACHA20_H */
