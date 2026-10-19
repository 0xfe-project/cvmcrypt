/*
 * src/aead/gcm.h
 *
 * AES-GCM per NIST SP 800-38D.
 *
 * Written for cvmcrypt following the spec, not carried from ltc (whose
 * GCM is spread across 10 files with a state machine for incremental
 * feeding). cvmcrypt's GCM is one-shot: set up, encrypt, tag. The
 * GHASH uses the aarch64 PMULL instruction where available, scalar
 * bit-by-bit elsewhere.
 */

#ifndef CVMCRYPT_AEAD_GCM_H
#define CVMCRYPT_AEAD_GCM_H

#include "base/types.h"
#include "cipher/aes.h"

#define CVMCRYPT_GCM_TAG_SIZE ((usize)16)
#define CVMCRYPT_GCM_IV_SIZE ((usize)12)

typedef struct CvmcryptGcm {
    CvmcryptAesKey aes;
    /* Hash subkey H = AES_K(0^128), in GCM byte order. */
    u8 H[16];
    /* Running GHASH accumulator. */
    u8 X[16];
#if defined(__aarch64__) || defined(__x86_64__)
    /* BoringSSL/OpenSSL aes-gcm key layout, built once at setup: round
     * keys as big-endian u32 at +0.., round count (u32) at byte 240.
     * Identical on arm64 and x86_64, so one side buffer serves both.
     * `aes.c` stays clean; only this side buffer knows the layout. */
    u32 aes_rk[61];
    /* GHASH table from gcm_init_clmul (built from VREV64(H)).
     * The arm64 and x86_64 tables are NOT interchangeable. */
    u8 htable[256];
    /* Non-zero when the adopted assembly kernel may be used (arm64:
     * always; x86_64: AES-NI + PCLMUL + SSSE3 present). */
    u8 asm_ok;
#endif
    /* The counter block: J0 padded to 16 bytes. */
    u8 counter[16];
    /* Buffered partial block. */
    u8 buf[16];
    usize buflen;
    /* Total AAD length in bits. */
    u64 aadlen;
    /* Total plaintext length in bits. */
    u64 ptlen;
    /* Which GHASH implementation. */
    u8 impl;
} CvmcryptGcm;

enum {
    CVMCRYPT_GCM_IMPL_SCALAR = 0,
    /* Hardware path: arm64 PMULL, or x86_64 AES-NI + PCLMULQDQ. */
    CVMCRYPT_GCM_IMPL_PMULL = 1,
};

/* ------------------------------------------------------------------ */
/* Keyed interface                                                      */
/*                                                                      */
/* The key schedule and the GHASH table dominate setup (~290 ns), which */
/* is 14% of a 16 KB TLS record. A connection reuses one key, so build  */
/* the key-derived state once with _setup() and then _seal()/_open()    */
/* per record; those only reset the per-message state.                  */
/* ------------------------------------------------------------------ */

bool cvmcrypt_gcm_setup(CvmcryptGcm* g, u8 const* key, usize keylen);

bool cvmcrypt_gcm_seal(CvmcryptGcm* g, u8 const iv[12], u8 const* aad, usize aadlen,
                       u8 const* pt, usize ptlen, u8* ct, u8 tag[16]);

bool cvmcrypt_gcm_open(CvmcryptGcm* g, u8 const iv[12], u8 const* aad, usize aadlen,
                       u8 const* ct, usize ctlen, u8* pt, u8 const tag[16]);

/* Zeroise the whole context, key-derived state included. */
void cvmcrypt_gcm_clear(CvmcryptGcm* g);

/*
 * One-shot AES-GCM encrypt. Produces ciphertext and a 16-byte tag.
 * iv is 12 bytes (the TLS 1.3 case); other lengths hash the IV.
 * Returns false on failure (bad key length).
 */
bool cvmcrypt_gcm_encrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* pt, usize ptlen,
                          u8* ct, u8 tag[16]);

/*
 * One-shot AES-GCM decrypt. Verifies the tag and produces plaintext.
 * Returns false if the tag does not match (plaintext is zeroised).
 */
bool cvmcrypt_gcm_decrypt(CvmcryptGcm* g, u8 const* key, usize keylen, u8 const iv[12],
                          u8 const* aad, usize aadlen, u8 const* ct, usize ctlen,
                          u8* pt, u8 const tag[16]);

#endif /* CVMCRYPT_AEAD_GCM_H */
