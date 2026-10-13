/*
 * src/mac/hmac.c
 *
 * HMAC (RFC 2104). Carried over from libtomcrypt's mac/hmac/ 
 * (Unlicense), rewritten to cvm conventions and specialised to the
 * two hashes cvmcrypt carries. No allocation: every buffer lives on
 * the caller's stack or inside the context.
 */

#include "mac/hmac.h"

#include "base/mem.h"
#include "base/secure.h"

/* ------------------------------------------------------------------ */
/* HMAC-SHA-256                                                        */
/* ------------------------------------------------------------------ */

void cvmcrypt_hmac_sha256_init(CvmcryptHmacSha256* h, u8 const* key, usize keylen) {
    u8 ipad[64];

    if (keylen > 64) {
        cvmcrypt_sha256(key, keylen, h->key);
        memset(h->key + 32, 0, 64 - 32);
    } else {
        memcpy(h->key, key, keylen);
        memset(h->key + keylen, 0, 64 - keylen);
    }

    for (usize i = 0; i < 64; i++) {
        ipad[i] = h->key[i] ^ 0x36;
    }

    cvmcrypt_sha256_init(&h->inner);
    cvmcrypt_sha256_update(&h->inner, ipad, 64);
    memset(ipad, 0, sizeof(ipad));
}

void cvmcrypt_hmac_sha256_update(CvmcryptHmacSha256* h, u8 const* data, usize len) {
    cvmcrypt_sha256_update(&h->inner, data, len);
}

void cvmcrypt_hmac_sha256_final(CvmcryptHmacSha256* h, u8 out[32]) {
    u8 inner_digest[32];
    u8 opad[64];
    CvmcryptSha256 outer;

    cvmcrypt_sha256_final(&h->inner, inner_digest);

    for (usize i = 0; i < 64; i++) {
        opad[i] = h->key[i] ^ 0x5c;
    }

    cvmcrypt_sha256_init(&outer);
    cvmcrypt_sha256_update(&outer, opad, 64);
    cvmcrypt_sha256_update(&outer, inner_digest, 32);
    cvmcrypt_sha256_final(&outer, out);

    memset(inner_digest, 0, sizeof(inner_digest));
    memset(opad, 0, sizeof(opad));
    memset(h->key, 0, sizeof(h->key));
}

void cvmcrypt_hmac_sha256(u8 const* key, usize keylen, u8 const* data, usize len,
                          u8 out[32]) {
    CvmcryptHmacSha256 h;
    cvmcrypt_hmac_sha256_init(&h, key, keylen);
    cvmcrypt_hmac_sha256_update(&h, data, len);
    cvmcrypt_hmac_sha256_final(&h, out);
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA-512                                                        */
/* ------------------------------------------------------------------ */

void cvmcrypt_hmac_sha512_init(CvmcryptHmacSha512* h, u8 const* key, usize keylen) {
    u8 ipad[128];

    if (keylen > 128) {
        cvmcrypt_sha512(key, keylen, h->key);
        memset(h->key + 64, 0, 128 - 64);
    } else {
        memcpy(h->key, key, keylen);
        memset(h->key + keylen, 0, 128 - keylen);
    }

    for (usize i = 0; i < 128; i++) {
        ipad[i] = h->key[i] ^ 0x36;
    }

    cvmcrypt_sha512_init(&h->inner);
    cvmcrypt_sha512_update(&h->inner, ipad, 128);
    memset(ipad, 0, sizeof(ipad));
}

void cvmcrypt_hmac_sha512_update(CvmcryptHmacSha512* h, u8 const* data, usize len) {
    cvmcrypt_sha512_update(&h->inner, data, len);
}

void cvmcrypt_hmac_sha512_final(CvmcryptHmacSha512* h, u8 out[64]) {
    u8 inner_digest[64];
    u8 opad[128];
    CvmcryptSha512 outer;

    cvmcrypt_sha512_final(&h->inner, inner_digest);

    for (usize i = 0; i < 128; i++) {
        opad[i] = h->key[i] ^ 0x5c;
    }

    cvmcrypt_sha512_init(&outer);
    cvmcrypt_sha512_update(&outer, opad, 128);
    cvmcrypt_sha512_update(&outer, inner_digest, 64);
    cvmcrypt_sha512_final(&outer, out);

    memset(inner_digest, 0, sizeof(inner_digest));
    memset(opad, 0, sizeof(opad));
    memset(h->key, 0, sizeof(h->key));
}

void cvmcrypt_hmac_sha512(u8 const* key, usize keylen, u8 const* data, usize len,
                          u8 out[64]) {
    CvmcryptHmacSha512 h;
    cvmcrypt_hmac_sha512_init(&h, key, keylen);
    cvmcrypt_hmac_sha512_update(&h, data, len);
    cvmcrypt_hmac_sha512_final(&h, out);
}
