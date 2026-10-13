/*
 * src/kdf/hkdf.c
 *
 * HKDF (RFC 5869) on HMAC-SHA-256 / HMAC-SHA-512.
 */

#include "kdf/hkdf.h"

#include "base/mem.h"
#include "mac/hmac.h"

/* ------------------------------------------------------------------ */
/* HKDF-SHA-256                                                        */
/* ------------------------------------------------------------------ */

void cvmcrypt_hkdf_sha256_extract(u8 prk[32], u8 const* salt, usize saltlen,
                                  u8 const* ikm, usize ikmlen) {
    /* PRK = HMAC-SHA-256(salt, IKM). If salt is empty, use a string of
     * HashLen zeros (per RFC 5869 §2.2). */
    if (salt == NULL || saltlen == 0) {
        u8 zeros[32] = {0};
        cvmcrypt_hmac_sha256(zeros, 32, ikm, ikmlen, prk);
    } else {
        cvmcrypt_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    }
}

bool cvmcrypt_hkdf_sha256_expand(u8* okm, usize okmlen, u8 const prk[32],
                                 u8 const* info, usize infolen) {
    if (okmlen > 255 * 32)
        return false;
    if (okmlen == 0)
        return true;
    if (info == NULL)
        infolen = 0;

    u8 t[32];
    u8 counter = 1;
    usize produced = 0;

    while (produced < okmlen) {
        CvmcryptHmacSha256 h;
        cvmcrypt_hmac_sha256_init(&h, prk, 32);

        if (produced > 0) {
            cvmcrypt_hmac_sha256_update(&h, t, 32);
        }
        if (infolen > 0) {
            cvmcrypt_hmac_sha256_update(&h, info, infolen);
        }
        cvmcrypt_hmac_sha256_update(&h, &counter, 1);
        cvmcrypt_hmac_sha256_final(&h, t);

        usize n = okmlen - produced;
        if (n > 32)
            n = 32;
        memcpy(okm + produced, t, n);
        produced += n;
        counter++;
    }
    memset(t, 0, sizeof(t));
    return true;
}

bool cvmcrypt_hkdf_sha256(u8* okm, usize okmlen, u8 const* salt, usize saltlen,
                          u8 const* ikm, usize ikmlen, u8 const* info, usize infolen) {
    u8 prk[32];
    cvmcrypt_hkdf_sha256_extract(prk, salt, saltlen, ikm, ikmlen);
    bool ok = cvmcrypt_hkdf_sha256_expand(okm, okmlen, prk, info, infolen);
    memset(prk, 0, sizeof(prk));
    return ok;
}

/* ------------------------------------------------------------------ */
/* HKDF-SHA-512                                                        */
/* ------------------------------------------------------------------ */

void cvmcrypt_hkdf_sha512_extract(u8 prk[64], u8 const* salt, usize saltlen,
                                  u8 const* ikm, usize ikmlen) {
    if (salt == NULL || saltlen == 0) {
        u8 zeros[64] = {0};
        cvmcrypt_hmac_sha512(zeros, 64, ikm, ikmlen, prk);
    } else {
        cvmcrypt_hmac_sha512(salt, saltlen, ikm, ikmlen, prk);
    }
}

bool cvmcrypt_hkdf_sha512_expand(u8* okm, usize okmlen, u8 const prk[64],
                                 u8 const* info, usize infolen) {
    if (okmlen > 255 * 64)
        return false;
    if (okmlen == 0)
        return true;
    if (info == NULL)
        infolen = 0;

    u8 t[64];
    u8 counter = 1;
    usize produced = 0;

    while (produced < okmlen) {
        CvmcryptHmacSha512 h;
        cvmcrypt_hmac_sha512_init(&h, prk, 64);

        if (produced > 0) {
            cvmcrypt_hmac_sha512_update(&h, t, 64);
        }
        if (infolen > 0) {
            cvmcrypt_hmac_sha512_update(&h, info, infolen);
        }
        cvmcrypt_hmac_sha512_update(&h, &counter, 1);
        cvmcrypt_hmac_sha512_final(&h, t);

        usize n = okmlen - produced;
        if (n > 64)
            n = 64;
        memcpy(okm + produced, t, n);
        produced += n;
        counter++;
    }
    memset(t, 0, sizeof(t));
    return true;
}

bool cvmcrypt_hkdf_sha512(u8* okm, usize okmlen, u8 const* salt, usize saltlen,
                          u8 const* ikm, usize ikmlen, u8 const* info, usize infolen) {
    u8 prk[64];
    cvmcrypt_hkdf_sha512_extract(prk, salt, saltlen, ikm, ikmlen);
    bool ok = cvmcrypt_hkdf_sha512_expand(okm, okmlen, prk, info, infolen);
    memset(prk, 0, sizeof(prk));
    return ok;
}
