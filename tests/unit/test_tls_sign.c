/*
 * tests/unit/test_tls_sign.c
 *
 * RSA + ECDSA sign with PKCS#8 private key import.
 * Sign with our implementation, verify with our verify (round-trip).
 */

#include "vendor/greatest.h"

#include <string.h>
#include <stdio.h>

#include "pk/rsa.h"
#include "ecc/p256.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

static u8 const hello_hash[32] = {
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b,
    0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
    0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
};

/* ------------------------------------------------------------------ */
/* RSA sign tests                                                       */
/* ------------------------------------------------------------------ */

TEST rsa_pkcs8_import(void) {
    CvmRsaPriv key;
    cvmcrypt_rsa_priv_init(&key);
    /* Read from file for simplicity (avoids 1200-line array). */
    FILE* f = fopen("/tmp/rsa_priv_pkcs8.der", "rb");
    if (f == NULL) {
        SKIPm("test key not available");
    }
    u8 buf[2048];
    usize len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    ASSERT(cvmcrypt_rsa_priv_import_pkcs8(&key, buf, len));
    ASSERT_EQ(2048, cvmcrypt_mpi_bitlen(&key.n));
    ASSERT_EQ(0x10001, key.e.p[0]);
    ASSERT(!cvmcrypt_mpi_is_zero(&key.d));
    cvmcrypt_rsa_priv_free(&key);
    PASS();
}

TEST rsa_sign_pkcs1_roundtrip(void) {
    CvmRsaPriv key;
    cvmcrypt_rsa_priv_init(&key);
    FILE* f = fopen("/tmp/rsa_priv_pkcs8.der", "rb");
    if (f == NULL) {
        SKIPm("test key not available");
    }
    u8 buf[2048];
    usize len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT(cvmcrypt_rsa_priv_import_pkcs8(&key, buf, len));

    /* Sign. */
    u8 sig[256];
    usize sig_len = cvmcrypt_rsa_sign_pkcs1_v15(&key, CVMCRYPT_RSA_HASH_SHA256,
                                                hello_hash, 32, sig, sizeof(sig));
    ASSERT(sig_len == 256);

    /* Import public key. */
    FILE* fp = fopen("/tmp/rsa_pub_test.der", "rb");
    if (fp == NULL) {
        SKIPm("test pub not available");
    }
    u8 pub[512];
    usize pub_len = fread(pub, 1, sizeof(pub), fp);
    fclose(fp);

    CvmRsaKey pub_key;
    cvmcrypt_rsa_init(&pub_key);
    ASSERT(cvmcrypt_rsa_import_spki(&pub_key, pub, pub_len));

    /* Verify our signature. */
    ASSERT(cvmcrypt_rsa_verify_pkcs1_v15(&pub_key, CVMCRYPT_RSA_HASH_SHA256, hello_hash,
                                         32, sig, sig_len));

    cvmcrypt_rsa_free(&pub_key);
    cvmcrypt_rsa_priv_free(&key);
    PASS();
}

TEST rsa_sign_pss_roundtrip(void) {
    CvmRsaPriv key;
    cvmcrypt_rsa_priv_init(&key);
    FILE* f = fopen("/tmp/rsa_priv_pkcs8.der", "rb");
    if (f == NULL) {
        SKIPm("test key not available");
    }
    u8 buf[2048];
    usize len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT(cvmcrypt_rsa_priv_import_pkcs8(&key, buf, len));

    /* Generate salt = hash of "salt" for deterministic test. */
    u8 salt[32];
    for (int i = 0; i < 32; i++)
        salt[i] = (u8)(i * 7);

    /* Sign. */
    u8 sig[256];
    usize sig_len = cvmcrypt_rsa_sign_pss(&key, CVMCRYPT_RSA_HASH_SHA256, hello_hash,
                                          32, sig, sizeof(sig), salt, 32);
    ASSERT(sig_len == 256);

    /* Import public key and verify. */
    FILE* fp = fopen("/tmp/rsa_pub_test.der", "rb");
    if (fp == NULL) {
        SKIPm("test pub not available");
    }
    u8 pub[512];
    usize pub_len = fread(pub, 1, sizeof(pub), fp);
    fclose(fp);

    CvmRsaKey pub_key;
    cvmcrypt_rsa_init(&pub_key);
    ASSERT(cvmcrypt_rsa_import_spki(&pub_key, pub, pub_len));
    ASSERT(cvmcrypt_rsa_verify_pss(&pub_key, CVMCRYPT_RSA_HASH_SHA256, hello_hash, 32,
                                   sig, sig_len));

    cvmcrypt_rsa_free(&pub_key);
    cvmcrypt_rsa_priv_free(&key);
    PASS();
}

/* ------------------------------------------------------------------ */
/* ECDSA sign tests                                                     */
/* ------------------------------------------------------------------ */

TEST ec_pkcs8_import(void) {
    CvmEcPriv key;
    cvmcrypt_ec_priv_init(&key);
    FILE* f = fopen("/tmp/ec_priv_pkcs8.der", "rb");
    if (f == NULL) {
        SKIPm("test key not available");
    }
    u8 buf[512];
    usize len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    ASSERT_EQ(EC_OK, cvmcrypt_ec_priv_import_pkcs8(&key, buf, len));
    ASSERT_EQ(EC_CURVE_P256, key.curve);
    ASSERT(!cvmcrypt_mpi_is_zero(&key.d));
    cvmcrypt_ec_priv_free(&key);
    PASS();
}

TEST ec_sign_roundtrip(void) {
    CvmEcPriv key;
    cvmcrypt_ec_priv_init(&key);
    FILE* f = fopen("/tmp/ec_priv_pkcs8.der", "rb");
    if (f == NULL) {
        SKIPm("test key not available");
    }
    u8 buf[512];
    usize len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_priv_import_pkcs8(&key, buf, len));

    /* Deterministic k for testing (in production, use a CSPRNG). */
    u8 k[32];
    for (int i = 0; i < 32; i++)
        k[i] = (u8)(i * 11 + 3);

    /* Sign. */
    u8 r[32], s[32];
    bool ok = cvmcrypt_ecdsa_sign(&key, hello_hash, 32, k, 32, r, s);
    ASSERT(ok);

    /* Import public key. */
    FILE* fp = fopen("/tmp/ec_pub_test.der", "rb");
    if (fp == NULL) {
        SKIPm("test pub not available");
    }
    u8 pub[512];
    usize pub_len = fread(pub, 1, sizeof(pub), fp);
    fclose(fp);

    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_import_spki(&pt, pub, pub_len));

    /* Verify our signature. */
    ASSERT(cvmcrypt_ecdsa_verify(&pt, hello_hash, 32, r, 32, s, 32));

    cvmcrypt_ec_free(&pt);
    cvmcrypt_ec_priv_free(&key);
    PASS();
}

SUITE(tls_sign) {
    RUN_TEST(rsa_pkcs8_import);
    RUN_TEST(rsa_sign_pkcs1_roundtrip);
    RUN_TEST(rsa_sign_pss_roundtrip);
    RUN_TEST(ec_pkcs8_import);
    RUN_TEST(ec_sign_roundtrip);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_sign);
    GREATEST_MAIN_END();
}
