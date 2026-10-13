/*
 * tests/unit/test_ecdsa.c
 *
 * P-256 ECDSA verify with real OpenSSL-generated test vectors.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "ecc/p256.h"
#include "base/types.h"

/* Generated with:
 *   openssl ecparam -name prime256v1 -genkey -noout -out ec_key.pem
 *   echo -n "hello" | openssl dgst -sha256 -sign ec_key.pem -out ec_sig.bin
 *   openssl ec -in ec_key.pem -pubout -outform DER -out ec_pub.der
 */

static u8 const test_ec_spki[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x1d, 0x07, 0xd0, 0xfd, 0xac, 0xfe, 0xb1, 0xd3, 0xbd, 0x63, 0x67, 0x6b,
    0xa2, 0x91, 0xd3, 0xaf, 0xd4, 0x53, 0xa6, 0x6a, 0x7a, 0xf5, 0x9c, 0x87, 0x92,
    0xbb, 0x26, 0x74, 0xaa, 0xd4, 0xcd, 0x1d, 0x52, 0x64, 0x6e, 0x06, 0x31, 0x74,
    0xde, 0x9a, 0xfc, 0xc9, 0x90, 0x00, 0x10, 0x77, 0xd0, 0x72, 0x8b, 0x58, 0xbe,
    0xde, 0xbe, 0x06, 0xd8, 0x4a, 0xd0, 0x31, 0x10, 0x5e, 0x5a, 0x84, 0xbc, 0xfb,
};

static u8 const test_ec_r[] = {
    0xc6, 0xa5, 0x99, 0x8b, 0x52, 0xe2, 0x04, 0x24, 0xae, 0x9f, 0x47,
    0x3b, 0x14, 0xa0, 0xb7, 0xab, 0x00, 0x5e, 0xd6, 0xae, 0xc4, 0x9f,
    0x34, 0xb1, 0xe2, 0x8e, 0xe5, 0x3f, 0x85, 0x00, 0x6e, 0x52,
};

static u8 const test_ec_s[] = {
    0xd5, 0xc3, 0xf0, 0x5e, 0xce, 0x20, 0xbb, 0x68, 0xe3, 0x7e, 0xfc,
    0x93, 0xcb, 0xbc, 0xd0, 0xf9, 0x59, 0x5e, 0xdd, 0x79, 0x34, 0x72,
    0x9c, 0x75, 0xb3, 0x75, 0x36, 0x47, 0x8e, 0x8b, 0x8f, 0xbe,
};

static u8 const test_ec_hash[] = {
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b,
    0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
    0x42, 0x5e, 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
};

TEST ec_spki_import(void) {
    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_import_spki(&pt, test_ec_spki, sizeof(test_ec_spki)));
    ASSERT(!cvmcrypt_mpi_is_zero(&pt.x));
    ASSERT(!cvmcrypt_mpi_is_zero(&pt.y));
    cvmcrypt_ec_free(&pt);
    PASS();
}

TEST ec_verify_valid(void) {
    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_import_spki(&pt, test_ec_spki, sizeof(test_ec_spki)));

    bool ok = cvmcrypt_ecdsa_verify(&pt, test_ec_hash, sizeof(test_ec_hash), test_ec_r,
                                    sizeof(test_ec_r), test_ec_s, sizeof(test_ec_s));
    ASSERT(ok);
    cvmcrypt_ec_free(&pt);
    PASS();
}

TEST ec_verify_tampered_r(void) {
    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_import_spki(&pt, test_ec_spki, sizeof(test_ec_spki)));

    u8 bad_r[32];
    memcpy(bad_r, test_ec_r, 32);
    bad_r[0] ^= 0x01; /* flip one bit */

    bool ok = cvmcrypt_ecdsa_verify(&pt, test_ec_hash, sizeof(test_ec_hash), bad_r,
                                    sizeof(bad_r), test_ec_s, sizeof(test_ec_s));
    ASSERT(!ok); /* must reject */
    cvmcrypt_ec_free(&pt);
    PASS();
}

TEST ec_verify_tampered_hash(void) {
    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    ASSERT_EQ(EC_OK, cvmcrypt_ec_import_spki(&pt, test_ec_spki, sizeof(test_ec_spki)));

    u8 bad_hash[32];
    memcpy(bad_hash, test_ec_hash, 32);
    bad_hash[0] ^= 0x01;

    bool ok = cvmcrypt_ecdsa_verify(&pt, bad_hash, sizeof(bad_hash), test_ec_r,
                                    sizeof(test_ec_r), test_ec_s, sizeof(test_ec_s));
    ASSERT(!ok); /* must reject */
    cvmcrypt_ec_free(&pt);
    PASS();
}

TEST ec_bad_input(void) {
    CvmEcPoint pt;
    cvmcrypt_ec_init(&pt);
    /* Wrong OID */
    ASSERT_EQ(EC_ERR_PARSE,
              cvmcrypt_ec_import_spki(&pt, test_ec_hash, sizeof(test_ec_hash)));
    /* Bad point format */
    u8 bad_point[64] = {0};
    ASSERT_EQ(EC_ERR_PARSE,
              cvmcrypt_ec_import_point(&pt, bad_point, sizeof(bad_point)));
    cvmcrypt_ec_free(&pt);
    PASS();
}

SUITE(ecdsa) {
    RUN_TEST(ec_spki_import);
    RUN_TEST(ec_verify_valid);
    RUN_TEST(ec_verify_tampered_r);
    RUN_TEST(ec_verify_tampered_hash);
    RUN_TEST(ec_bad_input);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(ecdsa);
    GREATEST_MAIN_END();
}
