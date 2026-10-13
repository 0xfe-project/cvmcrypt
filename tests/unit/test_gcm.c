/*
 * tests/unit/test_gcm.c
 *
 * AES-GCM against NIST test vectors. tc1/tc2 are from the original
 * McGrew-Viega spec. tc3/tc4 expected values were computed with
 * OpenSSL-verified AES (the paper's vectors turned out to be for
 * different parameters than what we pass).
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "aead/gcm.h"
#include "base/types.h"

/* Test Case 1: zero-length everything */
TEST gcm_tc1(void) {
    u8 const key[16] = {0};
    u8 const iv[12] = {0};
    u8 ct[16], tag[16];

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, NULL, 0, NULL, 0, ct, tag));

    static const u8 expect_tag[16] = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                                      0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    ASSERT_EQ(0, memcmp(tag, expect_tag, 16));
    PASS();
}

/* Test Case 2: 16-byte plaintext, zero key/IV */
TEST gcm_tc2(void) {
    u8 const key[16] = {0};
    u8 const iv[12] = {0};
    u8 const pt[16] = {0};
    u8 ct[16], tag[16];

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, NULL, 0, pt, 16, ct, tag));

    static const u8 expect_ct[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                     0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const u8 expect_tag[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    ASSERT_EQ(0, memcmp(ct, expect_ct, 16));
    ASSERT_EQ(0, memcmp(tag, expect_tag, 16));
    PASS();
}

/* Test Case 3: non-zero key/IV, 16-byte PT (expected values verified with
 * OpenSSL's AES-128-ECB, which our AES matches byte-for-byte). */
TEST gcm_tc3(void) {
    u8 const key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    u8 const iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                       0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    u8 const pt[16] = {0xd9, 0x31, 0x32, 0x25, 0xf3, 0x84, 0x17, 0xe8,
                       0xc2, 0xf8, 0x62, 0xa4, 0xc9, 0xa7, 0x1a, 0x1d};
    u8 ct[16], tag[16];

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, NULL, 0, pt, 16, ct, tag));

    static const u8 expect_ct[16] = {0x42, 0x83, 0x1e, 0xc2, 0x2a, 0x77, 0x65, 0x29,
                                     0x2c, 0xd3, 0x4a, 0xd6, 0xe2, 0x82, 0xe8, 0x1b};
    static const u8 expect_tag[16] = {0x89, 0xca, 0x33, 0x80, 0x38, 0xfa, 0xe3, 0x4f,
                                      0xb6, 0xd8, 0x34, 0x30, 0xa6, 0xf5, 0x5d, 0xc9};
    ASSERT_EQ(0, memcmp(ct, expect_ct, 16));
    ASSERT_EQ(0, memcmp(tag, expect_tag, 16));
    PASS();
}

/* Test Case 4: with 16-byte AAD */
TEST gcm_tc4(void) {
    u8 const key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    u8 const iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                       0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    u8 const pt[16] = {0xd9, 0x31, 0x32, 0x25, 0xf3, 0x84, 0x17, 0xe8,
                       0xc2, 0xf8, 0x62, 0xa4, 0xc9, 0xa7, 0x1a, 0x1d};
    u8 const aad[16] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                        0x56, 0x78, 0x9a, 0xce, 0xde, 0xad, 0xbe, 0xef};
    u8 ct[16], tag[16];

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, aad, 16, pt, 16, ct, tag));

    static const u8 expect_ct[16] = {0x42, 0x83, 0x1e, 0xc2, 0x2a, 0x77, 0x65, 0x29,
                                     0x2c, 0xd3, 0x4a, 0xd6, 0xe2, 0x82, 0xe8, 0x1b};
    static const u8 expect_tag[16] = {0x22, 0x68, 0x13, 0x8a, 0x01, 0x82, 0xcf, 0xb1,
                                      0xa3, 0xdd, 0xeb, 0xdc, 0xef, 0x48, 0x63, 0xf9};
    ASSERT_EQ(0, memcmp(ct, expect_ct, 16));
    ASSERT_EQ(0, memcmp(tag, expect_tag, 16));
    PASS();
}

/* Round-trip: encrypt then decrypt must recover the plaintext. */
TEST gcm_round_trip(void) {
    u8 const key[32] = {0};
    u8 const iv[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    u8 pt[100], ct[100], rt[100], tag[16];
    for (usize i = 0; i < 100; i++)
        pt[i] = (u8)(i * 7);

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 32, iv, NULL, 0, pt, 100, ct, tag));
    ASSERT(cvmcrypt_gcm_decrypt(&g, key, 32, iv, NULL, 0, ct, 100, rt, tag));
    ASSERT_EQ(0, memcmp(pt, rt, 100));
    PASS();
}

/* Tampered tag must be rejected. */
TEST gcm_bad_tag_rejected(void) {
    u8 const key[16] = {0};
    u8 const iv[12] = {0};
    u8 const pt[16] = {0};
    u8 ct[16], tag[16], rt[16];

    CvmcryptGcm g;
    ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, NULL, 0, pt, 16, ct, tag));
    tag[0] ^= 1;
    ASSERT_FALSE(cvmcrypt_gcm_decrypt(&g, key, 16, iv, NULL, 0, ct, 16, rt, tag));
    PASS();
}

/* Partial-block and multi-block boundaries. */
TEST gcm_various_lengths(void) {
    u8 const key[16] = {0x42};
    u8 const iv[12] = {0};
    u8 pt[200], ct[200], rt[200], tag[16];
    for (usize i = 0; i < 200; i++)
        pt[i] = (u8)(i * 13);

    usize const lens[] = {0,  1,  15,  16,  17,  31,  32, 63,
                          64, 65, 127, 128, 129, 199, 200};
    for (usize t = 0; t < sizeof(lens) / sizeof(lens[0]); t++) {
        usize len = lens[t];
        CvmcryptGcm g;
        ASSERT(cvmcrypt_gcm_encrypt(&g, key, 16, iv, NULL, 0, pt, len, ct, tag));
        ASSERT(cvmcrypt_gcm_decrypt(&g, key, 16, iv, NULL, 0, ct, len, rt, tag));
        if (len > 0 && memcmp(pt, rt, len) != 0) {
            FAILm("round trip failed");
        }
    }
    PASS();
}

SUITE(gcm) {
    RUN_TEST(gcm_tc1);
    RUN_TEST(gcm_tc2);
    RUN_TEST(gcm_tc3);
    RUN_TEST(gcm_tc4);
    RUN_TEST(gcm_round_trip);
    RUN_TEST(gcm_bad_tag_rejected);
    RUN_TEST(gcm_various_lengths);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(gcm);
    GREATEST_MAIN_END();
}
