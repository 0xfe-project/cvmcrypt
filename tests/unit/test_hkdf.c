/*
 * tests/unit/test_hkdf.c
 *
 * HKDF against RFC 5869 test vectors (Appendix A).
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "kdf/hkdf.h"
#include "base/types.h"

static bool hex_eq(u8 const* got, char const* want, usize n) {
    for (usize i = 0; i < n; i++) {
        char h[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 e = (u8)strtoul(h, NULL, 16);
        if (got[i] != e)
            return false;
    }
    return true;
}

/* RFC 5869 Test Case 1: basic SHA-256 */
TEST rfc5869_tc1(void) {
    u8 ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    static u8 const salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    static u8 const info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    u8 okm[42];

    ASSERT(cvmcrypt_hkdf_sha256(okm, 42, salt, 13, ikm, 22, info, 10));
    static char const expect[] =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865";
    ASSERT(hex_eq(okm, expect, 42));
    PASS();
}

/* RFC 5869 Test Case 2: longer inputs */
TEST rfc5869_tc2(void) {
    u8 ikm[80], salt[80], info[80];
    for (usize i = 0; i < 80; i++) {
        ikm[i] = (u8)i;
        salt[i] = (u8)(0x60 + i);
        info[i] = (u8)(0xb0 + i);
    }
    u8 okm[82];

    ASSERT(cvmcrypt_hkdf_sha256(okm, 82, salt, 80, ikm, 80, info, 80));
    static char const expect[] =
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87";
    ASSERT(hex_eq(okm, expect, 82));
    PASS();
}

/* RFC 5869 Test Case 3: zero-length salt and info */
TEST rfc5869_tc3(void) {
    u8 ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    u8 okm[42];

    ASSERT(cvmcrypt_hkdf_sha256(okm, 42, NULL, 0, ikm, 22, NULL, 0));
    static char const expect[] =
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8";
    ASSERT(hex_eq(okm, expect, 42));
    PASS();
}

/* Verify extract and expand are correct independently. */
TEST extract_then_expand(void) {
    u8 salt[16], ikm[32];
    for (usize i = 0; i < 16; i++)
        salt[i] = (u8)(i * 3);
    for (usize i = 0; i < 32; i++)
        ikm[i] = (u8)(i * 7);

    u8 prk[32];
    cvmcrypt_hkdf_sha256_extract(prk, salt, 16, ikm, 32);

    u8 okm1[64];
    ASSERT(cvmcrypt_hkdf_sha256_expand(okm1, 64, prk, NULL, 0));

    u8 okm2[64];
    ASSERT(cvmcrypt_hkdf_sha256(okm2, 64, salt, 16, ikm, 32, NULL, 0));

    ASSERT_EQ(0, memcmp(okm1, okm2, 64));
    PASS();
}

SUITE(hkdf) {
    RUN_TEST(rfc5869_tc1);
    RUN_TEST(rfc5869_tc2);
    RUN_TEST(rfc5869_tc3);
    RUN_TEST(extract_then_expand);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(hkdf);
    GREATEST_MAIN_END();
}
