/*
 * tests/unit/test_sha512.c
 *
 * SHA-512 and SHA-384 against the FIPS 180-4 known-answer vectors.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "hash/sha512.h"
#include "base/types.h"

static bool digest_eq_n(u8 const* got, char const* want, usize n) {
    usize want_len = strlen(want) / 2;
    if (want_len != n)
        return false;
    for (usize i = 0; i < n; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

TEST sha512_abc(void) {
    u8 d[64];
    cvmcrypt_sha512((u8 const*)"abc", 3, d);
    ASSERT(digest_eq_n(d,
                       "ddaf35a193617aba"
                       "cc417349ae204131"
                       "12e6fa4e89a97ea2"
                       "0a9eeee64b55d39a"
                       "2192992a274fc1a8"
                       "36ba3c23a3feebbd"
                       "454d4423643ce80e"
                       "2a9ac94fa54ca49f",
                       64));
    PASS();
}

TEST sha512_empty(void) {
    u8 d[64];
    cvmcrypt_sha512((u8 const*)"", 0, d);
    ASSERT(digest_eq_n(d,
                       "cf83e1357eefb8bd"
                       "f1542850d66d8007"
                       "d620e4050b5715dc"
                       "83f4a921d36ce9ce"
                       "47d0d13c5d85f2b0"
                       "ff8318d2877eec2f"
                       "63b931bd47417a81"
                       "a538327af927da3e",
                       64));
    PASS();
}

TEST sha384_abc(void) {
    u8 d[48];
    cvmcrypt_sha384((u8 const*)"abc", 3, d);
    ASSERT(digest_eq_n(d,
                       "cb00753f45a35e8b"
                       "b5a03d699ac65007"
                       "272c32ab0eded163"
                       "1a8b605a43ff5bed"
                       "8086072ba1e7cc23"
                       "58baeca134c825a7",
                       48));
    PASS();
}

TEST sha384_empty(void) {
    u8 d[48];
    cvmcrypt_sha384((u8 const*)"", 0, d);
    ASSERT(digest_eq_n(d,
                       "38b060a751ac9638"
                       "4cd9327eb1b1e36a"
                       "21fdb71114be0743"
                       "4c0cc7bf63f6e1da"
                       "274edebfe76f65fb"
                       "d51ad2f14898b95b",
                       48));
    PASS();
}

TEST sha512_incremental_matches_oneshot(void) {
    u8 data[300];
    for (usize i = 0; i < 300; i++)
        data[i] = (u8)(i * 37 + 11);

    u8 oneshot[64];
    cvmcrypt_sha512(data, 300, oneshot);

    CvmcryptSha512 md;
    cvmcrypt_sha512_init(&md);
    cvmcrypt_sha512_update(&md, data, 1);
    cvmcrypt_sha512_update(&md, data + 1, 127);
    cvmcrypt_sha512_update(&md, data + 128, 128);
    cvmcrypt_sha512_update(&md, data + 256, 44);
    u8 piecewise[64];
    cvmcrypt_sha512_final(&md, piecewise);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 64));
    PASS();
}

TEST sha384_incremental_matches_oneshot(void) {
    u8 data[300];
    for (usize i = 0; i < 300; i++)
        data[i] = (u8)(i * 37 + 11);

    u8 oneshot[48];
    cvmcrypt_sha384(data, 300, oneshot);

    CvmcryptSha512 md;
    cvmcrypt_sha384_init(&md);
    cvmcrypt_sha384_update(&md, data, 1);
    cvmcrypt_sha384_update(&md, data + 1, 127);
    cvmcrypt_sha384_update(&md, data + 128, 128);
    cvmcrypt_sha384_update(&md, data + 256, 44);
    u8 piecewise[48];
    cvmcrypt_sha384_final(&md, piecewise);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 48));
    PASS();
}

TEST impl_is_selected(void) {
    CvmcryptSha512 md;
    cvmcrypt_sha512_init(&md);
#if defined(__aarch64__)
    ASSERT_EQ(CVMCRYPT_SHA512_IMPL_ARM64, md.impl);
#else
    ASSERT_EQ(CVMCRYPT_SHA512_IMPL_SCALAR, md.impl);
#endif
    PASS();
}

SUITE(sha512) {
    RUN_TEST(sha512_abc);
    RUN_TEST(sha512_empty);
    RUN_TEST(sha384_abc);
    RUN_TEST(sha384_empty);
    RUN_TEST(sha512_incremental_matches_oneshot);
    RUN_TEST(sha384_incremental_matches_oneshot);
    RUN_TEST(impl_is_selected);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(sha512);
    GREATEST_MAIN_END();
}
