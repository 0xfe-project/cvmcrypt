/*
 * tests/unit/test_sha256.c
 *
 * SHA-256 against the NIST known-answer vectors. The "abc" and
 * "abcdbcdecdef..." cases are the two from FIPS 180-4's example set;
 * the rest exercise the padding paths and the incremental-matching
 * property.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "hash/sha256.h"
#include "base/types.h"

static bool digest_eq(u8 const* got, char const* want) {
    usize want_len = strlen(want) / 2;
    if (want_len != 32) {
        return false;
    }
    for (usize i = 0; i < 32; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect) {
            return false;
        }
    }
    return true;
}

TEST nist_abc(void) {
    u8 digest[32];
    cvmcrypt_sha256((u8 const*)"abc", 3, digest);
    ASSERT(digest_eq(digest, "ba7816bf8f01cfea414140de5dae2223"
                             "b00361a396177a9cb410ff61f20015ad"));
    PASS();
}

TEST nist_long_message(void) {
    u8 digest[32];
    cvmcrypt_sha256(
        (u8 const*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        digest);
    ASSERT(digest_eq(digest, "248d6a61d20638b8e5c026930c3e6039"
                             "a33ce45964ff2167f6ecedd419db06c1"));
    PASS();
}

TEST empty_input(void) {
    u8 digest[32];
    cvmcrypt_sha256((u8 const*)"", 0, digest);
    ASSERT(digest_eq(digest, "e3b0c44298fc1c149afbf4c8996fb924"
                             "27ae41e4649b934ca495991b7852b855"));
    PASS();
}

TEST incremental_matches_oneshot(void) {
    u8 data[200];
    for (usize i = 0; i < 200; i++) {
        data[i] = (u8)(i * 31 + 7);
    }

    u8 oneshot[32];
    cvmcrypt_sha256(data, 200, oneshot);

    CvmcryptSha256 md;
    cvmcrypt_sha256_init(&md);
    cvmcrypt_sha256_update(&md, data, 1);
    cvmcrypt_sha256_update(&md, data + 1, 63);
    cvmcrypt_sha256_update(&md, data + 64, 64);
    cvmcrypt_sha256_update(&md, data + 128, 65);
    cvmcrypt_sha256_update(&md, data + 193, 7);
    u8 piecewise[32];
    cvmcrypt_sha256_final(&md, piecewise);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 32));
    PASS();
}

TEST multi_block_chaining(void) {
    u8 data[1000];
    for (usize i = 0; i < 1000; i++) {
        data[i] = (u8)(i * 7);
    }
    u8 fast[32];
    cvmcrypt_sha256(data, 1000, fast);

    CvmcryptSha256 md;
    cvmcrypt_sha256_init(&md);
    for (usize i = 0; i < 1000; i++) {
        cvmcrypt_sha256_update(&md, data + i, 1);
    }
    u8 slow[32];
    cvmcrypt_sha256_final(&md, slow);

    ASSERT_EQ(0, memcmp(fast, slow, 32));
    PASS();
}

SUITE(sha256) {
    RUN_TEST(nist_abc);
    RUN_TEST(nist_long_message);
    RUN_TEST(empty_input);
    RUN_TEST(incremental_matches_oneshot);
    RUN_TEST(multi_block_chaining);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(sha256);
    GREATEST_MAIN_END();
}
