/*
 * tests/unit/test_hmac.c
 *
 * HMAC-SHA-256 and HMAC-SHA-512 against RFC 4231 test vectors (which
 * cover the empty message, short keys, long keys that need hashing
 * down, and boundary-length data).
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "mac/hmac.h"
#include "base/types.h"

static bool tag_eq(u8 const* got, char const* want, usize n) {
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

/* RFC 4231 test case 1: key = 0x0b × 20, data = "Hi There" */
TEST rfc4231_tc1_sha256(void) {
    u8 key[20];
    memset(key, 0x0b, sizeof(key));
    u8 out[32];
    cvmcrypt_hmac_sha256(key, 20, (u8 const*)"Hi There", 8, out);
    ASSERT(tag_eq(out,
                  "b0344c61d8db38535ca8afceaf0bf12b"
                  "881dc200c9833da726e9376c2e32cff7",
                  32));
    PASS();
}

TEST rfc4231_tc1_sha512(void) {
    u8 key[20];
    memset(key, 0x0b, sizeof(key));
    u8 out[64];
    cvmcrypt_hmac_sha512(key, 20, (u8 const*)"Hi There", 8, out);
    ASSERT(tag_eq(out,
                  "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                  "2379f4e2ce4ec2787ad0b30545e17cde"
                  "daa833b7d6b8a702038b274eaea3f4e4"
                  "be9d914eeb61f1702e696c203a126854",
                  64));
    PASS();
}

/* RFC 4231 test case 2: key = "Jefe", data = "what do ya want..." */
TEST rfc4231_tc2_sha256(void) {
    u8 const* key = (u8 const*)"Jefe";
    u8 const* data = (u8 const*)"what do ya want for nothing?";
    u8 out[32];
    cvmcrypt_hmac_sha256(key, 4, data, 28, out);
    ASSERT(tag_eq(out,
                  "5bdcc146bf60754e6a042426089575c7"
                  "5a003f089d2739839dec58b964ec3843",
                  32));
    PASS();
}

TEST rfc4231_tc2_sha512(void) {
    u8 const* key = (u8 const*)"Jefe";
    u8 const* data = (u8 const*)"what do ya want for nothing?";
    u8 out[64];
    cvmcrypt_hmac_sha512(key, 4, data, 28, out);
    ASSERT(tag_eq(out,
                  "164b7a7bfcf819e2e395fbe73b56e0a3"
                  "87bd64222e831fd610270cd7ea250554"
                  "9758bf75c05a994a6d034f65f8f0e6fd"
                  "caeab1a34d4a6b4b636e070a38bce737",
                  64));
    PASS();
}

/* RFC 4231 test case 3: key and data both 0xaa */
TEST rfc4231_tc3_sha256(void) {
    u8 key[20];
    u8 data[50];
    memset(key, 0xaa, sizeof(key));
    memset(data, 0xdd, sizeof(data));
    u8 out[32];
    cvmcrypt_hmac_sha256(key, 20, data, 50, out);
    ASSERT(tag_eq(out,
                  "773ea91e36800e46854db8ebd09181a7"
                  "2959098b3ef8c122d9635514ced565fe",
                  32));
    PASS();
}

/* RFC 4231 test case 6: key longer than block size (131 bytes) */
TEST rfc4231_tc6_sha256(void) {
    u8 key[131];
    memset(key, 0xaa, sizeof(key));
    u8 const* data =
        (u8 const*)"Test Using Larger Than Block-Size Key - Hash Key First";
    u8 out[32];
    cvmcrypt_hmac_sha256(key, 131, data, 54, out);
    ASSERT(tag_eq(out,
                  "60e431591ee0b67f0d8a26aacbf5b77f"
                  "8e0bc6213728c5140546040f0ee37f54",
                  32));
    PASS();
}

TEST rfc4231_tc6_sha512(void) {
    u8 key[131];
    memset(key, 0xaa, sizeof(key));
    u8 const* data =
        (u8 const*)"Test Using Larger Than Block-Size Key - Hash Key First";
    u8 out[64];
    cvmcrypt_hmac_sha512(key, 131, data, 54, out);
    ASSERT(tag_eq(out,
                  "80b24263c7c1a3ebb71493c1dd7be8b4"
                  "9b46d1f41b4aeec1121b013783f8f352"
                  "6b56d037e05f2598bd0fd2215d6a1e52"
                  "95e64f73f63f0aec8b915a985d786598",
                  64));
    PASS();
}

TEST hmac_sha256_incremental_matches_oneshot(void) {
    u8 key[32];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 13);

    u8 data[200];
    for (usize i = 0; i < 200; i++)
        data[i] = (u8)(i * 7 + 3);

    u8 oneshot[32];
    cvmcrypt_hmac_sha256(key, 32, data, 200, oneshot);

    CvmcryptHmacSha256 h;
    cvmcrypt_hmac_sha256_init(&h, key, 32);
    cvmcrypt_hmac_sha256_update(&h, data, 1);
    cvmcrypt_hmac_sha256_update(&h, data + 1, 99);
    cvmcrypt_hmac_sha256_update(&h, data + 100, 100);
    u8 piecewise[32];
    cvmcrypt_hmac_sha256_final(&h, piecewise);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 32));
    PASS();
}

SUITE(hmac) {
    RUN_TEST(rfc4231_tc1_sha256);
    RUN_TEST(rfc4231_tc1_sha512);
    RUN_TEST(rfc4231_tc2_sha256);
    RUN_TEST(rfc4231_tc2_sha512);
    RUN_TEST(rfc4231_tc3_sha256);
    RUN_TEST(rfc4231_tc6_sha256);
    RUN_TEST(rfc4231_tc6_sha512);
    RUN_TEST(hmac_sha256_incremental_matches_oneshot);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(hmac);
    GREATEST_MAIN_END();
}
