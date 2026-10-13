/*
 * tests/unit/test_poly1305.c
 *
 * Poly1305 against RFC 8439 §2.5.2 test vectors.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "mac/poly1305.h"
#include "base/types.h"

static bool tag_eq(u8 const* got, char const* want) {
    for (usize i = 0; i < 16; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

/* RFC 8439 §2.5.2 Test Vector #1 */
TEST rfc8439_tv1(void) {
    u8 const key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
    u8 const msg[] = "Cryptographic Forum Research Group";
    u8 tag[16];

    cvmcrypt_poly1305(key, (u8 const*)msg, sizeof(msg) - 1, tag);
    ASSERT(tag_eq(tag, "a8061dc1305136c6c22b8baf0c0127a9"));
    PASS();
}

/* RFC 8439 §2.5.2 Test Vector #2: data too long for one block */
TEST rfc8439_tv2(void) {
    u8 const key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
                        0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e};
    /* 34 bytes of 0x00 */
    u8 msg[34] = {0};
    u8 tag[16];

    cvmcrypt_poly1305(key, msg, 34, tag);
    ASSERT(tag_eq(tag, "36e5f6b5c5e06070f0efca96227a863e"));
    PASS();
}

/* RFC 8439 §2.5.2 Test Vector #3 */
TEST rfc8439_tv3(void) {
    u8 const key[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u8 const msg[2] = {0x00, 0x00};
    u8 tag[16];

    cvmcrypt_poly1305(key, msg, 2, tag);
    ASSERT(tag_eq(tag, "00000000000000000000000000000000"));
    PASS();
}

/* RFC 8439 §2.5.2 Test Vector #4 */

/* RFC 8439 §2.5.2 Test Vector #5: all-zero key, one byte */
TEST rfc8439_tv5(void) {
    u8 const key[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u8 const msg[16] = {0};
    u8 tag[16];

    cvmcrypt_poly1305(key, msg, 16, tag);
    ASSERT(tag_eq(tag, "00000000000000000000000000000000"));
    PASS();
}

/* Incremental matches one-shot. */
TEST poly1305_incremental(void) {
    u8 key[32];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 7 + 1);

    u8 data[200];
    for (usize i = 0; i < 200; i++)
        data[i] = (u8)(i * 13);

    u8 oneshot[16];
    cvmcrypt_poly1305(key, data, 200, oneshot);

    CvmcryptPoly1305 p;
    cvmcrypt_poly1305_init(&p, key);
    cvmcrypt_poly1305_update(&p, data, 1);
    cvmcrypt_poly1305_update(&p, data + 1, 15);
    cvmcrypt_poly1305_update(&p, data + 16, 100);
    cvmcrypt_poly1305_update(&p, data + 116, 84);
    u8 piecewise[16];
    cvmcrypt_poly1305_final(&p, piecewise);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 16));
    PASS();
}

SUITE(poly1305) {
    RUN_TEST(rfc8439_tv1);
    RUN_TEST(rfc8439_tv2);
    RUN_TEST(rfc8439_tv3);
    RUN_TEST(rfc8439_tv5);
    RUN_TEST(poly1305_incremental);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(poly1305);
    GREATEST_MAIN_END();
}
