/*
 * tests/unit/test_chacha20.c
 *
 * ChaCha20 against RFC 8439 §2.4.2 (block function test) and §2.4.2
 * (encryption test).
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "stream/chacha20.h"
#include "base/types.h"

static bool bytes_eq(u8 const* got, char const* want, usize n) {
    for (usize i = 0; i < n; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

/* RFC 8439 §2.4.2 test vector */
TEST rfc8439_block(void) {
    u8 const key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    u8 const nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                          0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);

    u8 const pt[64] = {0}; /* "One block of keystream" */
    u8 ct[64];
    cvmcrypt_chacha20_xor(&c, pt, 64, ct);

    static char const expect[] = "10f1e7e4d13b5915500fdd1fa32071c4"
                                 "c7d1f4c733c068030422aa9ac3d46c4e"
                                 "d2826446079faa0914c2d705d98b02a2"
                                 "b5129cd1de164eb9cbd083e8a2503c4e";
    ASSERT(bytes_eq(ct, expect, 64));
    PASS();
}

/* RFC 8439 §2.4.2 encryption test (same key/nonce, counter=1) */
TEST rfc8439_encrypt(void) {
    u8 const key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    u8 const nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    /* "Ladies and Gentlemen of the class of '99: If I could offer you "
       "only one tip for the future, sunscreen would be it." */
    static char const msg[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    usize msglen = sizeof(msg) - 1;

    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);

    u8 ct[200];
    cvmcrypt_chacha20_xor(&c, (u8 const*)msg, msglen, ct);

    /* Round-trip. */
    CvmcryptChaCha20 d;
    cvmcrypt_chacha20_init(&d, key, 1, nonce);
    u8 rt[200];
    cvmcrypt_chacha20_xor(&d, ct, msglen, rt);
    ASSERT_EQ(0, memcmp(msg, rt, msglen));

    /* Check a few known bytes of ciphertext (start of block 1). */
    static char const expect_prefix[] = "6e2e359a2568f98041ba0728dd0d6981";
    ASSERT(bytes_eq(ct, expect_prefix, 16));
    PASS();
}

/* Multiple blocks: counter must increment. */
TEST multi_block(void) {
    u8 key[32];
    u8 nonce[12];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 3);
    for (usize i = 0; i < 12; i++)
        nonce[i] = (u8)(i * 5);

    u8 pt[200], ct[200], rt[200];
    for (usize i = 0; i < 200; i++)
        pt[i] = (u8)(i * 7);

    CvmcryptChaCha20 c;
    cvmcrypt_chacha20_init(&c, key, 1, nonce);
    cvmcrypt_chacha20_xor(&c, pt, 200, ct);

    /* Decrypt with fresh state. */
    CvmcryptChaCha20 d;
    cvmcrypt_chacha20_init(&d, key, 1, nonce);
    cvmcrypt_chacha20_xor(&d, ct, 200, rt);
    ASSERT_EQ(0, memcmp(pt, rt, 200));
    PASS();
}

/* Incremental (piecewise) must match one-shot. */
TEST incremental_matches_oneshot(void) {
    u8 key[32], nonce[12];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 11);
    for (usize i = 0; i < 12; i++)
        nonce[i] = (u8)(i * 7);

    u8 pt[150];
    for (usize i = 0; i < 150; i++)
        pt[i] = (u8)(i * 3);

    CvmcryptChaCha20 c1;
    cvmcrypt_chacha20_init(&c1, key, 1, nonce);
    u8 oneshot[150];
    cvmcrypt_chacha20_xor(&c1, pt, 150, oneshot);

    CvmcryptChaCha20 c2;
    cvmcrypt_chacha20_init(&c2, key, 1, nonce);
    u8 piecewise[150];
    cvmcrypt_chacha20_xor(&c2, pt, 1, piecewise);
    cvmcrypt_chacha20_xor(&c2, pt + 1, 63, piecewise + 1);
    cvmcrypt_chacha20_xor(&c2, pt + 64, 64, piecewise + 64);
    cvmcrypt_chacha20_xor(&c2, pt + 128, 22, piecewise + 128);

    ASSERT_EQ(0, memcmp(oneshot, piecewise, 150));
    PASS();
}

SUITE(chacha20) {
    RUN_TEST(rfc8439_block);
    RUN_TEST(rfc8439_encrypt);
    RUN_TEST(multi_block);
    RUN_TEST(incremental_matches_oneshot);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(chacha20);
    GREATEST_MAIN_END();
}
