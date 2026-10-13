/*
 * tests/unit/test_aes.c
 *
 * AES-128/192/256 against FIPS 197 Appendix C known-answer vectors.
 * Round-trip encrypt→decrypt is also verified for all key sizes.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "cipher/aes.h"
#include "base/types.h"

static bool block_eq(u8 const* got, char const* want) {
    for (usize i = 0; i < 16; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

/* FIPS 197 Appendix C.1 — AES-128 */
TEST fips197_aes128(void) {
    u8 const key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    u8 const pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 ct[16], rt[16];

    CvmcryptAesKey k;
    ASSERT(cvmcrypt_aes_setup(&k, key, 16));
    ASSERT_EQ((u32)10, k.rounds);

    cvmcrypt_aes_encrypt_block(&k, pt, ct);
    ASSERT(block_eq(ct, "69c4e0d86a7b0430d8cdb78070b4c55a"));

    cvmcrypt_aes_decrypt_block(&k, ct, rt);
    ASSERT_EQ(0, memcmp(pt, rt, 16));
    PASS();
}

/* FIPS 197 Appendix C.2 — AES-192 */
TEST fips197_aes192(void) {
    u8 const key[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    u8 const pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 ct[16], rt[16];

    CvmcryptAesKey k;
    ASSERT(cvmcrypt_aes_setup(&k, key, 24));
    ASSERT_EQ((u32)12, k.rounds);

    cvmcrypt_aes_encrypt_block(&k, pt, ct);
    ASSERT(block_eq(ct, "dda97ca4864cdfe06eaf70a0ec0d7191"));

    cvmcrypt_aes_decrypt_block(&k, ct, rt);
    ASSERT_EQ(0, memcmp(pt, rt, 16));
    PASS();
}

/* FIPS 197 Appendix C.3 — AES-256 */
TEST fips197_aes256(void) {
    u8 const key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    u8 const pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 ct[16], rt[16];

    CvmcryptAesKey k;
    ASSERT(cvmcrypt_aes_setup(&k, key, 32));
    ASSERT_EQ((u32)14, k.rounds);

    cvmcrypt_aes_encrypt_block(&k, pt, ct);
    ASSERT(block_eq(ct, "8ea2b7ca516745bfeafc49904b496089"));

    cvmcrypt_aes_decrypt_block(&k, ct, rt);
    ASSERT_EQ(0, memcmp(pt, rt, 16));
    PASS();
}

TEST invalid_key_length_rejected(void) {
    CvmcryptAesKey k;
    u8 key[20] = {0};
    ASSERT_FALSE(cvmcrypt_aes_setup(&k, key, 20));
    ASSERT_FALSE(cvmcrypt_aes_setup(&k, key, 0));
    ASSERT_FALSE(cvmcrypt_aes_setup(&k, key, 33));
    PASS();
}

TEST round_trip_many_blocks(void) {
    CvmcryptAesKey k;
    u8 key[32];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 11);

    ASSERT(cvmcrypt_aes_setup(&k, key, 32));

    for (usize b = 0; b < 100; b++) {
        u8 pt[16], ct[16], rt[16];
        for (usize i = 0; i < 16; i++)
            pt[i] = (u8)(b * 16 + i);
        cvmcrypt_aes_encrypt_block(&k, pt, ct);
        cvmcrypt_aes_decrypt_block(&k, ct, rt);
        if (memcmp(pt, rt, 16) != 0) {
            FAILm("round trip failed");
        }
    }
    PASS();
}

SUITE(aes) {
    RUN_TEST(fips197_aes128);
    RUN_TEST(fips197_aes192);
    RUN_TEST(fips197_aes256);
    RUN_TEST(invalid_key_length_rejected);
    RUN_TEST(round_trip_many_blocks);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(aes);
    GREATEST_MAIN_END();
}
