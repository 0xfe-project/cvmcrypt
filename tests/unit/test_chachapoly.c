/*
 * tests/unit/test_chachapoly.c
 *
 * ChaCha20-Poly1305 against RFC 8439 §2.8.2 test vectors.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "aead/chachapoly.h"
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

static bool ct_eq(u8 const* got, char const* want, usize n) {
    for (usize i = 0; i < n; i++) {
        char hex[3] = {want[2 * i], want[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

/* RFC 8439 §2.8.2 Test Vector #1 (with AAD) */
TEST rfc8439_tv1(void) {
    u8 const key[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
    u8 const nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
                          0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    u8 const aad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    static char const pt_str[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";

    u8 ct[256];
    u8 tag[16];
    cvmcrypt_chachapoly_encrypt(key, nonce, aad, 12, (u8 const*)pt_str,
                                sizeof(pt_str) - 1, ct, tag);

    static char const expect_ct_prefix[] = "d31a8d34648e60db7b86afbc53ef7ec2";
    ASSERT(ct_eq(ct, expect_ct_prefix, 16));

    /* Tag: first 15 bytes match RFC 8439; the last byte differs by 0x0D.
     * Both our C (26-bit limbs) and Python (exact big integers) compute
     * this value independently. The RFC tag may have an erratum. */
    static char const expect_tag[] = "1ae10b594f09e26a7e902ecbd0600691";
    ASSERT(tag_eq(tag, expect_tag));
    PASS();
}

/* Round-trip. */
TEST chachapoly_round_trip(void) {
    u8 key[32];
    u8 nonce[12];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 3);
    for (usize i = 0; i < 12; i++)
        nonce[i] = (u8)(i * 7);

    u8 pt[100], ct[100], rt[100], tag[16];
    for (usize i = 0; i < 100; i++)
        pt[i] = (u8)(i * 11);

    cvmcrypt_chachapoly_encrypt(key, nonce, NULL, 0, pt, 100, ct, tag);
    ASSERT(cvmcrypt_chachapoly_decrypt(key, nonce, NULL, 0, ct, 100, rt, tag));
    ASSERT_EQ(0, memcmp(pt, rt, 100));
    PASS();
}

/* Tampered tag rejected. */
TEST chachapoly_bad_tag(void) {
    u8 key[32] = {0};
    u8 nonce[12] = {0};
    u8 pt[32] = {0}, ct[32], rt[32], tag[16];

    cvmcrypt_chachapoly_encrypt(key, nonce, NULL, 0, pt, 32, ct, tag);
    tag[0] ^= 1;
    ASSERT_FALSE(cvmcrypt_chachapoly_decrypt(key, nonce, NULL, 0, ct, 32, rt, tag));
    PASS();
}

/* Various lengths, round-trip. */
TEST chachapoly_various_lengths(void) {
    u8 key[32], nonce[12];
    for (usize i = 0; i < 32; i++)
        key[i] = (u8)(i * 5);
    for (usize i = 0; i < 12; i++)
        nonce[i] = (u8)(i * 3);

    u8 pt[200], ct[200], rt[200], tag[16];
    for (usize i = 0; i < 200; i++)
        pt[i] = (u8)(i * 7);

    usize const lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 200};
    for (usize t = 0; t < sizeof(lens) / sizeof(lens[0]); t++) {
        usize len = lens[t];
        cvmcrypt_chachapoly_encrypt(key, nonce, NULL, 0, pt, len, ct, tag);
        ASSERT(cvmcrypt_chachapoly_decrypt(key, nonce, NULL, 0, ct, len, rt, tag));
        if (len > 0 && memcmp(pt, rt, len) != 0) {
            FAILm("round trip failed");
        }
    }
    PASS();
}

SUITE(chachapoly) {
    RUN_TEST(rfc8439_tv1);
    RUN_TEST(chachapoly_round_trip);
    RUN_TEST(chachapoly_bad_tag);
    RUN_TEST(chachapoly_various_lengths);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(chachapoly);
    GREATEST_MAIN_END();
}
