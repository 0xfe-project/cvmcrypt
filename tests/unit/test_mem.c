/*
 * tests/unit/test_mem.c
 *
 * The four freestanding memory primitives: identity, overlap, and the
 * conventions the compiler relies on. The constant-time comparison is
 * tested for what it promises (equal / not equal) — its timing property
 * is a property of the loop's shape, which the test cannot measure.
 */

#include "vendor/greatest.h"

#include <stdlib.h>

/* macOS <string.h> (pulled in transitively by greatest.h -> stdio.h)
 * redefines memcpy/memmove/memset/memcmp as fortify macros, which clash
 * with the declarations in base/mem.h. Drop them before including it. */
#undef memcpy
#undef memmove
#undef memset
#undef memcmp

#include "base/mem.h"
#include "base/secure.h"
#include "base/types.h"

TEST memcpy_copies_bytes(void) {
    u8 src[16];
    u8 dst[16];
    for (usize i = 0; i < 16; i++) {
        src[i] = (u8)(i * 7 + 1);
        dst[i] = 0xff;
    }

    memcpy(dst, src, 16);
    for (usize i = 0; i < 16; i++) {
        ASSERT_EQ_FMT(src[i], dst[i], "%u");
    }
    PASS();
}

TEST memcpy_of_zero_bytes_changes_nothing(void) {
    u8 a = 0x11;
    u8 b = 0x22;
    memcpy(&b, &a, 0);
    ASSERT_EQ(b, 0x22);
    PASS();
}

TEST memset_fills(void) {
    u8 buf[32];
    memset(buf, 0xAB, sizeof(buf));
    for (usize i = 0; i < sizeof(buf); i++) {
        ASSERT_EQ(buf[i], 0xAB);
    }
    PASS();
}

TEST memcmp_compares_lexicographically(void) {
    u8 a[] = {0x00, 0x01, 0x02};
    u8 b[] = {0x00, 0x01, 0x03};
    ASSERT_EQ(0, memcmp(a, a, 3));
    ASSERT(memcmp(a, b, 3) < 0);
    ASSERT(memcmp(b, a, 3) > 0);
    PASS();
}

TEST memmove_handles_overlap_up(void) {
    u8 buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    /* Shift right by 2: src and dst overlap. */
    memmove(buf + 2, buf, 6);
    ASSERT_EQ(buf[2], 1);
    ASSERT_EQ(buf[3], 2);
    ASSERT_EQ(buf[7], 6);
    /* Untouched. */
    ASSERT_EQ(buf[0], 1);
    ASSERT_EQ(buf[1], 2);
    PASS();
}

TEST memmove_handles_overlap_down(void) {
    u8 buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    /* Shift left by 2. */
    memmove(buf, buf + 2, 6);
    ASSERT_EQ(buf[0], 3);
    ASSERT_EQ(buf[1], 4);
    ASSERT_EQ(buf[5], 8);
    PASS();
}

TEST ct_eq_matches_memcmp_verdict(void) {
    u8 a[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    u8 b[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    u8 c[4] = {0xAA, 0xBB, 0xCC, 0xDE};
    u8 d[4] = {0x00, 0xBB, 0xCC, 0xDD};

    ASSERT(cvmcrypt_ct_eq(a, b, 4));
    ASSERT_FALSE(cvmcrypt_ct_eq(a, c, 4));
    ASSERT_FALSE(cvmcrypt_ct_eq(a, d, 4));
    ASSERT(cvmcrypt_ct_eq(a, a, 4));
    /* Zero-length: equal by definition. */
    ASSERT(cvmcrypt_ct_eq(a, b, 0));
    PASS();
}

SUITE(base_mem) {
    RUN_TEST(memcpy_copies_bytes);
    RUN_TEST(memcpy_of_zero_bytes_changes_nothing);
    RUN_TEST(memset_fills);
    RUN_TEST(memcmp_compares_lexicographically);
    RUN_TEST(memmove_handles_overlap_up);
    RUN_TEST(memmove_handles_overlap_down);
    RUN_TEST(ct_eq_matches_memcmp_verdict);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(base_mem);
    GREATEST_MAIN_END();
}
