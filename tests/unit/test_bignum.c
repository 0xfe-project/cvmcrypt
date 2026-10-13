/*
 * tests/unit/test_bignum.c
 *
 * Bignum operations against known values.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "math/bignum.h"
#include "base/types.h"

TEST mpi_init_free(void) {
    CvmMpi a;
    cvmcrypt_mpi_init(&a);
    ASSERT_EQ(0, a.n);
    ASSERT(a.p == NULL);
    ASSERT_EQ(1, a.s);
    cvmcrypt_mpi_free(&a);
    ASSERT(a.p == NULL);
    PASS();
}

TEST mpi_read_write_binary(void) {
    CvmMpi a;
    cvmcrypt_mpi_init(&a);

    /* Write 0x123456789ABCDEF0 in big-endian. */
    u8 const buf[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    ASSERT(cvmcrypt_mpi_read_binary(&a, buf, 8));
    ASSERT_EQ(1, a.n);
    ASSERT_EQ(0x123456789ABCDEF0ULL, a.p[0]);

    /* Write back. */
    u8 out[8];
    ASSERT(cvmcrypt_mpi_write_binary(&a, out, 8));
    ASSERT_EQ(0, memcmp(buf, out, 8));

    cvmcrypt_mpi_free(&a);
    PASS();
}

TEST mpi_add_sub(void) {
    CvmMpi a, b, c;
    cvmcrypt_mpi_init(&a);
    cvmcrypt_mpi_init(&b);
    cvmcrypt_mpi_init(&c);

    /* a = 0xFFFFFFFFFFFFFFFF (max u64) */
    u8 max[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT(cvmcrypt_mpi_read_binary(&a, max, 8));

    /* b = 1 */
    u8 one[1] = {1};
    ASSERT(cvmcrypt_mpi_read_binary(&b, one, 1));

    /* c = a + b = 0x10000000000000000 (2^64) */
    ASSERT(cvmcrypt_mpi_add_abs(&c, &a, &b));
    ASSERT_EQ(2, c.n);
    ASSERT_EQ(0, c.p[0]);
    ASSERT_EQ(1, c.p[1]);

    /* a = c - b = 0xFFFFFFFFFFFFFFFF */
    CvmMpi d;
    cvmcrypt_mpi_init(&d);
    ASSERT(cvmcrypt_mpi_sub_abs(&d, &c, &b));
    ASSERT_EQ(0, cvmcrypt_mpi_cmp_abs(&d, &a));

    cvmcrypt_mpi_free(&a);
    cvmcrypt_mpi_free(&b);
    cvmcrypt_mpi_free(&c);
    cvmcrypt_mpi_free(&d);
    PASS();
}

TEST mpi_mul(void) {
    CvmMpi a, b, c;
    cvmcrypt_mpi_init(&a);
    cvmcrypt_mpi_init(&b);
    cvmcrypt_mpi_init(&c);

    /* a = 0x12345678, b = 0x9ABCDEF0 */
    u8 abuf[4] = {0x12, 0x34, 0x56, 0x78};
    u8 bbuf[4] = {0x9A, 0xBC, 0xDE, 0xF0};
    ASSERT(cvmcrypt_mpi_read_binary(&a, abuf, 4));
    ASSERT(cvmcrypt_mpi_read_binary(&b, bbuf, 4));

    /* c = a * b */
    ASSERT(cvmcrypt_mpi_mul_mpi(&c, &a, &b));

    /* Verify: 0x12345678 * 0x9ABCDEF0 */
    u64 expected = (u64)0x12345678ULL * 0x9ABCDEF0ULL;
    ASSERT_EQ(1, c.n);
    ASSERT_EQ(expected, c.p[0]);

    cvmcrypt_mpi_free(&a);
    cvmcrypt_mpi_free(&b);
    cvmcrypt_mpi_free(&c);
    PASS();
}

TEST mpi_mul_large(void) {
    CvmMpi a, b, c;
    cvmcrypt_mpi_init(&a);
    cvmcrypt_mpi_init(&b);
    cvmcrypt_mpi_init(&c);

    /* a = b = 0xFFFFFFFFFFFFFFFF (max u64) */
    u8 max[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT(cvmcrypt_mpi_read_binary(&a, max, 8));
    ASSERT(cvmcrypt_mpi_read_binary(&b, max, 8));

    /* c = a * a = (2^64 - 1)^2 = 2^128 - 2^65 + 1 */
    ASSERT(cvmcrypt_mpi_mul_mpi(&c, &a, &b));
    ASSERT_EQ(2, c.n);
    ASSERT_EQ(1, c.p[0]);                  /* low limb = 1 */
    ASSERT_EQ(0xFFFFFFFFFFFFFFFE, c.p[1]); /* high limb = 2^64 - 2 */

    cvmcrypt_mpi_free(&a);
    cvmcrypt_mpi_free(&b);
    cvmcrypt_mpi_free(&c);
    PASS();
}

TEST mpi_div_mod(void) {
    CvmMpi a, b, q, r;
    cvmcrypt_mpi_init(&a);
    cvmcrypt_mpi_init(&b);
    cvmcrypt_mpi_init(&q);
    cvmcrypt_mpi_init(&r);

    /* a = 100, b = 7. q = 14, r = 2. */
    ASSERT(cvmcrypt_mpi_grow(&a, 1));
    ASSERT(cvmcrypt_mpi_grow(&b, 1));
    a.p[0] = 100;
    b.p[0] = 7;
    ASSERT(cvmcrypt_mpi_div_mpi(&q, &r, &a, &b));
    ASSERT(q.n >= 1);
    ASSERT_EQ(14, q.p[0]);
    ASSERT(r.n >= 1);
    ASSERT_EQ(2, r.p[0]);

    cvmcrypt_mpi_free(&a);
    cvmcrypt_mpi_free(&b);
    cvmcrypt_mpi_free(&q);
    cvmcrypt_mpi_free(&r);
    PASS();
}

TEST mpi_exp_mod(void) {
    CvmMpi a, e, n, r;
    cvmcrypt_mpi_init(&a);
    cvmcrypt_mpi_init(&e);
    cvmcrypt_mpi_init(&n);
    cvmcrypt_mpi_init(&r);

    /* 3^4 mod 7 = 81 mod 7 = 4 */
    ASSERT(cvmcrypt_mpi_grow(&a, 1));
    ASSERT(cvmcrypt_mpi_grow(&e, 1));
    ASSERT(cvmcrypt_mpi_grow(&n, 1));
    a.p[0] = 3;
    e.p[0] = 4;
    n.p[0] = 7;
    ASSERT(cvmcrypt_mpi_exp_mod(&r, &a, &e, &n));
    ASSERT(r.n >= 1);
    ASSERT_EQ(4, r.p[0]);

    /* 2^10 mod 1000 = 1024 mod 1000 = 24 */
    a.p[0] = 2;
    e.p[0] = 10;
    n.p[0] = 1000;
    ASSERT(cvmcrypt_mpi_exp_mod(&r, &a, &e, &n));
    ASSERT(r.n >= 1);
    ASSERT_EQ(24, r.p[0]);

    cvmcrypt_mpi_free(&a);
    cvmcrypt_mpi_free(&e);
    cvmcrypt_mpi_free(&n);
    cvmcrypt_mpi_free(&r);
    PASS();
}

TEST mpi_bitlen(void) {
    CvmMpi a;
    cvmcrypt_mpi_init(&a);
    ASSERT(cvmcrypt_mpi_grow(&a, 1));

    a.p[0] = 0;
    cvmcrypt_mpi_shrink(&a);
    ASSERT_EQ(0, cvmcrypt_mpi_bitlen(&a));

    cvmcrypt_mpi_grow(&a, 1);
    a.p[0] = 1;
    ASSERT_EQ(1, cvmcrypt_mpi_bitlen(&a));

    a.p[0] = 0xFF;
    ASSERT_EQ(8, cvmcrypt_mpi_bitlen(&a));

    a.p[0] = 0x100;
    ASSERT_EQ(9, cvmcrypt_mpi_bitlen(&a));

    a.p[0] = UINT64_MAX;
    ASSERT_EQ(64, cvmcrypt_mpi_bitlen(&a));

    cvmcrypt_mpi_free(&a);
    PASS();
}

SUITE(bignum) {
    RUN_TEST(mpi_init_free);
    RUN_TEST(mpi_read_write_binary);
    RUN_TEST(mpi_add_sub);
    RUN_TEST(mpi_mul);
    RUN_TEST(mpi_mul_large);
    RUN_TEST(mpi_div_mod);
    RUN_TEST(mpi_exp_mod);
    RUN_TEST(mpi_bitlen);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(bignum);
    GREATEST_MAIN_END();
}
