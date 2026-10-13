/*
 * tests/unit/test_der.c
 *
 * DER decoder: TLV parsing, integer decoding, OID, bit string.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "asn1/der.h"
#include "math/bignum.h"
#include "base/types.h"

/* INTEGER 0: 02 01 00 */
TEST der_integer_zero(void) {
    u8 const buf[] = {0x02, 0x01, 0x00};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT(cvmcrypt_mpi_is_zero(&n));
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* INTEGER 0x7F: 02 01 7F */
TEST der_integer_7f(void) {
    u8 const buf[] = {0x02, 0x01, 0x7F};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT_EQ(1, n.n);
    ASSERT_EQ(0x7F, n.p[0]);
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* INTEGER 128: 02 02 00 80 (leading zero for positive sign bit) */
TEST der_integer_128(void) {
    u8 const buf[] = {0x02, 0x02, 0x00, 0x80};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT_EQ(1, n.n);
    ASSERT_EQ(0x80, n.p[0]);
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* INTEGER 256: 02 02 01 00 */
TEST der_integer_256(void) {
    u8 const buf[] = {0x02, 0x02, 0x01, 0x00};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT_EQ(1, n.n);
    ASSERT_EQ(0x100, n.p[0]);
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* Long form length: INTEGER with 200-byte value (positive, 0x00 sign prefix). */
TEST der_long_length(void) {
    u8 buf[3 + 201]; /* 1 sign byte + 200 data bytes */
    buf[0] = 0x02;
    buf[1] = 0x81; /* long form, 1 length byte */
    buf[2] = 201;  /* 1 sign + 200 data */
    buf[3] = 0x00; /* sign byte: positive */
    memset(buf + 4, 0xAB, 200);

    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT(n.n >= 3); /* 200 bytes = 25 limbs */
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* SEQUENCE containing INTEGER and NULL. */
TEST der_sequence(void) {
    /* SEQUENCE { INTEGER 5, NULL } */
    u8 const buf[] = {0x30, 0x05, 0x02, 0x01, 0x05, 0x05, 0x00};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    DerCursor seq;
    ASSERT_EQ(DER_OK, der_read_sequence(&c, &seq));
    ASSERT_EQ(5, seq.remaining);

    /* Inside the sequence. */
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&seq, &n));
    ASSERT_EQ(5, n.p[0]);
    ASSERT_EQ(DER_OK, der_read_null(&seq));
    ASSERT_EQ(0, seq.remaining);
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* OID: 1.2.840.10045.2.1 (ecPublicKey) */
TEST der_oid(void) {
    /* OID 1.2.840.10045.2.1 = 06 07 2A 86 48 CE 3D 02 01 */
    u8 const buf[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    u8 const* oid;
    usize oid_len;
    ASSERT_EQ(DER_OK, der_read_oid(&c, &oid, &oid_len));
    ASSERT_EQ(7, oid_len);
    ASSERT_EQ(0x2A, oid[0]); /* 1.2 = 42 = 0x2A */
    PASS();
}

/* BIT STRING: RSA public key wrapper. */
TEST der_bit_string(void) {
    /* BIT STRING with 0 unused bits and 3 data bytes. */
    u8 const buf[] = {0x03, 0x04, 0x00, 0x01, 0x02, 0x03};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    u8 const* data;
    usize len;
    u8 unused;
    ASSERT_EQ(DER_OK, der_read_bit_string(&c, &data, &len, &unused));
    ASSERT_EQ(3, len);
    ASSERT_EQ(0, unused);
    ASSERT_EQ(1, data[0]);
    ASSERT_EQ(2, data[1]);
    ASSERT_EQ(3, data[2]);
    PASS();
}

/* Bad tag. */
TEST der_bad_tag(void) {
    u8 const buf[] = {0x05, 0x00}; /* NULL, not INTEGER */
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_ERR_BAD_TAG, der_read_integer(&c, &n));
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* Truncated input. */
TEST der_truncated(void) {
    u8 const buf[] = {0x02, 0x05, 0x01}; /* claims 5 bytes, only 1 present */
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_ERR_TRUNCATED, der_read_integer(&c, &n));
    cvmcrypt_mpi_free(&n);
    PASS();
}

/* BOOLEAN. */
TEST der_boolean(void) {
    u8 const buf[] = {0x01, 0x01, 0xFF};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    bool b;
    ASSERT_EQ(DER_OK, der_read_boolean(&c, &b));
    ASSERT(b);
    PASS();
}

/* Skip TLV. */
TEST der_skip(void) {
    /* SEQUENCE { INTEGER 1, INTEGER 2 } — skip the first. */
    u8 const buf[] = {0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    DerCursor c = der_cursor_init(buf, sizeof(buf));
    ASSERT_EQ(DER_OK, der_skip_tlv(&c));
    /* Second INTEGER should still be readable. */
    CvmMpi n;
    cvmcrypt_mpi_init(&n);
    ASSERT_EQ(DER_OK, der_read_integer(&c, &n));
    ASSERT_EQ(2, n.p[0]);
    cvmcrypt_mpi_free(&n);
    PASS();
}

SUITE(der) {
    RUN_TEST(der_integer_zero);
    RUN_TEST(der_integer_7f);
    RUN_TEST(der_integer_128);
    RUN_TEST(der_integer_256);
    RUN_TEST(der_long_length);
    RUN_TEST(der_sequence);
    RUN_TEST(der_oid);
    RUN_TEST(der_bit_string);
    RUN_TEST(der_bad_tag);
    RUN_TEST(der_truncated);
    RUN_TEST(der_boolean);
    RUN_TEST(der_skip);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(der);
    GREATEST_MAIN_END();
}
