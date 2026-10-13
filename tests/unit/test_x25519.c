/*
 * tests/unit/test_x25519.c
 *
 * X25519 against RFC 7748 §5.2 and §6.1 test vectors.
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "kx/x25519.h"
#include "base/types.h"

static bool hex_eq(u8 const* got, char const* want_hex, usize n) {
    for (usize i = 0; i < n; i++) {
        char hex[3] = {want_hex[2 * i], want_hex[2 * i + 1], 0};
        u8 expect = (u8)strtoul(hex, NULL, 16);
        if (got[i] != expect)
            return false;
    }
    return true;
}

/* RFC 7748 §5.2 Test Vector 1 */
TEST rfc7748_s5_2_tv1(void) {
    u8 scalar[32], point[32], out[32];
    for (usize i = 0; i < 32; i++) {
        scalar[i] = (u8)(i + 1);
        point[i] = (u8)(i + 1);
    }
    /* Actually the RFC uses specific hex values. Let me construct them. */
    /* Scalar: a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4 */
    static char const scalar_hex[] =
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    static char const point_hex[] =
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    static char const expect_hex[] =
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

    for (usize i = 0; i < 32; i++) {
        char h[3] = {scalar_hex[2 * i], scalar_hex[2 * i + 1], 0};
        scalar[i] = (u8)strtoul(h, NULL, 16);
        h[0] = point_hex[2 * i];
        h[1] = point_hex[2 * i + 1];
        point[i] = (u8)strtoul(h, NULL, 16);
    }

    cvmcrypt_x25519(out, scalar, point);
    ASSERT(hex_eq(out, expect_hex, 32));
    PASS();
}

/* RFC 7748 §5.2 Test Vector 2 */
TEST rfc7748_s5_2_tv2(void) {
    u8 scalar[32], point[32], out[32];
    static char const scalar_hex[] =
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
    static char const point_hex[] =
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
    static char const expect_hex[] =
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

    for (usize i = 0; i < 32; i++) {
        char h[3] = {scalar_hex[2 * i], scalar_hex[2 * i + 1], 0};
        scalar[i] = (u8)strtoul(h, NULL, 16);
        h[0] = point_hex[2 * i];
        h[1] = point_hex[2 * i + 1];
        point[i] = (u8)strtoul(h, NULL, 16);
    }

    cvmcrypt_x25519(out, scalar, point);
    ASSERT(hex_eq(out, expect_hex, 32));
    PASS();
}

/* RFC 7748 §6.1 Diffie-Hellman */
TEST rfc7748_dh(void) {
    /* Alice's private key: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a */
    u8 alice_priv[32], alice_pub[32];
    /* Bob's private key: 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb */
    u8 bob_priv[32], bob_pub[32];
    /* Shared: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742 */
    u8 shared_alice[32], shared_bob[32];

    static char const alice_priv_hex[] =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    static char const alice_pub_hex[] =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    static char const bob_priv_hex[] =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    static char const bob_pub_hex[] =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    static char const shared_hex[] =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    for (usize i = 0; i < 32; i++) {
        char h[3];
        h[0] = alice_priv_hex[2 * i];
        h[1] = alice_priv_hex[2 * i + 1];
        alice_priv[i] = (u8)strtoul(h, NULL, 16);
        h[0] = bob_priv_hex[2 * i];
        h[1] = bob_priv_hex[2 * i + 1];
        bob_priv[i] = (u8)strtoul(h, NULL, 16);
    }

    /* Generate public keys. */
    cvmcrypt_x25519_base(alice_pub, alice_priv);
    cvmcrypt_x25519_base(bob_pub, bob_priv);

    ASSERT(hex_eq(alice_pub, alice_pub_hex, 32));
    ASSERT(hex_eq(bob_pub, bob_pub_hex, 32));

    /* Both sides derive the same shared secret. */
    cvmcrypt_x25519_shared(shared_alice, alice_priv, bob_pub);
    cvmcrypt_x25519_shared(shared_bob, bob_priv, alice_pub);

    ASSERT(hex_eq(shared_alice, shared_hex, 32));
    ASSERT_EQ(0, memcmp(shared_alice, shared_bob, 32));
    PASS();
}

/* Iterated test: 1 iteration of the RFC 7748 §5.2 loop. */
TEST rfc7748_iterated(void) {
    u8 k[32], u[32], out[32];
    /* Initial: k = 09 00...00, u = 09 00...00 */
    memset(k, 0, 32);
    k[0] = 9;
    memset(u, 0, 32);
    u[0] = 9;

    for (usize iter = 0; iter < 1; iter++) {
        cvmcrypt_x25519(out, k, u);
        memcpy(u, k, 32);
        memcpy(k, out, 32);
    }
    /* After 1 iteration, the expected result is from RFC 7748 §5.2. */
    static char const expect[] =
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
    ASSERT(hex_eq(k, expect, 32));
    PASS();
}

SUITE(x25519) {
    RUN_TEST(rfc7748_s5_2_tv1);
    RUN_TEST(rfc7748_s5_2_tv2);
    RUN_TEST(rfc7748_dh);
    RUN_TEST(rfc7748_iterated);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(x25519);
    GREATEST_MAIN_END();
}
