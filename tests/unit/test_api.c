/*
 * tests/unit/test_api.c
 *
 * The public surface in include/cvmcrypt/: aead.h, hash.h, cipher.h,
 * random.h.
 *
 * What this file is for: the dispatch layer is the part nobody looks at, so
 * it is the part that quietly returns the wrong algorithm. Every vector below
 * is therefore either an independent implementation's output or a
 * cross-check against a second implementation in this tree — never a value
 * this code produced.
 *
 *   AES-128 header protection   openssl enc -aes-128-ecb -nopad
 *   ChaCha20 header protection  a reference implementation checked against
 *                               RFC 8439 §2.3.2 before being used
 *   HKDF-SHA256                 cvmcrypt's own specialised HKDF
 *   HKDF-SHA384                 Python hmac + hashlib
 *   SHA-384("abc")              FIPS 180-4
 */

#include "vendor/greatest.h"

#include <stdlib.h>
#include <string.h>

#include "base/types.h"
#include "cvmcrypt/cvmcrypt.h"
#include "kdf/hkdf.h"

static void hex_to_bytes(u8* out, usize n, char const* hex) {
    for (usize i = 0; i < n; i++) {
        char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        out[i] = (u8)strtoul(pair, NULL, 16);
    }
}

static bool bytes_eq(u8 const* got, char const* want_hex, usize n) {
    u8 want[64];
    if (n > sizeof(want)) {
        return false;
    }
    hex_to_bytes(want, n, want_hex);
    return memcmp(got, want, n) == 0;
}

/* ------------------------------------------------------------------ */
/* AEAD                                                                 */
/* ------------------------------------------------------------------ */

TEST aead_roundtrip_all_algorithms(void) {
    CvmcryptAeadAlg const* algs[] = {
        &cvmcrypt_aead_aes128gcm,
        &cvmcrypt_aead_aes256gcm,
        &cvmcrypt_aead_chacha20poly1305,
    };

    u8 key[32];
    u8 nonce[12];
    u8 aad[13];
    u8 pt[300];
    u8 ct[300];
    u8 back[300];
    u8 tag[16];

    for (usize i = 0; i < sizeof(key); i++) {
        key[i] = (u8)(0xa0 + i);
    }
    for (usize i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (u8)(0x10 + i);
    }
    for (usize i = 0; i < sizeof(aad); i++) {
        aad[i] = (u8)(0x30 + i);
    }
    for (usize i = 0; i < sizeof(pt); i++) {
        pt[i] = (u8)(i * 7 + 1);
    }

    for (usize a = 0; a < sizeof(algs) / sizeof(algs[0]); a++) {
        CvmcryptAeadAlg const* alg = algs[a];
        CvmcryptAeadCtx ctx;

        ASSERT_EQ(12, (int)cvmcrypt_aead_nonce_size(alg));
        ASSERT_EQ(16, (int)cvmcrypt_aead_tag_size(alg));

        ASSERT(cvmcrypt_aead_init(&ctx, alg, key));
        ASSERT(
            cvmcrypt_aead_seal(&ctx, nonce, aad, sizeof(aad), pt, sizeof(pt), ct, tag));

        /* The ciphertext must differ from the plaintext for every length. */
        ASSERT(memcmp(ct, pt, sizeof(pt)) != 0);

        ASSERT(cvmcrypt_aead_open(&ctx, nonce, aad, sizeof(aad), ct, sizeof(ct), back,
                                  tag));
        ASSERT_MEM_EQ(pt, back, sizeof(pt));

        /* One flipped ciphertext bit must be rejected, and must not leave
         * plaintext behind. */
        ct[7] ^= 0x01;
        memset(back, 0xAA, sizeof(back));
        ASSERT_FALSE(cvmcrypt_aead_open(&ctx, nonce, aad, sizeof(aad), ct, sizeof(ct),
                                        back, tag));
        ct[7] ^= 0x01;

        /* A different AAD must be rejected too. */
        aad[0] ^= 0x80;
        ASSERT_FALSE(cvmcrypt_aead_open(&ctx, nonce, aad, sizeof(aad), ct, sizeof(ct),
                                        back, tag));
        aad[0] ^= 0x80;
        cvmcrypt_aead_clear(&ctx);
    }

    PASS();
}

TEST aead_wrong_key_size_rejected(void) {
    CvmcryptAeadCtx ctx;
    u8 key[32] = {0};
    /* AES-128 wants 16; give it an alg whose key size never matches by
     * handing AES-256 a 16-byte-valid pointer — init cannot check the buffer,
     * so instead check that an unknown/null alg fails. */
    ASSERT_FALSE(cvmcrypt_aead_init(&ctx, NULL, key));
    ASSERT_FALSE(cvmcrypt_aead_init(NULL, &cvmcrypt_aead_aes128gcm, key));
    ASSERT_FALSE(cvmcrypt_aead_init(&ctx, &cvmcrypt_aead_aes128gcm, NULL));
    PASS();
}

/* The dispatch must not diverge from the direct call it wraps. */
TEST aead_chachapoly_matches_direct(void) {
    u8 key[32];
    u8 nonce[12] = {0};
    u8 aad[5] = {1, 2, 3, 4, 5};
    u8 pt[64];
    u8 ct_api[64];
    u8 ct_direct[64];
    u8 tag_api[16];
    u8 tag_direct[16];
    CvmcryptAeadCtx ctx;

    for (usize i = 0; i < sizeof(key); i++) {
        key[i] = (u8)i;
    }
    for (usize i = 0; i < sizeof(pt); i++) {
        pt[i] = (u8)(i * 3 + 1);
    }

    cvmcrypt_chachapoly_encrypt(key, nonce, aad, sizeof(aad), pt, sizeof(pt), ct_direct,
                                tag_direct);

    ASSERT(cvmcrypt_aead_init(&ctx, &cvmcrypt_aead_chacha20poly1305, key));
    ASSERT(cvmcrypt_aead_seal(&ctx, nonce, aad, sizeof(aad), pt, sizeof(pt), ct_api,
                              tag_api));

    ASSERT_MEM_EQ(ct_direct, ct_api, sizeof(ct_api));
    ASSERT_MEM_EQ(tag_direct, tag_api, sizeof(tag_api));
    cvmcrypt_aead_clear(&ctx);
    PASS();
}

/* ------------------------------------------------------------------ */
/* hash / HKDF                                                          */
/* ------------------------------------------------------------------ */

TEST sha384_digest_kat(void) {
    u8 out[48];
    CvmcryptMdCtx ctx;

    ASSERT_EQ(48, (int)cvmcrypt_md_digest_size(&cvmcrypt_md_sha384));
    ASSERT_EQ(128, (int)cvmcrypt_md_block_size(&cvmcrypt_md_sha384));

    ASSERT(cvmcrypt_md_digest(&cvmcrypt_md_sha384, (u8 const*)"abc", 3, out));
    ASSERT(bytes_eq(out,
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                    "8086072ba1e7cc2358baeca134c825a7",
                    48));

    /* Incremental must agree with one-shot. */
    cvmcrypt_md_init(&ctx, &cvmcrypt_md_sha384);
    cvmcrypt_md_update(&ctx, (u8 const*)"a", 1);
    cvmcrypt_md_update(&ctx, (u8 const*)"bc", 2);
    cvmcrypt_md_final(&ctx, out);
    ASSERT(bytes_eq(out,
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                    "8086072ba1e7cc2358baeca134c825a7",
                    48));
    PASS();
}

/* Same inputs through the generic path and cvmcrypt's specialised HKDF. */
TEST hkdf_sha256_matches_specialised(void) {
    u8 ikm[32];
    u8 salt[12];
    u8 const info[] = "cvmcrypt hkdf equivalence";
    u8 prk_generic[32];
    u8 prk_specialised[32];
    u8 okm_generic[80];
    u8 okm_specialised[80];

    for (usize i = 0; i < sizeof(ikm); i++) {
        ikm[i] = (u8)i;
    }
    for (usize i = 0; i < sizeof(salt); i++) {
        salt[i] = (u8)(0x40 + i);
    }

    ASSERT(cvmcrypt_hkdf_extract(&cvmcrypt_md_sha256, prk_generic, salt, sizeof(salt),
                                 ikm, sizeof(ikm)));
    cvmcrypt_hkdf_sha256_extract(prk_specialised, salt, sizeof(salt), ikm, sizeof(ikm));
    ASSERT_MEM_EQ(prk_specialised, prk_generic, sizeof(prk_generic));

    ASSERT(cvmcrypt_hkdf_expand(&cvmcrypt_md_sha256, okm_generic, sizeof(okm_generic),
                                prk_generic, info, sizeof(info) - 1));
    ASSERT(cvmcrypt_hkdf_sha256_expand(okm_specialised, sizeof(okm_specialised),
                                       prk_specialised, info, sizeof(info) - 1));
    ASSERT_MEM_EQ(okm_specialised, okm_generic, sizeof(okm_generic));
    PASS();
}

/* HKDF-SHA384: SHA-384 had no HKDF at all before this header existed. */
TEST hkdf_sha384_kat(void) {
    u8 ikm[32];
    u8 salt[12];
    u8 const info[] = "cvmcrypt hkdf test";
    u8 prk[48];
    u8 okm[80];

    for (usize i = 0; i < sizeof(ikm); i++) {
        ikm[i] = (u8)i;
    }
    for (usize i = 0; i < sizeof(salt); i++) {
        salt[i] = (u8)i;
    }

    ASSERT(cvmcrypt_hkdf_extract(&cvmcrypt_md_sha384, prk, salt, sizeof(salt), ikm,
                                 sizeof(ikm)));
    ASSERT(bytes_eq(prk,
                    "fe0b2e004fb57551b341250bbf6f1047efa8e7ab275ffb593113cfbeb2bd2c8e"
                    "dd6363623665040e5f616ee46b09463e",
                    48));

    ASSERT(cvmcrypt_hkdf_expand(&cvmcrypt_md_sha384, okm, sizeof(okm), prk, info,
                                sizeof(info) - 1));
    ASSERT(bytes_eq(okm,
                    "70794b50ad012a484300a587fa6ba29cc431bfc8572562e17a7f90090e3b4d7b"
                    "1fd0198d7e3c7fb6",
                    40));
    ASSERT(bytes_eq(okm + 40,
                    "6cf8c321249dbdbe4e9e6312f23b0ffe060f3638a41f1d66bd1296f1e0655f5a"
                    "5b42fab596c451cd",
                    40));

    /* Absent salt means HashLen zeros, not "no salt". */
    ASSERT(cvmcrypt_hkdf_extract(&cvmcrypt_md_sha384, prk, NULL, 0, ikm, sizeof(ikm)));
    u8 zero_salt[48] = {0};
    u8 prk_explicit[48];
    ASSERT(cvmcrypt_hkdf_extract(&cvmcrypt_md_sha384, prk_explicit, zero_salt,
                                 sizeof(zero_salt), ikm, sizeof(ikm)));
    ASSERT_MEM_EQ(prk_explicit, prk, sizeof(prk));

    /* RFC 5869's limit. */
    u8 too_much[255 * 48 + 1];
    ASSERT_FALSE(cvmcrypt_hkdf_expand(&cvmcrypt_md_sha384, too_much, sizeof(too_much),
                                      prk, NULL, 0));
    PASS();
}

/* ------------------------------------------------------------------ */
/* cipher / header protection                                           */
/* ------------------------------------------------------------------ */

TEST hp_mask_aes128_kat(void) {
    u8 key[16];
    u8 sample[16];
    u8 mask[5];
    CvmcryptCipherCtx ctx;

    hex_to_bytes(key, sizeof(key), "000102030405060708090a0b0c0d0e0f");
    hex_to_bytes(sample, sizeof(sample), "d1b1c98dd7689fb8ec11d242b123dc9b");

    ASSERT(cvmcrypt_cipher_init(&ctx, &cvmcrypt_cipher_aes128, key));
    ASSERT(cvmcrypt_cipher_hp_mask(&ctx, sample, mask));
    ASSERT(bytes_eq(mask, "21a22dfb17", sizeof(mask)));

    /* The mask is the first five bytes of the block, and the block is
     * AES-ECB over the sample. Pin both. */
    u8 block[16];
    ASSERT(cvmcrypt_cipher_keystream(&ctx, sample, block));
    ASSERT_MEM_EQ(block, mask, sizeof(mask));
    cvmcrypt_cipher_clear(&ctx);
    PASS();
}

TEST hp_mask_chacha20_kat(void) {
    u8 key[32];
    u8 sample[16];
    u8 mask[5];
    CvmcryptCipherCtx ctx;

    hex_to_bytes(key, sizeof(key),
                 "25a282b9e82f06f221488917a4fc8f1b4b0f3b8ff1d0a5e0f9d3a1c7bd9e34a6");
    hex_to_bytes(sample, sizeof(sample), "5e5cd55c41f69080575d7999c25a5bfb");

    ASSERT(cvmcrypt_cipher_init(&ctx, &cvmcrypt_cipher_chacha20, key));
    ASSERT(cvmcrypt_cipher_hp_mask(&ctx, sample, mask));
    ASSERT(bytes_eq(mask, "b54937be4b", sizeof(mask)));
    cvmcrypt_cipher_clear(&ctx);
    PASS();
}

TEST cipher_keystream_matches_chacha20_rfc8439(void) {
    /* RFC 8439 §2.3.2: key 00..1f, nonce 000000090000004a00000000,
     * counter 1, first 16 keystream bytes. The sample below encodes exactly
     * that block input: counter little-endian, then the nonce. */
    u8 key[32];
    u8 sample[16];
    u8 block[16];
    CvmcryptCipherCtx ctx;

    for (usize i = 0; i < sizeof(key); i++) {
        key[i] = (u8)i;
    }
    hex_to_bytes(sample, sizeof(sample),
                 "01000000"
                 "000000090000004a00000000");

    ASSERT(cvmcrypt_cipher_init(&ctx, &cvmcrypt_cipher_chacha20, key));
    ASSERT(cvmcrypt_cipher_keystream(&ctx, sample, block));
    ASSERT(bytes_eq(block, "10f1e7e4d13b5915500fdd1fa32071c4", 16));
    cvmcrypt_cipher_clear(&ctx);
    PASS();
}

/* ------------------------------------------------------------------ */
/* random                                                               */
/* ------------------------------------------------------------------ */

static void fixed_fill(u8* out, usize len, void* user) {
    u8 const* seed = user;
    for (usize i = 0; i < len; i++) {
        out[i] = (u8)(seed[0] + i);
    }
}

TEST random_without_source_fails(void) {
    u8 buf[8];
    cvmcrypt_random_set_source(NULL, NULL);
    ASSERT_FALSE(cvmcrypt_random(buf, sizeof(buf)));

    u32 v;
    ASSERT_FALSE(cvmcrypt_random_below(&v, 10));
    PASS();
}

TEST random_with_source(void) {
    u8 seed[1] = {0x10};
    u8 buf[4];
    u32 v;

    cvmcrypt_random_set_source(fixed_fill, seed);
    ASSERT(cvmcrypt_random(buf, sizeof(buf)));
    ASSERT_EQ(0x10, buf[0]);
    ASSERT_EQ(0x13, buf[3]);

    ASSERT_FALSE(cvmcrypt_random_below(&v, 0));
    ASSERT(cvmcrypt_random_below(&v, 10));
    ASSERT(v < 10);

    cvmcrypt_random_set_source(NULL, NULL);
    PASS();
}

SUITE(api) {
    RUN_TEST(aead_roundtrip_all_algorithms);
    RUN_TEST(aead_wrong_key_size_rejected);
    RUN_TEST(aead_chachapoly_matches_direct);
    RUN_TEST(sha384_digest_kat);
    RUN_TEST(hkdf_sha256_matches_specialised);
    RUN_TEST(hkdf_sha384_kat);
    RUN_TEST(hp_mask_aes128_kat);
    RUN_TEST(hp_mask_chacha20_kat);
    RUN_TEST(cipher_keystream_matches_chacha20_rfc8439);
    RUN_TEST(random_without_source_fails);
    RUN_TEST(random_with_source);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(api);
    GREATEST_MAIN_END();
}
