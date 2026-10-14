/*
 * tests/unit/test_tls_keysched.c
 *
 * TLS 1.3 key schedule tests. Uses cvmcrypt SHA-256 as the hash backend.
 * Cross-verified against RFC 8448 (TLS 1.3 simple 1-RTT handshake vectors).
 */

#include "vendor/greatest.h"

#include <string.h>
#include <stdio.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/keyschedule.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* SHA-256 hash backend                                                 */
/* ------------------------------------------------------------------ */

typedef struct Sha256Ctx {
    CvmTlsHash super;
    CvmcryptSha256 ctx;
} Sha256Ctx;

static CvmTlsHash* sha256_create(void); /* fwd */

static CvmTlsHashAlgo const TLS_SHA256_ALGO = {
    .name = "sha256",
    .block_size = 64,
    .digest_size = 32,
    .create = sha256_create,
};

static void sha256_update(CvmTlsHash* _ctx, void const* src, usize len) {
    Sha256Ctx* ctx = (Sha256Ctx*)_ctx;
    cvmcrypt_sha256_update(&ctx->ctx, src, len);
}

static void sha256_final(CvmTlsHash* _ctx, void* digest, CvmTlsHashFinalMode mode) {
    Sha256Ctx* ctx = (Sha256Ctx*)_ctx;
    if (digest != NULL)
        cvmcrypt_sha256_final(&ctx->ctx, digest);
    if (mode == TLS_HASH_FINAL_RESET)
        cvmcrypt_sha256_init(&ctx->ctx);
    else if (mode == TLS_HASH_FINAL_FREE)
        cvmcrypt_secure_free(ctx, sizeof(*ctx));
}

static CvmTlsHash* sha256_create(void) {
    Sha256Ctx* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &TLS_SHA256_ALGO;
    ctx->super.update = sha256_update;
    ctx->super.final = sha256_final;
    ctx->super.clone = NULL;
    cvmcrypt_sha256_init(&ctx->ctx);
    return &ctx->super;
}

/* ------------------------------------------------------------------ */
/* dummy cipher suites                                                  */
/* ------------------------------------------------------------------ */

static CvmTlsAeadAlgo const DUMMY_AEAD = {
    .name = "dummy",
    .key_size = 16,
    .iv_size = 12,
    .tag_size = 16,
    .setup = NULL,
};

static CvmTlsCipherSuite const SUITE_SHA256 = {
    .id = TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .aead = &DUMMY_AEAD,
    .hash = &TLS_SHA256_ALGO,
    .name = "TLS_AES_128_GCM_SHA256",
};

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST hkdf_extract_rfc5869(void) {
    u8 const ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    u8 const salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    u8 const expected_prk[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                                 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                                 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                                 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    u8 prk[32];
    int ret =
        cvm_tls_hkdf_extract(&TLS_SHA256_ALGO, prk, (CvmTlsVec){salt, sizeof(salt)},
                             (CvmTlsVec){ikm, sizeof(ikm)});
    ASSERT_EQ(0, ret);
    ASSERT(memcmp(prk, expected_prk, 32) == 0);
    PASS();
}

TEST hkdf_expand_rfc5869(void) {
    u8 const prk[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    u8 const info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    u8 const expected_okm[42] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
                                 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
                                 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
                                 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
                                 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    u8 okm[42];
    int ret =
        cvm_tls_hkdf_expand(&TLS_SHA256_ALGO, okm, 42, (CvmTlsVec){prk, sizeof(prk)},
                            (CvmTlsVec){info, sizeof(info)});
    ASSERT_EQ(0, ret);
    ASSERT(memcmp(okm, expected_okm, 42) == 0);
    PASS();
}

TEST hkdf_early_secret_rfc8448(void) {
    /* RFC 8448 §3:
     * early_secret = HKDF-Extract(0, 0) =
     *   33ad0a1c607ec03b09e6cd9893680ce2
     *   10adf4aa515b2bd70d8f6c1e9b3b6ce4 */
    u8 early_secret[32];
    /* HKDF-Extract with zero salt and zero IKM.
     * Our API: salt = NULL/0 means all-zero salt of digest_size bytes. */
    u8 const zeros[32] = {0};
    int ret = cvm_tls_hkdf_extract(&TLS_SHA256_ALGO, early_secret,
                                   (CvmTlsVec){zeros, 32}, (CvmTlsVec){zeros, 32});
    ASSERT_EQ(0, ret);

    static u8 const expected[32] = {0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
                                    0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
                                    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
                                    0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a};
    ASSERT(memcmp(early_secret, expected, 32) == 0);

    /* Derive-Secret(early_secret, "derived", "") uses Hash("") as context. */
    u8 derived[32];
    u8 empty_hash[32];
    {
        CvmTlsHash* h = sha256_create();
        h->final(h, empty_hash, TLS_HASH_FINAL_FREE);
    }
    ret = cvm_tls_hkdf_expand_label(&TLS_SHA256_ALGO, derived, 32,
                                    (CvmTlsVec){early_secret, 32}, "derived",
                                    (CvmTlsVec){empty_hash, 32});
    ASSERT_EQ(0, ret);

    static u8 const expected_derived[32] = {
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54,
        0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48,
        0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba};
    ASSERT(memcmp(derived, expected_derived, 32) == 0);

    PASS();
}

TEST key_schedule_progression(void) {
    CvmTlsKeySched ks;
    cvm_tls_ks_init(&ks, &SUITE_SHA256);

    /* Generation 1: early secret. */
    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){NULL, 0}));
    ASSERT_EQ(1, ks.generation);

    static u8 const expected_early[32] = {
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd,
        0x98, 0x93, 0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f,
        0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a};
    ASSERT(memcmp(ks.secret, expected_early, 32) == 0);

    /* Generation 2: handshake secret (RFC 8448 ECDHE). */
    static u8 const shared_secret[32] = {
        0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac,
        0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75,
        0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d};
    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){shared_secret, 32}));
    ASSERT_EQ(2, ks.generation);

    /* RFC 8448 expected handshake secret. */
    static u8 const expected_hs[32] = {0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f,
                                       0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
                                       0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
                                       0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac};
    ASSERT(memcmp(ks.secret, expected_hs, 32) == 0);

    /* Generation 3: master secret. */
    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){NULL, 0}));
    ASSERT_EQ(3, ks.generation);

    cvm_tls_ks_free(&ks);
    PASS();
}

TEST key_schedule_verify_data(void) {
    CvmTlsKeySched ks;
    cvm_tls_ks_init(&ks, &SUITE_SHA256);

    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){NULL, 0}));
    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){NULL, 0}));

    u8 transcript[] = "test transcript";
    cvm_tls_ks_update_hash(&ks, transcript, sizeof(transcript) - 1);

    u8 secret[32];
    ASSERT_EQ(0, cvm_tls_ks_derive_secret(&ks, secret, "s hs traffic"));

    u8 vd1[32], vd2[32];
    ASSERT_EQ(0, cvm_tls_ks_calc_verify_data(&ks, vd1, secret));
    ASSERT_EQ(0, cvm_tls_ks_calc_verify_data(&ks, vd2, secret));
    ASSERT(memcmp(vd1, vd2, 32) == 0);

    /* Different transcript → different verify data. */
    cvm_tls_ks_update_hash(&ks, (u8 const*)"more", 4);
    u8 vd3[32];
    ASSERT_EQ(0, cvm_tls_ks_calc_verify_data(&ks, vd3, secret));
    ASSERT(memcmp(vd1, vd3, 32) != 0);

    cvm_tls_ks_free(&ks);
    PASS();
}

TEST key_schedule_traffic_keys(void) {
    CvmTlsKeySched ks;
    cvm_tls_ks_init(&ks, &SUITE_SHA256);

    ASSERT_EQ(0, cvm_tls_ks_extract(&ks, (CvmTlsVec){NULL, 0}));

    u8 secret[32];
    ASSERT_EQ(0, cvm_tls_ks_derive_secret(&ks, secret, "c e traffic"));

    u8 key[16], iv[12];
    ASSERT_EQ(0, cvm_tls_ks_get_traffic_keys(&ks, key, 16, iv, 12, secret));

    u8 key2[16], iv2[12];
    ASSERT_EQ(0, cvm_tls_ks_get_traffic_keys(&ks, key2, 16, iv2, 12, secret));
    ASSERT(memcmp(key, key2, 16) == 0);
    ASSERT(memcmp(iv, iv2, 12) == 0);

    cvm_tls_ks_free(&ks);
    PASS();
}

SUITE(tls_keysched) {
    RUN_TEST(hkdf_extract_rfc5869);
    RUN_TEST(hkdf_expand_rfc5869);
    RUN_TEST(hkdf_early_secret_rfc8448);
    RUN_TEST(key_schedule_progression);
    RUN_TEST(key_schedule_verify_data);
    RUN_TEST(key_schedule_traffic_keys);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_keysched);
    GREATEST_MAIN_END();
}
