/*
 * tests/unit/test_tls_session.c
 *
 * Session resumption: ticket encrypt/decrypt round-trip,
 * server ticket generation, client ticket handling.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/session.h"
#include "aead/gcm.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */

static void mock_random(CvmTlsRandomBytes* self, void* buf, usize len) {
    (void)self;
    for (usize i = 0; i < len; i++)
        ((u8*)buf)[i] = (u8)(i * 7 + 3);
}
static CvmTlsRandomBytes const RANDOM = {.cb = mock_random};

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST ticket_key_init(void) {
    CvmTlsSessionKey key;
    u8 raw[16];
    for (int i = 0; i < 16; i++)
        raw[i] = (u8)(i * 3);
    cvm_tls_session_key_init(&key, raw);
    ASSERT(memcmp(key.key, raw, 16) == 0);
    PASS();
}

TEST ticket_key_generate(void) {
    CvmTlsSessionKey key;
    cvm_tls_session_key_generate(&key, (CvmTlsRandomBytes*)&RANDOM);
    /* Should not be all zeros. */
    bool nonzero = false;
    for (int i = 0; i < 16; i++) {
        if (key.key[i] != 0) {
            nonzero = true;
            break;
        }
    }
    ASSERT(nonzero);
    PASS();
}

TEST ticket_encrypt_decrypt_roundtrip(void) {
    /* This tests the encrypt→decrypt cycle through a full NST exchange.
     * Since server_send_ticket needs a full CvmTls context, we test
     * the decrypt path directly with a manually-built ticket. */
    CvmTlsSessionKey key;
    u8 raw_key[16];
    for (int i = 0; i < 16; i++)
        raw_key[i] = (u8)(i * 5);
    cvm_tls_session_key_init(&key, raw_key);

    /* Build a ticket manually (same format as session.c). */
    u8 pt[4 + 2 + 8 + 32 + 32]; /* same as TICKET_PLAINTEXT_SIZE */
    memset(pt, 0, sizeof(pt));
    pt[0] = 'C';
    pt[1] = 'V';
    pt[2] = 'M';
    pt[3] = 1;
    pt[4] = 0x13;
    pt[5] = 0x01; /* TLS_AES_128_GCM_SHA256 */
    /* creation_time = 12345678 */
    for (int i = 0; i < 8; i++)
        pt[6 + i] = (u8)(12345678ULL >> (56 - i * 8));
    /* PSK */
    for (int i = 0; i < 32; i++)
        pt[14 + i] = (u8)(i * 11);
    /* transcript hash */
    for (int i = 0; i < 32; i++)
        pt[46 + i] = (u8)(i * 13);

    u8 nonce[12];
    for (int i = 0; i < 12; i++)
        nonce[i] = (u8)(i * 7);

    /* Encrypt. */
    u8 ct[78 + 16]; /* plaintext + tag */
    {
        /* Use proper prototype. */
    }
    {
#include "aead/gcm.h"
        CvmcryptGcm gcm;
        cvmcrypt_gcm_encrypt(&gcm, key.key, 16, nonce, NULL, 0, pt, sizeof(pt), ct,
                             ct + sizeof(pt));
    }

    /* Build full ticket: nonce || ct || tag. */
    u8 ticket[12 + 78 + 16];
    memcpy(ticket, nonce, 12);
    memcpy(ticket + 12, ct, 78 + 16);

    /* Decrypt and verify. */
    CvmTlsSessionData data;
    int ret =
        cvm_tls_server_decrypt_ticket(&key, (CvmTlsVec){ticket, sizeof(ticket)}, &data);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(0x1301, data.cipher_suite_id);
    ASSERT_EQ(12345678, data.creation_time);
    ASSERT(memcmp(data.psk, pt + 14, 32) == 0);
    ASSERT(memcmp(data.transcript_hash, pt + 46, 32) == 0);

    PASS();
}

TEST ticket_decrypt_wrong_key(void) {
    CvmTlsSessionKey key1, key2;
    u8 raw1[16], raw2[16];
    for (int i = 0; i < 16; i++) {
        raw1[i] = (u8)(i);
        raw2[i] = (u8)(i + 100);
    }
    cvm_tls_session_key_init(&key1, raw1);
    cvm_tls_session_key_init(&key2, raw2);

    /* Build a ticket encrypted with key1. */
    u8 pt[78];
    memset(pt, 0, sizeof(pt));
    pt[0] = 'C';
    pt[1] = 'V';
    pt[2] = 'M';
    pt[3] = 1;
    u8 nonce[12] = {0};
    u8 ct[78 + 16];
    {
#include "aead/gcm.h"
        CvmcryptGcm gcm;
        cvmcrypt_gcm_encrypt(&gcm, key1.key, 16, nonce, NULL, 0, pt, sizeof(pt), ct,
                             ct + sizeof(pt));
    }
    u8 ticket[12 + 78 + 16];
    memcpy(ticket, nonce, 12);
    memcpy(ticket + 12, ct, 78 + 16);

    /* Try to decrypt with key2 — should fail (GCM tag mismatch). */
    CvmTlsSessionData data;
    int ret = cvm_tls_server_decrypt_ticket(&key2, (CvmTlsVec){ticket, sizeof(ticket)},
                                            &data);
    ASSERT(ret != 0); /* must fail */

    PASS();
}

TEST ticket_decrypt_tampered(void) {
    CvmTlsSessionKey key;
    u8 raw[16];
    for (int i = 0; i < 16; i++)
        raw[i] = 0x42;
    cvm_tls_session_key_init(&key, raw);

    u8 pt[78];
    memset(pt, 0, sizeof(pt));
    pt[0] = 'C';
    pt[1] = 'V';
    pt[2] = 'M';
    pt[3] = 1;
    u8 nonce[12] = {0};
    u8 ct[78 + 16];
    {
#include "aead/gcm.h"
        CvmcryptGcm gcm;
        cvmcrypt_gcm_encrypt(&gcm, key.key, 16, nonce, NULL, 0, pt, sizeof(pt), ct,
                             ct + sizeof(pt));
    }
    u8 ticket[12 + 78 + 16];
    memcpy(ticket, nonce, 12);
    memcpy(ticket + 12, ct, 78 + 16);
    /* Tamper with ciphertext. */
    ticket[20] ^= 0x01;

    CvmTlsSessionData data;
    int ret =
        cvm_tls_server_decrypt_ticket(&key, (CvmTlsVec){ticket, sizeof(ticket)}, &data);
    ASSERT(ret != 0);

    PASS();
}

SUITE(tls_session) {
    RUN_TEST(ticket_key_init);
    RUN_TEST(ticket_key_generate);
    RUN_TEST(ticket_encrypt_decrypt_roundtrip);
    RUN_TEST(ticket_decrypt_wrong_key);
    RUN_TEST(ticket_decrypt_tampered);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_session);
    GREATEST_MAIN_END();
}
