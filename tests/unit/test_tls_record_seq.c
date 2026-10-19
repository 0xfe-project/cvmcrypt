/*
 * tests/unit/test_tls_record_seq.c
 *
 * Pins the record sequence number to the right half of the IV.
 *
 * RFC 8446 §5.3: the 64-bit sequence number is left-padded to the IV length
 * and XORed in, so for a 12-byte IV it lands in the LAST eight bytes. XORing
 * into the first eight is invisible at seq 0 — every byte is zero — and
 * breaks every record after the first.
 *
 * That is not hypothetical. It shipped, and it survived the TCP interop test
 * because example.com packs its whole handshake flight into one record, so
 * only seq 0 was ever exercised. It showed up against a server that sends one
 * record per handshake message.
 *
 * The expected bytes below come from Go's crypto/cipher (tls/crypto_cvm.c's
 * nonce construction is not consulted for them):
 *
 *   key   = 000102030405060708090a0b0c0d0e0f
 *   iv    = 000102030405060708090a0b
 *   plain = "hello, record" || 0x17
 *   aad   = 17 03 03 00 1e
 *
 * A test that only round-tripped encrypt→decrypt would pass with the bug in
 * place, because both sides would be wrong the same way. That is why this one
 * compares against an outside implementation.
 */

#include "vendor/greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/types.h"
#include "tls/tls.h"
#include "tls/tls_internal.h"

static CvmTlsAeadAlgo const* aes128gcm_algo(void) {
    static CvmTlsContext ctx;
    static bool init;
    if (!init) {
        cvm_tls_context_defaults(&ctx);
        init = true;
    }
    for (usize i = 0; ctx.cipher_suites[i] != NULL; i++) {
        if (ctx.cipher_suites[i]->id == 0x1301) {
            return ctx.cipher_suites[i]->aead;
        }
    }
    return NULL;
}

static void hex_to_bytes(u8* out, usize n, char const* hex) {
    for (usize i = 0; i < n; i++) {
        char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        out[i] = (u8)strtoul(pair, NULL, 16);
    }
}

static bool seq_matches(u64 seq, char const* want_hex) {
    u8 key[16], iv[12], want[64], pt[32], ct[64];

    hex_to_bytes(key, sizeof(key), "000102030405060708090a0b0c0d0e0f");
    hex_to_bytes(iv, sizeof(iv), "000102030405060708090a0b");

    usize const ptlen = 13; /* "hello, record" — the type byte is added below */
    memcpy(pt, "hello, record", ptlen);

    CvmTlsAeadAlgo const* algo = aes128gcm_algo();
    if (algo == NULL) {
        return false;
    }

    CvmTlsAead* aead = algo->setup(algo, true, key, iv);
    if (aead == NULL) {
        return false;
    }

    CvmTlsTrafficProt tp = {.aead = aead, .seq = seq};
    usize const ctlen =
        cvm_tls_aead_encrypt(&tp, ct, pt, ptlen, TLS_CONTENT_TYPE_APPDATA);
    /* +1 for the content-type byte cvm_tls_aead_encrypt appends, +16 tag. */
    usize const wantlen = ptlen + 1 + 16;

    bool ok = ctlen == wantlen;
    if (ok) {
        hex_to_bytes(want, wantlen, want_hex);
        ok = memcmp(want, ct, wantlen) == 0;
        if (!ok) {
            printf("  seq=%llu ctlen=%zu\n  want ", (unsigned long long)seq, ctlen);
            for (usize i = 0; i < wantlen; i++)
                printf("%02x", want[i]);
            printf("\n  got  ");
            for (usize i = 0; i < wantlen; i++)
                printf("%02x", ct[i]);
            printf("\n");
        }
    }

    /* cvm_tls_aead_encrypt advances the caller's sequence number itself. */
    ok = ok && tp.seq == seq + 1;

    aead->dispose(aead);
    return ok;
}

TEST seq0_matches_reference(void) {
    ASSERT(
        seq_matches(0, "fb09cba20937d7262eb10ef852b475338acdb8259a3fe6c7c40c3cb8fb0d"));
    PASS();
}

TEST seq1_matches_reference(void) {
    /* This is the case the shipped bug broke: nonce[11] becomes 0x0a. */
    ASSERT(
        seq_matches(1, "a95c7afe0b335f0ee2c7b0d8587e0d44adaf73fb7b0837cf1caf0cd922f9"));
    PASS();
}

TEST seq2_matches_reference(void) {
    ASSERT(
        seq_matches(2, "99c4903715bef2f0651ee676cea284f29d47e252632198378ff8f8357fd1"));
    PASS();
}

TEST roundtrip_at_each_seq(void) {
    u8 key[16], iv[12];
    u8 pt[32] = "multi-record handshake";
    u8 ct[64], back[64];
    u8 type;

    hex_to_bytes(key, sizeof(key), "000102030405060708090a0b0c0d0e0f");
    hex_to_bytes(iv, sizeof(iv), "000102030405060708090a0b");

    CvmTlsAeadAlgo const* algo = aes128gcm_algo();
    ASSERT(algo != NULL);

    CvmTlsAead* enc = algo->setup(algo, true, key, iv);
    CvmTlsAead* dec = algo->setup(algo, false, key, iv);
    ASSERT(enc != NULL && dec != NULL);

    CvmTlsTrafficProt tp_enc = {.aead = enc, .seq = 0};
    CvmTlsTrafficProt tp_dec = {.aead = dec, .seq = 0};

    usize const ptlen = sizeof("multi-record handshake") - 1;

    for (int round = 0; round < 4; round++) {
        usize const ctlen =
            cvm_tls_aead_encrypt(&tp_enc, ct, pt, ptlen, TLS_CONTENT_TYPE_APPDATA);
        ASSERT_EQ(ptlen + 1 + 16, ctlen);

        usize outlen = 0;
        ASSERT_EQ(0, cvm_tls_aead_decrypt(&tp_dec, back, &outlen, &type, ct, ctlen));
        ASSERT_EQ(ptlen, outlen);
        ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, type);
        ASSERT_MEM_EQ(pt, back, ptlen);
    }

    enc->dispose(enc);
    dec->dispose(dec);
    PASS();
}

SUITE(tls_record_seq) {
    RUN_TEST(seq0_matches_reference);
    RUN_TEST(seq1_matches_reference);
    RUN_TEST(seq2_matches_reference);
    RUN_TEST(roundtrip_at_each_seq);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_record_seq);
    GREATEST_MAIN_END();
}
