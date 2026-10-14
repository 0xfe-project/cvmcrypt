/*
 * tests/unit/test_tls_record.c
 *
 * TLS 1.3 record layer tests: framing, AEAD round-trip, fragmentation.
 * Uses cvmcrypt AES-GCM as the AEAD backend.
 */

#include "vendor/greatest.h"

#include <string.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "aead/gcm.h"
#include "cipher/aes.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* mock AEAD backend (uses cvmcrypt AES-GCM)                            */
/* ------------------------------------------------------------------ */

#define MOCK_KEY_SIZE 16 /* AES-128 */
#define MOCK_IV_SIZE 12
#define MOCK_TAG_SIZE 16

typedef struct MockAead {
    CvmTlsAead super;
    CvmcryptGcm gcm;       /* working buffer */
    u8 key[MOCK_KEY_SIZE]; /* stored key */
    bool is_enc;
    u8 static_iv[MOCK_IV_SIZE];
} MockAead;

static void mock_dispose(CvmTlsAead* _ctx) {
    MockAead* ctx = (MockAead*)_ctx;
    cvmcrypt_secure_free(ctx, sizeof(*ctx));
}

static void mock_do_encrypt(CvmTlsAead* _ctx, u8* output, u8 const* input, usize inlen,
                            u64 seq, void const* aad, usize aadlen) {
    MockAead* ctx = (MockAead*)_ctx;
    u8 nonce[MOCK_IV_SIZE];
    memcpy(nonce, ctx->static_iv, MOCK_IV_SIZE);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (u8)(seq >> (56 - i * 8));
    /* Output = ciphertext || tag */
    cvmcrypt_gcm_encrypt(&ctx->gcm, ctx->key, MOCK_KEY_SIZE, nonce, (u8 const*)aad,
                         aadlen, input, inlen, output, output + inlen);
}

static usize mock_do_decrypt(CvmTlsAead* _ctx, u8* output, u8 const* input, usize inlen,
                             u64 seq, void const* aad, usize aadlen) {
    MockAead* ctx = (MockAead*)_ctx;
    u8 nonce[MOCK_IV_SIZE];
    memcpy(nonce, ctx->static_iv, MOCK_IV_SIZE);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (u8)(seq >> (56 - i * 8));
    /* Input = ciphertext || tag */
    bool ok = cvmcrypt_gcm_decrypt(&ctx->gcm, ctx->key, MOCK_KEY_SIZE, nonce,
                                   (u8 const*)aad, aadlen, input, inlen - MOCK_TAG_SIZE,
                                   output, input + inlen - MOCK_TAG_SIZE);
    return ok ? inlen - MOCK_TAG_SIZE : (usize)-1;
}

static CvmTlsAeadAlgo const MOCK_AEAD_ALGO = {
    .name = "mock-aes128gcm",
    .key_size = MOCK_KEY_SIZE,
    .iv_size = MOCK_IV_SIZE,
    .tag_size = MOCK_TAG_SIZE,
    .setup = NULL, /* we construct manually */
};

static MockAead* mock_aead_new(u8 const* key, bool is_enc) {
    MockAead* ctx = rt_mem_alloc(sizeof(MockAead));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.algo = &MOCK_AEAD_ALGO;
    ctx->super.dispose = mock_dispose;
    ctx->super.do_encrypt = mock_do_encrypt;
    ctx->super.do_decrypt = mock_do_decrypt;
    memcpy(ctx->key, key, MOCK_KEY_SIZE);
    ctx->is_enc = is_enc;
    memset(ctx->static_iv, 0x42, MOCK_IV_SIZE);
    return ctx;
}

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST record_header_parse(void) {
    u8 hdr[5] = {TLS_CONTENT_TYPE_HANDSHAKE, 3, 3, 0x10, 0x00};
    CvmTlsRecord rec;
    ASSERT_EQ(0, cvm_tls_parse_record_header(&rec, hdr));
    ASSERT_EQ(TLS_CONTENT_TYPE_HANDSHAKE, rec.type);
    ASSERT_EQ(0x1000, rec.length);
    PASS();
}

TEST record_header_oversize(void) {
    u8 hdr[5] = {TLS_CONTENT_TYPE_APPDATA, 3, 3, 0xFF, 0xFF};
    CvmTlsRecord rec;
    /* 0xFFFF = 65535 < TLS_MAX_ENCRYPTED_RECORD_SIZE (16384+256) fails */
    /* Actually 65535 > 16640, so it should fail */
    /* Wait, 0xFFFF = 65535, and TLS_MAX_ENCRYPTED_RECORD_SIZE = 16384+256 = 16640 */
    /* 65535 > 16640, so should return RECORD_OVERFLOW */
    int ret = cvm_tls_parse_record_header(&rec, hdr);
    ASSERT(ret != 0);
    PASS();
}

TEST record_parse_complete(void) {
    /* A complete record in a single buffer. */
    u8 record[] = {
        TLS_CONTENT_TYPE_APPDATA,
        3,
        3,
        0,
        5, /* header: 5 bytes body */
        'h',
        'e',
        'l',
        'l',
        'o', /* body */
    };
    CvmTlsRecord rec;
    CvmTlsBuf pending;
    cvm_tls_buf_init(&pending, NULL, 0);
    usize len = sizeof(record);
    int ret = cvm_tls_parse_record(&rec, record, &len, &pending);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, rec.type);
    ASSERT_EQ(5, rec.length);
    ASSERT(memcmp(rec.fragment, "hello", 5) == 0);
    ASSERT_EQ(sizeof(record), len);
    cvm_tls_buf_dispose(&pending);
    PASS();
}

TEST record_parse_partial(void) {
    /* Record arrives in two chunks. */
    u8 record[] = {
        TLS_CONTENT_TYPE_APPDATA, 3, 3, 0, 5, 'h', 'e', 'l', 'l', 'o',
    };

    CvmTlsBuf pending;
    cvm_tls_buf_init(&pending, NULL, 0);

    /* First chunk: only 3 bytes of the header. */
    usize len = 3;
    CvmTlsRecord rec;
    int ret = cvm_tls_parse_record(&rec, record, &len, &pending);
    ASSERT_EQ(TLS_ERROR_IN_PROGRESS, ret);
    ASSERT_EQ(3, len); /* consumed 3 bytes */

    /* Second chunk: the rest. */
    len = sizeof(record) - 3;
    ret = cvm_tls_parse_record(&rec, record + 3, &len, &pending);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, rec.type);
    ASSERT_EQ(5, rec.length);
    ASSERT(memcmp(rec.fragment, "hello", 5) == 0);
    ASSERT_EQ(sizeof(record) - 3, len);

    cvm_tls_buf_dispose(&pending);
    PASS();
}

TEST record_parse_bad_type(void) {
    u8 record[] = {0x99, 3, 3, 0, 0}; /* invalid content type */
    CvmTlsRecord rec;
    CvmTlsBuf pending;
    cvm_tls_buf_init(&pending, NULL, 0);
    usize len = sizeof(record);
    int ret = cvm_tls_parse_record(&rec, record, &len, &pending);
    ASSERT_EQ(TLS_ALERT_DECODE_ERROR, ret);
    cvm_tls_buf_dispose(&pending);
    PASS();
}

TEST aead_roundtrip(void) {
    u8 key[MOCK_KEY_SIZE];
    memset(key, 0xAB, sizeof(key));

    MockAead* enc = mock_aead_new(key, true);
    MockAead* dec = mock_aead_new(key, false);
    ASSERT(enc != NULL && dec != NULL);

    CvmTlsTrafficProt tp_enc = {.aead = &enc->super, .seq = 0};
    CvmTlsTrafficProt tp_dec = {.aead = &dec->super, .seq = 0};

    u8 plaintext[] = "hello world";
    u8 ciphertext[128];
    u8 decrypted[128];
    u8 content_type;

    usize enc_len =
        cvm_tls_aead_encrypt(&tp_enc, ciphertext, plaintext, sizeof(plaintext) - 1,
                             TLS_CONTENT_TYPE_APPDATA);
    ASSERT_EQ(sizeof(plaintext) - 1 + 1 + MOCK_TAG_SIZE, enc_len);

    usize dec_len;
    int ret = cvm_tls_aead_decrypt(&tp_dec, decrypted, &dec_len, &content_type,
                                   ciphertext, enc_len);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(sizeof(plaintext) - 1, dec_len);
    ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, content_type);
    ASSERT(memcmp(decrypted, plaintext, dec_len) == 0);

    mock_dispose(&enc->super);
    mock_dispose(&dec->super);
    PASS();
}

TEST aead_tampered(void) {
    u8 key[MOCK_KEY_SIZE];
    memset(key, 0xCD, sizeof(key));

    MockAead* enc = mock_aead_new(key, true);
    MockAead* dec = mock_aead_new(key, false);

    CvmTlsTrafficProt tp_enc = {.aead = &enc->super, .seq = 0};
    CvmTlsTrafficProt tp_dec = {.aead = &dec->super, .seq = 0};

    u8 plaintext[] = "test data";
    u8 ciphertext[128];
    u8 decrypted[128];
    u8 content_type;

    usize enc_len =
        cvm_tls_aead_encrypt(&tp_enc, ciphertext, plaintext, sizeof(plaintext) - 1,
                             TLS_CONTENT_TYPE_HANDSHAKE);
    /* Tamper with the ciphertext. */
    ciphertext[0] ^= 0x01;

    usize dec_len;
    int ret = cvm_tls_aead_decrypt(&tp_dec, decrypted, &dec_len, &content_type,
                                   ciphertext, enc_len);
    ASSERT_EQ(TLS_ALERT_BAD_RECORD_MAC, ret);

    mock_dispose(&enc->super);
    mock_dispose(&dec->super);
    PASS();
}

TEST push_encrypted_records_roundtrip(void) {
    u8 key[MOCK_KEY_SIZE];
    memset(key, 0x11, sizeof(key));

    MockAead* enc = mock_aead_new(key, true);
    MockAead* dec = mock_aead_new(key, false);

    CvmTlsTrafficProt tp_enc = {.aead = &enc->super, .seq = 0};
    CvmTlsTrafficProt tp_dec = {.aead = &dec->super, .seq = 0};

    /* Data larger than one record (16384). */
    usize data_len = 20000;
    u8* data = rt_mem_alloc(data_len);
    for (usize i = 0; i < data_len; i++)
        data[i] = (u8)(i & 0xFF);

    CvmTlsBuf out;
    cvm_tls_buf_init(&out, NULL, 0);
    int ret = cvm_tls_push_encrypted_records(&out, TLS_CONTENT_TYPE_APPDATA, data,
                                             data_len, &tp_enc);
    ASSERT_EQ(0, ret);
    ASSERT(out.off > data_len); /* overhead added */

    /* Now parse and decrypt. */
    u8 const* src = out.base;
    usize remaining = out.off;
    usize total_plain = 0;
    u8* plaintext = rt_mem_alloc(data_len + 256);

    while (remaining > 0) {
        CvmTlsRecord rec;
        CvmTlsBuf pending;
        cvm_tls_buf_init(&pending, NULL, 0);
        usize consumed = remaining;
        ret = cvm_tls_parse_record(&rec, src, &consumed, &pending);
        ASSERT_EQ(0, ret);
        ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, rec.type);

        usize ptlen;
        u8 ct;
        ret = cvm_tls_aead_decrypt(&tp_dec, plaintext + total_plain, &ptlen, &ct,
                                   rec.fragment, rec.length);
        ASSERT_EQ(0, ret);
        ASSERT_EQ(TLS_CONTENT_TYPE_APPDATA, ct);
        total_plain += ptlen;

        src += consumed;
        remaining -= consumed;
        cvm_tls_buf_dispose(&pending);
    }

    ASSERT_EQ(data_len, total_plain);
    ASSERT(memcmp(plaintext, data, data_len) == 0);

    rt_mem_free(plaintext);
    rt_mem_free(data);
    cvm_tls_buf_dispose(&out);
    mock_dispose(&enc->super);
    mock_dispose(&dec->super);
    PASS();
}

TEST buf_grow(void) {
    CvmTlsBuf buf;
    u8 small[16];
    cvm_tls_buf_init(&buf, small, sizeof(small));

    /* Push more than the small buffer. */
    for (int i = 0; i < 100; i++) {
        ASSERT_EQ(0, cvm_tls_buf_push(&buf, (u8)i));
    }
    ASSERT_EQ(100, buf.off);
    ASSERT(buf.is_allocated); /* should have reallocated */
    ASSERT(buf.base != small);

    /* Verify content. */
    for (int i = 0; i < 100; i++) {
        ASSERT_EQ((u8)i, buf.base[i]);
    }

    cvm_tls_buf_dispose(&buf);
    PASS();
}

SUITE(tls_record) {
    RUN_TEST(record_header_parse);
    RUN_TEST(record_header_oversize);
    RUN_TEST(record_parse_complete);
    RUN_TEST(record_parse_partial);
    RUN_TEST(record_parse_bad_type);
    RUN_TEST(aead_roundtrip);
    RUN_TEST(aead_tampered);
    RUN_TEST(push_encrypted_records_roundtrip);
    RUN_TEST(buf_grow);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_record);
    GREATEST_MAIN_END();
}
