/*
 * src/tls/keyschedule.c
 *
 * TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 *   0
   |
   v
HKDF-Extract(=0, 0)                    ← early secret
   |
   +→ Derive-Secret(., "ext binder" / "res binder", "")
   +→ Derive-Secret(., "c e traffic", ClientHello)
   |
HKDF-Extract(., Derive-Secret(., "derived", ""))   ← handshake secret
   |
   +→ Derive-Secret(., "s hs traffic", ServerHello)
   +→ Derive-Secret(., "c hs traffic", ServerHello)
   |
HKDF-Extract(., Derive-Secret(., "derived", ""))   ← master secret
   |
   +→ Derive-Secret(., "s ap traffic", ...)
   +→ Derive-Secret(., "c ap traffic", ...)
   +→ Derive-Secret(., "exp master", ...)
   |
HKDF-Extract(., Derive-Secret(., "res master", ...)) ← resumption secret
 */

#include "tls/tls_internal.h"
#ifdef TLS_DEBUG
#include <stdio.h>
#endif
#include "tls/keyschedule.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

static u8 const ZEROES[TLS_MAX_DIGEST_SIZE] = {0};

/* ------------------------------------------------------------------ */
/* HKDF (RFC 5869) built on cvmcrypt hash                              */
/* ------------------------------------------------------------------ */

/* We need HMAC for HKDF. The hash context is abstract, so we build
 * HMAC on top of the callback interface. */

typedef struct HmacCtx {
    CvmTlsHash* hash;
    u8 key_pad[TLS_MAX_BLOCK_SIZE * 2]; /* key XOR opad/ipad */
    usize block_size;
    usize digest_size;
} HmacCtx;

static void hmac_init(HmacCtx* ctx, CvmTlsHashAlgo const* algo, u8 const* key,
                      usize key_len) {
    ctx->hash = algo->create();
    ctx->block_size = algo->block_size;
    ctx->digest_size = algo->digest_size;

    /* Key: if longer than block, hash it; pad to block size. */
    u8 key_block[TLS_MAX_BLOCK_SIZE];
    memset(key_block, 0, ctx->block_size);
    if (key_len > ctx->block_size) {
        CvmTlsHash* h = algo->create();
        h->update(h, key, key_len);
        h->final(h, key_block, TLS_HASH_FINAL_FREE);
    } else {
        memcpy(key_block, key, key_len);
    }

    /* key_pad = key XOR ipad (0x36) */
    for (usize i = 0; i < ctx->block_size; i++)
        ctx->key_pad[i] = key_block[i] ^ 0x36;
    /* second half = key XOR opad (0x5c) */
    for (usize i = 0; i < ctx->block_size; i++)
        ctx->key_pad[ctx->block_size + i] = key_block[i] ^ 0x5c;

    /* Start inner hash. */
    ctx->hash->update(ctx->hash, ctx->key_pad, ctx->block_size);

    memset(key_block, 0, sizeof(key_block));
}

static void hmac_update(HmacCtx* ctx, u8 const* data, usize len) {
    ctx->hash->update(ctx->hash, data, len);
}

static void hmac_final(HmacCtx* ctx, u8* output) {
    u8 inner_digest[TLS_MAX_DIGEST_SIZE];
    /* Save algo before FREE mode destroys the context. */
    CvmTlsHashAlgo const* algo = ctx->hash->algo;
    ctx->hash->final(ctx->hash, inner_digest, TLS_HASH_FINAL_FREE);

    /* Outer hash: H(key XOR opad || inner_digest). */
    CvmTlsHash* outer = algo->create();
    outer->update(outer, ctx->key_pad + ctx->block_size, ctx->block_size);
    outer->update(outer, inner_digest, ctx->digest_size);
    outer->final(outer, output, TLS_HASH_FINAL_FREE);

    memset(inner_digest, 0, sizeof(inner_digest));
    memset(ctx->key_pad, 0, sizeof(ctx->key_pad));
}

/* HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm) */
int cvm_tls_hkdf_extract(CvmTlsHashAlgo const* hash, void* output, CvmTlsVec salt,
                         CvmTlsVec ikm) {
    HmacCtx ctx;
    hmac_init(&ctx, hash, salt.base, salt.len);
    hmac_update(&ctx, ikm.base, ikm.len);
    hmac_final(&ctx, output);
    return 0;
}

/* HKDF-Expand(PRK, info, L) */
int cvm_tls_hkdf_expand(CvmTlsHashAlgo const* hash, void* output, usize outlen,
                        CvmTlsVec prk, CvmTlsVec info) {
    u8 counter = 1;
    u8* dst = output;
    usize remaining = outlen;
    u8 prev[TLS_MAX_DIGEST_SIZE];
    usize prev_len = 0;

    while (remaining > 0) {
        HmacCtx ctx;
        hmac_init(&ctx, hash, prk.base, prk.len);
        if (prev_len > 0)
            hmac_update(&ctx, prev, prev_len);
        hmac_update(&ctx, info.base, info.len);
        hmac_update(&ctx, &counter, 1);
        hmac_final(&ctx, prev);

        usize n = hash->digest_size < remaining ? hash->digest_size : remaining;
        memcpy(dst, prev, n);
        dst += n;
        remaining -= n;
        prev_len = hash->digest_size;
        counter++;
    }

    memset(prev, 0, sizeof(prev));
    return 0;
}

/* HKDF-Expand-Label(secret, label, hash_value, length) per RFC 8446 §7.1. */
int cvm_tls_hkdf_expand_label(CvmTlsHashAlgo const* hash, void* output, usize outlen,
                              CvmTlsVec secret, char const* label,
                              CvmTlsVec hash_value) {
    /* HkdfLabel = struct {
     *     uint16 length;
     *     opaque label<7..255> = "tls13 " + Label;
     *     opaque context<0..255> = Context;
     * }; */
    u8 info[256];
    usize off = 0;

    /* length (2 bytes) */
    info[off++] = (u8)(outlen >> 8);
    info[off++] = (u8)outlen;

    /* label */
    usize label_len = 6; /* "tls13 " */
    while (label[label_len - 6] != 0)
        label_len++;
    label_len -= 6; /* actual label part length */
    info[off++] = (u8)(label_len + 6);
    memcpy(info + off, "tls13 ", 6);
    off += 6;
    memcpy(info + off, label, label_len);
    off += label_len;

    /* context (hash_value) */
    info[off++] = (u8)hash_value.len;
    memcpy(info + off, hash_value.base, hash_value.len);
    off += hash_value.len;

    return cvm_tls_hkdf_expand(hash, output, outlen, secret, (CvmTlsVec){info, off});
}

/* ------------------------------------------------------------------ */
/* key schedule                                                         */
/* ------------------------------------------------------------------ */

void cvm_tls_ks_init(CvmTlsKeySched* ks, CvmTlsCipherSuite const* suite) {
    memset(ks, 0, sizeof(*ks));
    ks->suite = suite;
    ks->hash_ctx = suite->hash->create();
    ks->generation = 0;
}

void cvm_tls_ks_free(CvmTlsKeySched* ks) {
    if (ks->hash_ctx != NULL) {
        ks->hash_ctx->final(ks->hash_ctx, NULL, TLS_HASH_FINAL_FREE);
        ks->hash_ctx = NULL;
    }
    /* secret is embedded in the struct — zero it, don't free. */
    memset(ks->secret, 0, sizeof(ks->secret));
    ks->generation = 0;
}

/* Extract: advance to the next generation.
 * generation 1 = early secret, 2 = handshake secret, 3 = master secret. */
int cvm_tls_ks_extract(CvmTlsKeySched* ks, CvmTlsVec ikm) {
    int ret;
    CvmTlsHashAlgo const* hash = ks->suite->hash;

    if (ikm.base == NULL) {
        ikm.base = ZEROES;
        ikm.len = hash->digest_size;
    }

    if (ks->generation != 0) {
        /* Derive-Secret(., "derived", "") from the current secret. */
        u8 derived[TLS_MAX_DIGEST_SIZE];
        u8 empty_hash[TLS_MAX_DIGEST_SIZE];
        /* Compute hash of empty string. */
        CvmTlsHash* h = hash->create();
        h->final(h, empty_hash, TLS_HASH_FINAL_FREE);

        ret = cvm_tls_hkdf_expand_label(hash, derived, hash->digest_size,
                                        (CvmTlsVec){ks->secret, hash->digest_size},
                                        "derived",
                                        (CvmTlsVec){empty_hash, hash->digest_size});
        if (ret != 0)
            return ret;
#ifdef TLS_DEBUG
        printf("[debug] derived: ");
        for (int i = 0; i < (int)hash->digest_size; i++)
            printf("%02x", derived[i]);
        printf("\n");
#endif
        memcpy(ks->secret, derived, hash->digest_size);
        memset(derived, 0, sizeof(derived));
    }

    ks->generation++;
#ifdef TLS_DEBUG
    printf("[debug] extract gen=%u: ikm_len=%zu, pre_secret=", ks->generation, ikm.len);
    for (int i = 0; i < (int)hash->digest_size; i++)
        printf("%02x", ks->secret[i]);
    printf("\n");
#endif
    ret = cvm_tls_hkdf_extract(hash, ks->secret,
                               (CvmTlsVec){ks->secret, hash->digest_size}, ikm);
#ifdef TLS_DEBUG
    printf("[debug] extract gen=%u: post_secret=", ks->generation);
    for (int i = 0; i < (int)hash->digest_size; i++)
        printf("%02x", ks->secret[i]);
    printf("\n");
#endif
    return ret;
}

/* Derive-Secret(secret, label, Transcript-Hash) */
int cvm_tls_ks_derive_secret(CvmTlsKeySched* ks, void* secret, char const* label) {
    u8 hash_value[TLS_MAX_DIGEST_SIZE];
    CvmTlsHashAlgo const* hash = ks->suite->hash;

    /* Snapshot the transcript hash. */
    ks->hash_ctx->final(ks->hash_ctx, hash_value, TLS_HASH_FINAL_SNAPSHOT);

    int ret = cvm_tls_hkdf_expand_label(
        hash, secret, hash->digest_size, (CvmTlsVec){ks->secret, hash->digest_size},
        label, (CvmTlsVec){hash_value, hash->digest_size});
    memset(hash_value, 0, sizeof(hash_value));
    return ret;
}

/* Update the transcript hash with a handshake message. */
void cvm_tls_ks_update_hash(CvmTlsKeySched* ks, u8 const* msg, usize msglen) {
    ks->hash_ctx->update(ks->hash_ctx, msg, msglen);
}

/* Derive traffic keys from a secret: key + iv for the AEAD. */
int cvm_tls_ks_get_traffic_keys(CvmTlsKeySched* ks, void* key, usize key_size, void* iv,
                                usize iv_size, void const* secret) {
    CvmTlsHashAlgo const* hash = ks->suite->hash;
    CvmTlsVec secret_vec = {secret, hash->digest_size};
    u8 empty_hash[TLS_MAX_DIGEST_SIZE];

    /* For traffic keys, the context is an empty hash. */
    CvmTlsHash* h = hash->create();
    h->final(h, empty_hash, TLS_HASH_FINAL_FREE);

    int ret = cvm_tls_hkdf_expand_label(hash, key, key_size, secret_vec, "key",
                                        (CvmTlsVec){empty_hash, 0});
    if (ret != 0)
        return ret;

    ret = cvm_tls_hkdf_expand_label(hash, iv, iv_size, secret_vec, "iv",
                                    (CvmTlsVec){empty_hash, 0});
    return ret;
}

/* Compute the Finished verify data: HMAC(finished_key, Transcript-Hash). */
int cvm_tls_ks_calc_verify_data(CvmTlsKeySched* ks, void* output, void const* secret) {
    CvmTlsHashAlgo const* hash = ks->suite->hash;

    /* finished_key = HKDF-Expand-Label(secret, "finished", "", hash_len) */
    u8 finished_key[TLS_MAX_DIGEST_SIZE];
    int ret = cvm_tls_hkdf_expand_label(hash, finished_key, hash->digest_size,
                                        (CvmTlsVec){secret, hash->digest_size},
                                        "finished", (CvmTlsVec){NULL, 0});
    if (ret != 0)
        return ret;

    /* verify_data = HMAC(finished_key, Transcript-Hash) */
    HmacCtx ctx;
    hmac_init(&ctx, hash, finished_key, hash->digest_size);

    u8 transcript[TLS_MAX_DIGEST_SIZE];
    ks->hash_ctx->final(ks->hash_ctx, transcript, TLS_HASH_FINAL_SNAPSHOT);
    hmac_update(&ctx, transcript, hash->digest_size);
    hmac_final(&ctx, output);

    memset(finished_key, 0, sizeof(finished_key));
    memset(transcript, 0, sizeof(transcript));
    return 0;
}
