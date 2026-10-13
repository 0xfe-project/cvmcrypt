/*
 * src/pk/rsa.c
 *
 * RSA verify: SPKI import, PKCS#1 v1.5 verify, PSS verify.
 * Written from PKCS#1 v2.2 (RFC 8017).
 */

#include "pk/rsa.h"

#include "base/mem.h"
#include "base/secure.h"
#include "asn1/der.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* init / free                                                          */
/* ------------------------------------------------------------------ */

void cvmcrypt_rsa_init(CvmRsaKey* key) {
    cvmcrypt_mpi_init(&key->n);
    cvmcrypt_mpi_init(&key->e);
}

void cvmcrypt_rsa_free(CvmRsaKey* key) {
    cvmcrypt_mpi_free(&key->n);
    cvmcrypt_mpi_free(&key->e);
}

/* ------------------------------------------------------------------ */
/* SPKI import                                                          */
/* ------------------------------------------------------------------ */

/*
 * SPKI = SEQUENCE {
 *   algorithm  AlgorithmIdentifier,  -- SEQUENCE { OID rsaEncryption, NULL }
 *   subjectPublicKey BIT STRING      -- DER-encoded RSAPublicKey
 * }
 * RSAPublicKey = SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 */
bool cvmcrypt_rsa_import_spki(CvmRsaKey* key, u8 const* der, usize derlen) {
    DerCursor c = der_cursor_init(der, derlen);
    DerCursor spki, algo, rsa_key;

    /* outer SEQUENCE */
    if (der_read_sequence(&c, &spki) != DER_OK)
        return false;

    /* AlgorithmIdentifier SEQUENCE (skip it — we assume RSA) */
    if (der_read_sequence(&spki, &algo) != DER_OK)
        return false;
    /* Skip the OID inside algo. */
    if (der_skip_tlv(&algo) != DER_OK)
        return false;
    /* Skip params (NULL or PSS params). */
    if (der_skip_tlv(&algo) != DER_OK)
        return false;

    /* BIT STRING containing DER-encoded RSAPublicKey */
    u8 const* bs_data;
    usize bs_len;
    u8 unused;
    if (der_read_bit_string(&spki, &bs_data, &bs_len, &unused) != DER_OK)
        return false;
    if (unused != 0)
        return false;

    /* RSAPublicKey = SEQUENCE { INTEGER n, INTEGER e } */
    DerCursor rsa_c = der_cursor_init(bs_data, bs_len);
    if (der_read_sequence(&rsa_c, &rsa_key) != DER_OK)
        return false;

    if (der_read_integer(&rsa_key, &key->n) != DER_OK)
        return false;
    if (der_read_integer(&rsa_key, &key->e) != DER_OK)
        return false;

    return true;
}

/* ------------------------------------------------------------------ */
/* RSA public operation                                                 */
/* ------------------------------------------------------------------ */

bool cvmcrypt_rsa_public(CvmMpi* result, CvmMpi const* sig, CvmRsaKey const* key) {
    /* result = sig^e mod n */
    return cvmcrypt_mpi_exp_mod(result, sig, &key->e, &key->n);
}

/* ------------------------------------------------------------------ */
/* PKCS#1 v1.5 verify                                                   */
/* ------------------------------------------------------------------ */

/* DigestInfo prefix per PKCS#1 v2.2 §9.2. These are the ASN.1 encoded
 * DigestInfo structures for each hash algorithm. */
static u8 const DI_SHA256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                               0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                               0x01, 0x05, 0x00, 0x04, 0x20};
static u8 const DI_SHA384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60,
                               0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                               0x02, 0x05, 0x00, 0x04, 0x30};
static u8 const DI_SHA512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60,
                               0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                               0x03, 0x05, 0x00, 0x04, 0x40};

static u8 const* get_digest_info(CvmRsaHashId id, usize* di_len) {
    switch (id) {
    case CVMCRYPT_RSA_HASH_SHA256:
        *di_len = sizeof(DI_SHA256);
        return DI_SHA256;
    case CVMCRYPT_RSA_HASH_SHA384:
        *di_len = sizeof(DI_SHA384);
        return DI_SHA384;
    case CVMCRYPT_RSA_HASH_SHA512:
        *di_len = sizeof(DI_SHA512);
        return DI_SHA512;
    default:
        return NULL;
    }
}

bool cvmcrypt_rsa_verify_pkcs1_v15(CvmRsaKey const* key, CvmRsaHashId hash_id,
                                   u8 const* hash, usize hashlen, u8 const* sig,
                                   usize siglen) {
    usize di_len;
    u8 const* di = get_digest_info(hash_id, &di_len);
    if (di == NULL)
        return false;

    /* EM length = key length in bytes. */
    usize n_bits = cvmcrypt_mpi_bitlen(&key->n);
    usize em_len = (n_bits + 7) / 8;
    if (siglen != em_len)
        return false;

    /* Parse sig as big-endian integer, compute sig^e mod n. */
    CvmMpi sig_mpi, em_mpi;
    cvmcrypt_mpi_init(&sig_mpi);
    cvmcrypt_mpi_init(&em_mpi);

    if (!cvmcrypt_mpi_read_binary(&sig_mpi, sig, siglen))
        goto fail;
    if (!cvmcrypt_rsa_public(&em_mpi, &sig_mpi, key))
        goto fail;

    /* Write em_mpi to a buffer. */
    u8* em = rt_mem_alloc(em_len);
    if (em == NULL)
        goto fail;
    memset(em, 0, em_len);
    if (!cvmcrypt_mpi_write_binary(&em_mpi, em, em_len)) {
        rt_mem_free(em);
        goto fail;
    }

    /* Build expected EM = 0x00 || 0x01 || PS (0xFF...) || 0x00 || T
     * where T = DigestInfo || hash. */
    usize t_len = di_len + hashlen;
    if (em_len < t_len + 11) {
        rt_mem_free(em);
        goto fail;
    }

    u8* expected = rt_mem_alloc(em_len);
    if (expected == NULL) {
        rt_mem_free(em);
        goto fail;
    }
    expected[0] = 0x00;
    expected[1] = 0x01;
    usize ps_len = em_len - t_len - 3;
    memset(expected + 2, 0xFF, ps_len);
    expected[2 + ps_len] = 0x00;
    memcpy(expected + 3 + ps_len, di, di_len);
    memcpy(expected + 3 + ps_len + di_len, hash, hashlen);

    /* Constant-time comparison. */
    bool ok = cvmcrypt_ct_eq(em, expected, em_len);

    memset(em, 0, em_len);
    memset(expected, 0, em_len);
    rt_mem_free(em);
    rt_mem_free(expected);
    cvmcrypt_mpi_free(&sig_mpi);
    cvmcrypt_mpi_free(&em_mpi);
    return ok;

fail:
    cvmcrypt_mpi_free(&sig_mpi);
    cvmcrypt_mpi_free(&em_mpi);
    return false;
}

/* ------------------------------------------------------------------ */
/* PSS verify                                                           */
/* ------------------------------------------------------------------ */

/* MGF1: mask = seed-hash repeatedly. */
static void mgf1(CvmRsaHashId hash_id, u8 const* seed, usize seedlen, u8* mask,
                 usize masklen) {
    u8 counter_be[4];
    usize hashlen = (hash_id == CVMCRYPT_RSA_HASH_SHA256)   ? 32
                    : (hash_id == CVMCRYPT_RSA_HASH_SHA384) ? 48
                                                            : 64;
    u8 hash_out[64];
    usize pos = 0;

    for (u32 counter = 0; pos < masklen; counter++) {
        counter_be[0] = (u8)(counter >> 24);
        counter_be[1] = (u8)(counter >> 16);
        counter_be[2] = (u8)(counter >> 8);
        counter_be[3] = (u8)counter;

        if (hash_id == CVMCRYPT_RSA_HASH_SHA256) {
            CvmcryptSha256 h;
            cvmcrypt_sha256_init(&h);
            cvmcrypt_sha256_update(&h, seed, seedlen);
            cvmcrypt_sha256_update(&h, counter_be, 4);
            cvmcrypt_sha256_final(&h, hash_out);
        } else {
            CvmcryptSha512 h;
            cvmcrypt_sha512_init(&h);
            cvmcrypt_sha512_update(&h, seed, seedlen);
            cvmcrypt_sha512_update(&h, counter_be, 4);
            cvmcrypt_sha512_final(&h, hash_out);
        }

        usize n = masklen - pos;
        if (n > hashlen)
            n = hashlen;
        memcpy(mask + pos, hash_out, n);
        pos += n;
    }
}

bool cvmcrypt_rsa_verify_pss(CvmRsaKey const* key, CvmRsaHashId hash_id, u8 const* hash,
                             usize hashlen, u8 const* sig, usize siglen) {
    usize n_bits = cvmcrypt_mpi_bitlen(&key->n);
    usize em_len = (n_bits + 7) / 8;
    usize hashlen_expected = (hash_id == CVMCRYPT_RSA_HASH_SHA256)   ? 32
                             : (hash_id == CVMCRYPT_RSA_HASH_SHA384) ? 48
                                                                     : 64;

    if (hashlen != hashlen_expected)
        return false;
    if (siglen != em_len)
        return false;

    /* EM = sig^e mod n. */
    CvmMpi sig_mpi, em_mpi;
    cvmcrypt_mpi_init(&sig_mpi);
    cvmcrypt_mpi_init(&em_mpi);

    if (!cvmcrypt_mpi_read_binary(&sig_mpi, sig, siglen))
        goto fail;
    if (!cvmcrypt_rsa_public(&em_mpi, &sig_mpi, key))
        goto fail;

    u8* em = rt_mem_alloc(em_len);
    if (em == NULL)
        goto fail;
    memset(em, 0, em_len);
    if (!cvmcrypt_mpi_write_binary(&em_mpi, em, em_len)) {
        rt_mem_free(em);
        goto fail;
    }

    /* RFC 8017 §9.1.2 EMSA-PSS-VERIFY:
     * EM = maskedDB || H || 0xbc
     * maskedDB is em[0 .. db_len-1], H is em[db_len .. db_len+hLen-1]. */
    usize db_len = em_len - hashlen - 1;

    /* Check the last byte: must be 0xbc. */
    if (em[em_len - 1] != 0xBC) {
        rt_mem_free(em);
        goto fail;
    }

    /* RFC 8017 §8.1.1: emBits = modBits - 1. The leftmost
     * (8*em_len - emBits) bits of EM must be zero. */
    u8 mask_bits = (u8)((8 * em_len - (n_bits - 1)) & 7);
    if (mask_bits > 0 && (em[0] >> (8 - mask_bits)) != 0) {
        rt_mem_free(em);
        goto fail;
    }

    /* dbMask = MGF1(H, db_len); DB = maskedDB XOR dbMask. */
    u8* db_mask = rt_mem_alloc(db_len);
    if (db_mask == NULL) {
        rt_mem_free(em);
        goto fail;
    }
    u8 const* h = em + db_len;
    u8* db = em; /* in-place unmask */
    mgf1(hash_id, h, hashlen, db_mask, db_len);
    for (usize i = 0; i < db_len; i++)
        db[i] ^= db_mask[i];

    /* Clear the leftmost mask_bits of DB[0]. */
    if (mask_bits > 0)
        db[0] &= (u8)((1 << (8 - mask_bits)) - 1);

    /* DB should be: PS (zeros) || 0x01 || salt. Find the 0x01. */
    usize idx = 0;
    while (idx < db_len && db[idx] == 0x00)
        idx++;
    if (idx >= db_len || db[idx] != 0x01) {
        rt_mem_free(db_mask);
        rt_mem_free(em);
        goto fail;
    }
    idx++; /* skip the 0x01 */

    /* salt = DB[idx .. db_len-1]. sLen = db_len - idx.
     * Compute M' = 0x00*8 || mHash || salt, then H' = Hash(M'). */
    usize salt_len = db_len - idx;
    u8 const* salt = db + idx;

    u8 m_prime[8 + 64 + 64]; /* 8 zero bits + max hash + max salt */
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, hash, hashlen);
    memcpy(m_prime + 8 + hashlen, salt, salt_len);

    u8 h_prime[64];
    usize m_prime_len = 8 + hashlen + salt_len;
    switch (hash_id) {
    case CVMCRYPT_RSA_HASH_SHA256: {
        CvmcryptSha256 ctx;
        cvmcrypt_sha256_init(&ctx);
        cvmcrypt_sha256_update(&ctx, m_prime, m_prime_len);
        cvmcrypt_sha256_final(&ctx, h_prime);
        break;
    }
    case CVMCRYPT_RSA_HASH_SHA384: {
        CvmcryptSha512 ctx;
        cvmcrypt_sha384_init(&ctx);
        cvmcrypt_sha512_update(&ctx, m_prime, m_prime_len);
        cvmcrypt_sha384_final(&ctx, h_prime);
        break;
    }
    case CVMCRYPT_RSA_HASH_SHA512: {
        CvmcryptSha512 ctx;
        cvmcrypt_sha512_init(&ctx);
        cvmcrypt_sha512_update(&ctx, m_prime, m_prime_len);
        cvmcrypt_sha512_final(&ctx, h_prime);
        break;
    }
    }

    /* Valid iff H' == H. */
    bool ok = cvmcrypt_ct_eq(h_prime, h, hashlen);

    rt_mem_free(db_mask);
    rt_mem_free(em);
    cvmcrypt_mpi_free(&sig_mpi);
    cvmcrypt_mpi_free(&em_mpi);
    return ok;

fail:
    cvmcrypt_mpi_free(&sig_mpi);
    cvmcrypt_mpi_free(&em_mpi);
    return false;
}
