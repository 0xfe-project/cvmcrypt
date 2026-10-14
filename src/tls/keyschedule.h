/*
 * src/tls/keyschedule.h
 *
 * TLS 1.3 key schedule state.
 */

#ifndef CVMCRYPT_TLS_KEYSCHEDULE_H
#define CVMCRYPT_TLS_KEYSCHEDULE_H

#include "tls/tls.h"

typedef struct CvmTlsKeySched {
    CvmTlsCipherSuite const* suite;
    CvmTlsHash* hash_ctx; /* running transcript hash */
    u8 secret[TLS_MAX_DIGEST_SIZE];
    u32 generation; /* 0=init, 1=early, 2=handshake, 3=master */
} CvmTlsKeySched;

void cvm_tls_ks_init(CvmTlsKeySched* ks, CvmTlsCipherSuite const* suite);
void cvm_tls_ks_free(CvmTlsKeySched* ks);

/* Advance to the next secret generation. */
int cvm_tls_ks_extract(CvmTlsKeySched* ks, CvmTlsVec ikm);

/* Derive-Secret(secret, label, Transcript-Hash). */
int cvm_tls_ks_derive_secret(CvmTlsKeySched* ks, void* secret, char const* label);

/* Feed a handshake message into the transcript hash. */
void cvm_tls_ks_update_hash(CvmTlsKeySched* ks, u8 const* msg, usize msglen);

/* Derive AEAD key + iv from a traffic secret. */
int cvm_tls_ks_get_traffic_keys(CvmTlsKeySched* ks, void* key, usize key_size, void* iv,
                                usize iv_size, void const* secret);

/* Compute Finished verify_data = HMAC(finished_key, Transcript-Hash). */
int cvm_tls_ks_calc_verify_data(CvmTlsKeySched* ks, void* output, void const* secret);

#endif /* CVMCRYPT_TLS_KEYSCHEDULE_H */
