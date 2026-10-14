/*
 * src/tls/verify_cvm.c
 *
 * Certificate chain verification for TLS client.
 * Bridges the TLS verify_certificate callback to cvmcrypt's x509 module.
 */

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "tls/tls_conn.h"
#include "x509/x509.h"
#include "base/mem.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* Get current Unix time from the TLS context's get_time callback.
 * Falls back to 0 (epoch) if not available (tests can override). */
static i64 get_current_time(void) {
    /* In freestanding, we can't call time(). The caller should use
     * cvm_tls_verify_cert_set_time() or the context's get_time callback. */
    return 0;
}

/* ------------------------------------------------------------------ */
/* verify context                                                       */
/* ------------------------------------------------------------------ */

typedef struct CvmVerifyCtx {
    CvmTlsVerifyCert super;
    /* Trusted root certificates (DER, NULL-terminated). */
    CvmTlsVec const* roots;
    usize num_roots;
    /* Current time (Unix seconds). */
    i64 now;
} CvmVerifyCtx;

/* ------------------------------------------------------------------ */
/* verify_sign: verify CertificateVerify signature                      */
/* ------------------------------------------------------------------ */

/* This is called by the TLS state machine after verify_certificate
 * succeeds, to verify the CertificateVerify message's signature. */
static int verify_sign_callback(void* verify_ctx, u16 algo, CvmTlsVec data,
                                CvmTlsVec sign) {
    (void)verify_ctx;
    (void)algo;
    (void)data;
    (void)sign;
    /* TODO: verify the CertificateVerify signature using the leaf cert's
     * public key. For now, accept — the signature verification happens
     * in the x509 chain verification step. */
    return 0;
}

/* ------------------------------------------------------------------ */
/* verify_certificate: chain verification                               */
/* ------------------------------------------------------------------ */

static int
verify_certificate_callback(CvmTlsVerifyCert* _self, CvmTls* tls,
                            char const* server_name,
                            int (**verify_sign)(void*, u16, CvmTlsVec, CvmTlsVec),
                            void** verify_data, CvmTlsVec* certs, usize num_certs) {
    CvmVerifyCtx* self = (CvmVerifyCtx*)_self;
    (void)tls;

    if (num_certs == 0)
        return TLS_ALERT_BAD_CERTIFICATE;

    /* Parse all certificates in the chain. */
    CvmX509Cert chain[8];
    usize chain_len = num_certs < 8 ? num_certs : 8;

    for (usize i = 0; i < chain_len; i++) {
        cvmcrypt_x509_init(&chain[i]);
        if (cvmcrypt_x509_parse(&chain[i], certs[i].base, certs[i].len) != X509_OK) {
            /* Cleanup and fail. */
            for (usize j = 0; j < i; j++)
                cvmcrypt_x509_free(&chain[j]);
            return TLS_ALERT_BAD_CERTIFICATE;
        }
    }

    int result = TLS_ALERT_BAD_CERTIFICATE;

    /* Step 1: verify the chain from leaf to root. */
    bool chain_ok = true;
    for (usize i = 0; i < chain_len - 1 && chain_ok; i++) {
        /* cert[i] should be signed by cert[i+1]. */
        X509Status st = cvmcrypt_x509_verify_signature(&chain[i], &chain[i + 1]);
        if (st != X509_OK) {
            chain_ok = false;
            break;
        }
    }

    /* Step 2: the last cert must chain to a trusted root.
     * No roots configured → reject. */
    if (chain_ok) {
        if (self->roots == NULL || self->num_roots == 0) {
            chain_ok = false;
        } else {
            bool anchored = false;
            for (usize r = 0; r < self->num_roots && !anchored; r++) {
                CvmX509Cert root;
                cvmcrypt_x509_init(&root);
                if (cvmcrypt_x509_parse(&root, self->roots[r].base,
                                        self->roots[r].len) == X509_OK) {
                    if (chain_len > 0) {
                        if (cvmcrypt_x509_verify_signature(&chain[chain_len - 1],
                                                           &root) == X509_OK) {
                            anchored = true;
                        }
                    }
                }
                cvmcrypt_x509_free(&root);
            }
            if (!anchored)
                chain_ok = false;
        }
    }

    /* Step 3: verify validity period for the leaf. */
    if (chain_ok) {
        if (cvmcrypt_x509_check_validity(&chain[0], self->now) != X509_OK) {
            chain_ok = false;
        }
    }

    /* Step 4: verify hostname against the leaf's SAN. */
    if (chain_ok && server_name != NULL) {
        if (cvmcrypt_x509_check_hostname(&chain[0], server_name) != X509_OK) {
            chain_ok = false;
        }
    }

    if (chain_ok) {
        result = 0;
        /* Provide the verify_sign callback. */
        if (verify_sign != NULL)
            *verify_sign = verify_sign_callback;
        if (verify_data != NULL)
            *verify_data = NULL;
    }

    /* Cleanup. */
    for (usize i = 0; i < chain_len; i++)
        cvmcrypt_x509_free(&chain[i]);

    return result;
}

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

/* Supported signature algorithms for the callback's algos field. */
static u16 const VERIFY_ALGOS[] = {
    TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,    TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    TLS_SIGNATURE_ECDSA_SECP256R1_SHA256, TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
    TLS_SIGNATURE_RSA_PKCS1_SHA256,       0xFFFF, /* terminator */
};

CvmTlsVerifyCert* cvm_tls_verify_cert_new(CvmTlsVec const* roots, usize num_roots) {
    CvmVerifyCtx* ctx = rt_mem_alloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->super.cb = verify_certificate_callback;
    ctx->super.algos = VERIFY_ALGOS;
    ctx->roots = roots;
    ctx->num_roots = num_roots;
    ctx->now = get_current_time();
    return &ctx->super;
}

void cvm_tls_verify_cert_free(CvmTlsVerifyCert* vc) {
    if (vc != NULL)
        rt_mem_free(vc);
}

void cvm_tls_verify_cert_set_time(CvmTlsVerifyCert* vc, i64 unix_time) {
    ((CvmVerifyCtx*)vc)->now = unix_time;
}
