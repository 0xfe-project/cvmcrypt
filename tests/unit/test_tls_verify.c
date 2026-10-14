/*
 * tests/unit/test_tls_verify.c
 *
 * Certificate chain verification through the TLS callback interface.
 * Uses real OpenSSL-generated certificates.
 */

#include "vendor/greatest.h"

#include <string.h>
#include <stdio.h>

#include "tls/tls.h"
#include "tls/tls_internal.h"
#include "x509/x509.h"
#include "base/types.h"
#include "base/secure.h"

extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* Declarations from verify_cvm.c */
CvmTlsVerifyCert* cvm_tls_verify_cert_new(CvmTlsVec const* roots, usize num_roots);
void cvm_tls_verify_cert_free(CvmTlsVerifyCert* vc);
void cvm_tls_verify_cert_set_time(CvmTlsVerifyCert* vc, i64 unix_time);

/* ------------------------------------------------------------------ */
/* helper: load test certificates                                       */
/* ------------------------------------------------------------------ */

static bool load_file(char const* path, u8* buf, usize cap, usize* out_len) {
    FILE* f = fopen(path, "rb");
    if (f == NULL)
        return false;
    *out_len = fread(buf, 1, cap, f);
    fclose(f);
    return *out_len > 0;
}

/* ------------------------------------------------------------------ */
/* tests                                                                */
/* ------------------------------------------------------------------ */

TEST verify_self_signed_cert(void) {
    /* Load the self-signed test cert generated earlier. */
    u8 cert_der[4096];
    usize cert_len;
    if (!load_file("/tmp/test_cert.der", cert_der, sizeof(cert_der), &cert_len)) {
        SKIPm("test cert not available");
    }

    /* The cert is its own root. */
    CvmTlsVec roots[] = {{cert_der, cert_len}};

    CvmTlsVerifyCert* vc = cvm_tls_verify_cert_new(roots, 1);
    ASSERT(vc != NULL);

    /* Set time to within validity (cert is valid from ~2025-01). */
    cvm_tls_verify_cert_set_time(vc, 1792000000); /* Oct 2025 */

    /* Build the cert chain (just the self-signed cert). */
    CvmTlsVec certs[] = {{cert_der, cert_len}};

    int (*verify_sign)(void*, u16, CvmTlsVec, CvmTlsVec) = NULL;
    void* verify_data = NULL;

    int ret = vc->cb(vc, NULL, "example.com", &verify_sign, &verify_data, certs, 1);
    ASSERT_EQ(0, ret); /* should verify */
    ASSERT(verify_sign != NULL);

    cvm_tls_verify_cert_free(vc);
    PASS();
}

TEST verify_hostname_mismatch(void) {
    u8 cert_der[4096];
    usize cert_len;
    if (!load_file("/tmp/test_cert.der", cert_der, sizeof(cert_der), &cert_len)) {
        SKIPm("test cert not available");
    }

    CvmTlsVec roots[] = {{cert_der, cert_len}};
    CvmTlsVerifyCert* vc = cvm_tls_verify_cert_new(roots, 1);
    cvm_tls_verify_cert_set_time(vc, 1792000000);

    CvmTlsVec certs[] = {{cert_der, cert_len}};

    int ret = vc->cb(vc, NULL, "other-domain.org", NULL, NULL, certs, 1);
    ASSERT(ret != 0); /* should fail hostname check */

    cvm_tls_verify_cert_free(vc);
    PASS();
}

TEST verify_expired_cert(void) {
    u8 cert_der[4096];
    usize cert_len;
    if (!load_file("/tmp/test_cert.der", cert_der, sizeof(cert_der), &cert_len)) {
        SKIPm("test cert not available");
    }

    CvmTlsVec roots[] = {{cert_der, cert_len}};
    CvmTlsVerifyCert* vc = cvm_tls_verify_cert_new(roots, 1);
    /* Set time far in the future (cert expires in ~2026). */
    cvm_tls_verify_cert_set_time(vc, 1900000000); /* 2030 */

    CvmTlsVec certs[] = {{cert_der, cert_len}};

    int ret = vc->cb(vc, NULL, "example.com", NULL, NULL, certs, 1);
    ASSERT(ret != 0); /* should fail expiry check */

    cvm_tls_verify_cert_free(vc);
    PASS();
}

TEST verify_no_root(void) {
    u8 cert_der[4096];
    usize cert_len;
    if (!load_file("/tmp/test_cert.der", cert_der, sizeof(cert_der), &cert_len)) {
        SKIPm("test cert not available");
    }

    /* No trusted roots → chain should fail. */
    CvmTlsVerifyCert* vc = cvm_tls_verify_cert_new(NULL, 0);
    cvm_tls_verify_cert_set_time(vc, 1792000000);

    CvmTlsVec certs[] = {{cert_der, cert_len}};

    int ret = vc->cb(vc, NULL, "example.com", NULL, NULL, certs, 1);
    ASSERT(ret != 0); /* should fail (no trust anchor) */

    cvm_tls_verify_cert_free(vc);
    PASS();
}

TEST verify_empty_chain(void) {
    CvmTlsVerifyCert* vc = cvm_tls_verify_cert_new(NULL, 0);
    int ret = vc->cb(vc, NULL, "example.com", NULL, NULL, NULL, 0);
    ASSERT(ret != 0); /* empty chain → fail */
    cvm_tls_verify_cert_free(vc);
    PASS();
}

SUITE(tls_verify) {
    RUN_TEST(verify_self_signed_cert);
    RUN_TEST(verify_hostname_mismatch);
    RUN_TEST(verify_expired_cert);
    RUN_TEST(verify_no_root);
    RUN_TEST(verify_empty_chain);
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tls_verify);
    GREATEST_MAIN_END();
}
