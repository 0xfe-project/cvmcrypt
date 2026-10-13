/*
 * src/base/secure.c
 *
 * Zeroising free and constant-time comparison. See secure.h for the
 * contracts.
 */

#include "base/secure.h"

#include "base/mem.h"

bool cvmcrypt_ct_eq(void const* a, void const* b, usize n) {
    u8 const* x = a;
    u8 const* y = b;
    u8 diff = 0;
    for (usize i = 0; i < n; i++) {
        diff |= x[i] ^ y[i];
    }
    return diff == 0;
}

void cvmcrypt_secure_free(void* p, usize n) {
    if (p == NULL) {
        return;
    }
    u8* d = p;
    for (usize i = 0; i < n; i++) {
        d[i] = 0;
    }
    /* rt_mem_free is declared in cvm's rt/rt.h. The link is resolved on
     * the hosted side; here we only reference it. */
    extern void rt_mem_free(void* p);
    rt_mem_free(p);
}
