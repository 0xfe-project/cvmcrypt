/*
 * tests/support/rt_stub.c
 *
 * The hosted stubs for cvm's rt/ platform layer. cvmcrypt references
 * rt_mem_alloc / rt_mem_free / rt_mem_zero / rt_time_* — resolved at
 * link time by whoever links the library. In cvm that is cvm's rt/.
 * In cvmcrypt's own tests there is no collector and no rt/, so the few
 * functions the library actually calls are stubbed here.
 *
 * This file is linked into every test binary. It is not part of the
 * library and must not be reachable from src/.
 */

#include <stdlib.h>
#include <sys/time.h>

#include "base/types.h"

void* rt_mem_alloc(usize bytes) {
    if (bytes == 0) {
        return NULL;
    }
    return malloc(bytes);
}

void rt_mem_free(void* p) {
    free(p);
}

void* rt_mem_realloc(void* p, usize bytes) {
    if (bytes == 0) {
        free(p);
        return NULL;
    }
    return realloc(p, bytes);
}

void rt_mem_zero(void* p, usize bytes) {
    unsigned char* d = p;
    for (usize i = 0; i < bytes; i++) {
        d[i] = 0;
    }
}

u64 rt_time_nanos(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (u64)tv.tv_sec * 1000000000ull + (u64)tv.tv_usec * 1000ull;
}

u64 rt_time_millis(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (u64)tv.tv_sec * 1000ull + (u64)tv.tv_usec / 1000ull;
}
