/*
 * src/base/mem.h
 *
 * The four memory primitives the compiler is entitled to call in
 * freestanding C. Same contract as cvm's vm/mem.h: the compiler may emit
 * a call to memcpy, memmove, memset or memcmp for a struct assignment or
 * an array initialiser, and a libc-free translation unit has to provide
 * them.
 *
 * Hidden visibility so the symbols stay internal to the linked binary
 * and do not interpose on libc's.
 */

#ifndef CVMCRYPT_BASE_MEM_H
#define CVMCRYPT_BASE_MEM_H

#include "base/types.h"

#if defined(__GNUC__) || defined(__clang__)
#define CVMCRYPT_HIDDEN __attribute__((visibility("hidden")))
#else
#define CVMCRYPT_HIDDEN
#endif

CVMCRYPT_HIDDEN void* memcpy(void* restrict dst, void const* restrict src, usize n);
CVMCRYPT_HIDDEN void* memmove(void* dst, void const* src, usize n);
CVMCRYPT_HIDDEN void* memset(void* dst, int value, usize n);
CVMCRYPT_HIDDEN int memcmp(void const* a, void const* b, usize n);

#endif /* CVMCRYPT_BASE_MEM_H */
