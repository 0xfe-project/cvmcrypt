/*
 * include/cvmcrypt/cvmcrypt.h
 *
 * The public API of cvmcrypt.
 *
 * Everything under src/ is freestanding and references cvm's rt/ for
 * platform primitives. This header is the boundary: what vm/ and the
 * application see.
 *
 * Phase 1 of PLAN.md — nothing here yet. Each phase adds its surface.
 */

#ifndef CVMCRYPT_CVMCRYPT_H
#define CVMCRYPT_CVMCRYPT_H

#include "base/types.h"

#if defined(__GNUC__) || defined(__clang__)
#define CVMCRYPT_HIDDEN __attribute__((visibility("hidden")))
#else
#define CVMCRYPT_HIDDEN
#endif

#endif /* CVMCRYPT_CVMCRYPT_H */
