/*
 * include/cvmcrypt/cvmcrypt.h
 *
 * The public API of cvmcrypt.
 *
 * Everything under src/ is freestanding and references cvm's rt/ for
 * platform primitives. This header set is the boundary: what an embedder
 * sees.
 *
 * Two of the headers carry state by value rather than behind a pointer
 * (aead.h, cipher.h, hash.h). That is deliberate: cvmcrypt does not decide
 * where an embedder's memory comes from, so the context is a struct the
 * caller allocates. A 1.3 KB stack frame is cheaper than an allocator call
 * on the paths this library is used on.
 *
 * The subtrees under src/ (aead/, hash/, cipher/, ...) are on the include
 * path because the public contexts embed their state. The build line for any
 * consumer is therefore:
 *
 *     -I <cvmcrypt>/include -I <cvmcrypt>/src
 *
 * and nothing else.
 */

#ifndef CVMCRYPT_CVMCRYPT_H
#define CVMCRYPT_CVMCRYPT_H

#include "base/types.h"

#include "cvmcrypt/aead.h"
#include "cvmcrypt/cipher.h"
#include "cvmcrypt/hash.h"
#include "cvmcrypt/random.h"

#if defined(__GNUC__) || defined(__clang__)
#define CVMCRYPT_HIDDEN __attribute__((visibility("hidden")))
#else
#define CVMCRYPT_HIDDEN
#endif

#endif /* CVMCRYPT_CVMCRYPT_H */
