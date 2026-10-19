/*
 * include/cvmcrypt/random.h
 *
 * Randomness, with the source installed by the embedder.
 *
 * cvmcrypt is freestanding: it cannot call getrandom, arc4random_buf or
 * BCryptGenRandom, and it must not silently invent a fallback. So the source
 * is a hook — the platform layer (cvmsockets, a test harness, a hosted app)
 * installs one at startup, and this layer fails loudly until it does.
 *
 * A default that quietly returns zeros would be the single worst thing this
 * library could do, which is why there is not one.
 */

#ifndef CVMCRYPT_RANDOM_H
#define CVMCRYPT_RANDOM_H

#include "base/types.h"

/* Fill `len` bytes. Must not fail: if the platform cannot produce random
 * bytes, it must abort rather than return. */
typedef void (*CvmcryptRandomFill)(u8* out, usize len, void* user);

/* Install the source. `user` is passed back to `fill` unchanged. Passing a
 * NULL fill removes the source and makes cvmcrypt_random() fail again. */
void cvmcrypt_random_set_source(CvmcryptRandomFill fill, void* user);

/* Returns false when no source is installed. */
bool cvmcrypt_random(u8* out, usize len);

/* Uniform value in [0, bound) by rejection sampling, not by modulo — modulo
 * biases the low residues whenever bound is not a power of two. Returns false
 * when no source is installed or bound is 0. */
bool cvmcrypt_random_below(u32* out, u32 bound);

#endif /* CVMCRYPT_RANDOM_H */
