/*
 * src/base/secure.h
 *
 * Zeroising allocation and constant-time comparison.
 *
 * The freestanding audit's memory allocation goes through cvm's
 * rt_mem_alloc / rt_mem_free. Those do not clear, and they must not:
 * clearing on every allocation would be a cost the runtime pays for
 * code that does not want it. Key material is the exception — it must
 * not outlive its use in any observable form, which means cleared
 * before freed.
 *
 * cvmcrypt_ct_eq is the constant-time equality test. It replaces ltc's
 * XMEM_NEQ and every "memcmp(key, tag, n) == 0" that a naive port would
 * write. Whether it is constant-time is not something the type checker
 * can see; it is a property of the loop below, which reads every byte
 * on every call.
 */

#ifndef CVMCRYPT_BASE_SECURE_H
#define CVMCRYPT_BASE_SECURE_H

#include "base/types.h"

/*
 * Compare n bytes in constant time. Returns true when equal.
 *
 * The accumulator is ORed, not short-circuited: the loop has no early
 * exit, and the branch on the result happens only after every byte has
 * been read. That is the property callers are relying on; it is the
 * whole point of this function existing.
 */
bool cvmcrypt_ct_eq(void const* a, void const* b, usize n);

/*
 * Zeroise n bytes then free through rt_mem_free.
 *
 * The zeroing is a plain loop rather than rt_mem_zero because the
 * freestanding flavour cannot see rt_mem_zero's implementation (it is
 * hosted), and a loop cannot be optimised away: the pointer escapes
 * into the free that follows, so every store is observable.
 *
 * Accepts NULL and does nothing — same contract as rt_mem_free.
 */
void cvmcrypt_secure_free(void* p, usize n);

#endif /* CVMCRYPT_BASE_SECURE_H */
