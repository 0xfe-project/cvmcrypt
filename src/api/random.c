/*
 * src/api/random.c
 *
 * The randomness hook from include/cvmcrypt/random.h.
 *
 * There is no default source and no fallback. A freestanding library that
 * quietly returns zeros when it cannot get entropy is the worst possible
 * failure mode, so cvmcrypt_random() returns false until the embedder
 * installs one.
 */

#include "cvmcrypt/random.h"

#include "base/mem.h"

static CvmcryptRandomFill g_fill;
static void* g_user;

void cvmcrypt_random_set_source(CvmcryptRandomFill fill, void* user) {
    g_fill = fill;
    g_user = fill ? user : NULL;
}

bool cvmcrypt_random(u8* out, usize len) {
    if (g_fill == NULL) {
        return false;
    }
    if (len == 0) {
        return true;
    }
    if (out == NULL) {
        return false;
    }
    g_fill(out, len, g_user);
    return true;
}

bool cvmcrypt_random_below(u32* out, u32 bound) {
    if (out == NULL || bound == 0) {
        return false;
    }

    /*
     * Rejection sampling, not modulo. Taking v % bound biases the low
     * residues by one whenever bound does not divide 2^32, which is exactly
     * the case an attacker exploits in a nonce or a CID.
     *
     * threshold = 2^32 mod bound; values below it are the surplus and are
     * drawn again.
     */
    u32 const threshold = (u32)(0u - bound) % bound;

    for (;;) {
        u32 v;
        if (!cvmcrypt_random((u8*)&v, sizeof(v))) {
            return false;
        }
        if (v >= threshold) {
            *out = v % bound;
            return true;
        }
    }
}
