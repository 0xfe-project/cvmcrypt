/*
 * src/math/bignum.c
 *
 * Multi-precision integer arithmetic for RSA/ECC/x509.
 * Carried from mbedtls 3.6.7 (Apache-2.0), adapted to cvm conventions.
 *
 * Limbs are u64, little-endian. Sign is ±1 in the mpi struct.
 * Memory: rt_mem_alloc / rt_mem_free.
 */

#include "math/bignum.h"

#include "base/mem.h"

/* Platform allocator (resolved at link time, same pattern as secure.c). */
extern void* rt_mem_alloc(usize bytes);
extern void rt_mem_free(void* p);

/* ------------------------------------------------------------------ */
/* init / free / grow                                                  */
/* ------------------------------------------------------------------ */

void cvmcrypt_mpi_init(CvmMpi* X) {
    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

void cvmcrypt_mpi_free(CvmMpi* X) {
    if (X == NULL)
        return;
    if (X->p != NULL) {
        memset(X->p, 0, X->n * sizeof(mpi_uint));
        rt_mem_free(X->p);
    }
    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

bool cvmcrypt_mpi_grow(CvmMpi* X, usize nblimbs) {
    mpi_uint* p;
    if (nblimbs > MPI_MAX_LIMBS)
        return false;
    if (X->n < nblimbs) {
        p = rt_mem_alloc(nblimbs * sizeof(mpi_uint));
        if (p == NULL)
            return false;
        memset(p, 0, nblimbs * sizeof(mpi_uint));
        if (X->n > 0 && X->p != NULL) {
            memcpy(p, X->p, X->n * sizeof(mpi_uint));
            memset(X->p, 0, X->n * sizeof(mpi_uint));
            rt_mem_free(X->p);
        }
        X->n = nblimbs;
        X->p = p;
    }
    return true;
}

bool cvmcrypt_mpi_resize(CvmMpi* X, usize nblimbs) {
    if (nblimbs > MPI_MAX_LIMBS)
        return false;
    if (X->n > nblimbs) {
        /* Zero the limbs being removed. */
        memset(X->p + nblimbs, 0, (X->n - nblimbs) * sizeof(mpi_uint));
    }
    return cvmcrypt_mpi_grow(X, nblimbs);
}

void cvmcrypt_mpi_shrink(CvmMpi* X) {
    usize i;
    if (X == NULL || X->p == NULL)
        return;
    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0)
            break;
    }
    X->n = i;
    if (X->n == 0)
        X->s = 1;
}

/* ------------------------------------------------------------------ */
/* copy / swap                                                         */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_copy(CvmMpi* X, CvmMpi const* A) {
    if (X == A)
        return true;
    if (A->n == 0) {
        cvmcrypt_mpi_free(X);
        return true;
    }
    if (!cvmcrypt_mpi_grow(X, A->n))
        return false;
    memset(X->p, 0, X->n * sizeof(mpi_uint));
    memcpy(X->p, A->p, A->n * sizeof(mpi_uint));
    X->s = A->s;
    return true;
}

bool cvmcrypt_mpi_copy_assign(CvmMpi* X, CvmMpi const* A) {
    cvmcrypt_mpi_free(X);
    return cvmcrypt_mpi_copy(X, A);
}

void cvmcrypt_mpi_swap(CvmMpi* X, CvmMpi* Y) {
    CvmMpi T = *X;
    *X = *Y;
    *Y = T;
}

/* ------------------------------------------------------------------ */
/* comparison                                                          */
/* ------------------------------------------------------------------ */

i32 cvmcrypt_mpi_cmp_abs(CvmMpi const* X, CvmMpi const* Y) {
    usize i, j;
    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0)
            break;
    }
    for (j = Y->n; j > 0; j--) {
        if (Y->p[j - 1] != 0)
            break;
    }
    if (i == 0 && j == 0)
        return 0;
    if (i > j)
        return 1;
    if (j > i)
        return -1;
    for (; i > 0; i--) {
        if (X->p[i - 1] > Y->p[i - 1])
            return 1;
        if (X->p[i - 1] < Y->p[i - 1])
            return -1;
    }
    return 0;
}

i32 cvmcrypt_mpi_cmp_mpi(CvmMpi const* X, CvmMpi const* Y) {
    usize i, j;
    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0)
            break;
    }
    for (j = Y->n; j > 0; j--) {
        if (Y->p[j - 1] != 0)
            break;
    }
    if (i == 0 && j == 0)
        return 0;
    if (i == 0)
        return (Y->s > 0) ? -1 : 1;
    if (j == 0)
        return (X->s > 0) ? 1 : -1;
    if (X->s > 0 && Y->s < 0)
        return 1;
    if (X->s < 0 && Y->s > 0)
        return -1;
    if (i > j)
        return (X->s > 0) ? 1 : -1;
    if (j > i)
        return (X->s > 0) ? -1 : 1;
    for (; i > 0; i--) {
        if (X->p[i - 1] > Y->p[i - 1])
            return (X->s > 0) ? 1 : -1;
        if (X->p[i - 1] < Y->p[i - 1])
            return (X->s > 0) ? -1 : 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* bit operations                                                      */
/* ------------------------------------------------------------------ */

usize cvmcrypt_mpi_bitlen(CvmMpi const* X) {
    usize i;
    for (i = X->n; i > 0; i--) {
        if (X->p[i - 1] != 0)
            break;
    }
    if (i == 0)
        return 0;
    mpi_uint limb = X->p[i - 1];
    usize bits = 0;
    while (limb != 0) {
        limb >>= 1;
        bits++;
    }
    return (i - 1) * MPI_LIMB_BITS + bits;
}

usize cvmcrypt_mpi_lsb(CvmMpi const* X) {
    usize i, j;
    for (i = 0; i < X->n; i++) {
        if (X->p[i] != 0) {
            mpi_uint limb = X->p[i];
            for (j = 0; j < MPI_LIMB_BITS; j++) {
                if (limb & 1)
                    return i * MPI_LIMB_BITS + j;
                limb >>= 1;
            }
        }
    }
    return 0;
}

u64 cvmcrypt_mpi_get_bit(CvmMpi const* X, usize pos) {
    if (X->n * MPI_LIMB_BITS <= pos)
        return 0;
    return (X->p[pos / MPI_LIMB_BITS] >> (pos % MPI_LIMB_BITS)) & 1;
}

bool cvmcrypt_mpi_is_zero(CvmMpi const* X) {
    for (usize i = 0; i < X->n; i++) {
        if (X->p[i] != 0)
            return false;
    }
    return true;
}

void cvmcrypt_mpi_zeroize(CvmMpi* X) {
    memset(X->p, 0, X->n * sizeof(mpi_uint));
    X->s = 1;
}

/* ------------------------------------------------------------------ */
/* add / sub (absolute values, no sign handling)                      */
/* ------------------------------------------------------------------ */

/* Helper: add limb arrays, same length. Returns carry. */

/* Helper: sub limb arrays, same length (A >= B). Returns borrow (0). */

bool cvmcrypt_mpi_add_abs(CvmMpi* X, CvmMpi const* A, CvmMpi const* B) {
    usize n = (A->n > B->n) ? A->n : B->n;
    if (!cvmcrypt_mpi_grow(X, n + 1))
        return false;
    /* Zero-extend the shorter operand. */
    mpi_uint* Ad = A->p;
    mpi_uint* Bd = B->p;
    /* We use the fact that X's buffer is zeroed to zero-extend. */
    u64 carry = 0;
    for (usize i = 0; i < n; i++) {
        u64 a = (i < A->n) ? Ad[i] : 0;
        u64 b = (i < B->n) ? Bd[i] : 0;
        unsigned __int128 s = (unsigned __int128)a + b + carry;
        X->p[i] = (mpi_uint)s;
        carry = (u64)(s >> 64);
    }
    if (carry)
        X->p[n] = (mpi_uint)carry;
    else
        X->p[n] = 0;
    X->n = n + 1;
    X->s = 1;
    cvmcrypt_mpi_shrink(X);
    return true;
}

bool cvmcrypt_mpi_sub_abs(CvmMpi* X, CvmMpi const* A, CvmMpi const* B) {
    if (cvmcrypt_mpi_cmp_abs(A, B) < 0)
        return false; /* A < B: underflow */
    usize n = A->n;
    if (!cvmcrypt_mpi_grow(X, n))
        return false;
    u64 borrow = 0;
    for (usize i = 0; i < n; i++) {
        u64 a = A->p[i];
        u64 b = (i < B->n) ? B->p[i] : 0;
        u64 d = a - b - borrow;
        X->p[i] = (mpi_uint)d;
        /* Borrow detection: if the unsigned result is larger than the
         * minuend, the subtraction wrapped around (underflowed). */
        borrow = (d > a) ? 1 : 0;
    }
    X->s = 1;
    cvmcrypt_mpi_shrink(X);
    return true;
}

/* ------------------------------------------------------------------ */
/* multiply                                                            */
/* ------------------------------------------------------------------ */

/* Schoolbook multiplication using __int128. */
bool cvmcrypt_mpi_mul_mpi(CvmMpi* X, CvmMpi const* A, CvmMpi const* B) {
    CvmMpi ta, tb;
    cvmcrypt_mpi_init(&ta);
    cvmcrypt_mpi_init(&tb);

    /* Handle aliasing: grow(X) may free the buffer A or B points to. */
    if (X == A || X == B) {
        if (!cvmcrypt_mpi_copy(&ta, A) || !cvmcrypt_mpi_copy(&tb, B))
            goto fail;
        A = &ta;
        B = &tb;
    }

    usize n = A->n + B->n;
    if (n == 0) {
        cvmcrypt_mpi_free(X);
        cvmcrypt_mpi_free(&ta);
        cvmcrypt_mpi_free(&tb);
        return true;
    }
    if (!cvmcrypt_mpi_grow(X, n))
        goto fail;
    memset(X->p, 0, X->n * sizeof(mpi_uint));

    for (usize i = 0; i < A->n; i++) {
        unsigned __int128 carry = 0;
        for (usize j = 0; j < B->n; j++) {
            unsigned __int128 t =
                (unsigned __int128)A->p[i] * B->p[j] + X->p[i + j] + carry;
            X->p[i + j] = (mpi_uint)t;
            carry = t >> 64;
        }
        if (i + B->n < X->n)
            X->p[i + B->n] += (mpi_uint)carry;
    }
    X->s = A->s * B->s;
    X->n = n;
    cvmcrypt_mpi_shrink(X);
    cvmcrypt_mpi_free(&ta);
    cvmcrypt_mpi_free(&tb);
    return true;

fail:
    cvmcrypt_mpi_free(&ta);
    cvmcrypt_mpi_free(&tb);
    return false;
}

/* ------------------------------------------------------------------ */
/* divide (Knuth Algorithm D, simplified)                              */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_div_mpi(CvmMpi* Q, CvmMpi* R, CvmMpi const* A, CvmMpi const* B) {
    if (cvmcrypt_mpi_is_zero((CvmMpi*)B))
        return false; /* division by zero */

    /* If A < B, Q=0, R=A. */
    if (cvmcrypt_mpi_cmp_abs(A, B) < 0) {
        if (Q != NULL) {
            cvmcrypt_mpi_free(Q);
        }
        if (R != NULL) {
            if (!cvmcrypt_mpi_copy(R, A))
                return false;
        }
        return true;
    }

    /* Simple bit-by-bit long division. Not fast but correct.
     * Pre-allocates fixed buffers; no malloc/free inside the loop. */
    usize bits = cvmcrypt_mpi_bitlen(A);
    usize b_limbs = B->n;
    usize r_cap = b_limbs + 1; /* remainder ≤ 2*B after shift */
    usize q_limbs = (bits + MPI_LIMB_BITS - 1) / MPI_LIMB_BITS;

    CvmMpi quotient, remainder;
    cvmcrypt_mpi_init(&quotient);
    cvmcrypt_mpi_init(&remainder);

    if (!cvmcrypt_mpi_grow(&quotient, q_limbs ? q_limbs : 1))
        goto fail;
    if (!cvmcrypt_mpi_grow(&remainder, r_cap))
        goto fail;
    memset(quotient.p, 0, quotient.n * sizeof(mpi_uint));
    memset(remainder.p, 0, remainder.n * sizeof(mpi_uint));
    remainder.n = 0;

    for (i32 i = (i32)bits - 1; i >= 0; i--) {
        /* R = R << 1 | bit i of A — inline shift, no allocation. */
        mpi_uint carry = 0;
        for (usize j = 0; j < remainder.n; j++) {
            mpi_uint next = remainder.p[j] >> (MPI_LIMB_BITS - 1);
            remainder.p[j] = (remainder.p[j] << 1) | carry;
            carry = next;
        }
        if (carry && remainder.n < r_cap) {
            remainder.p[remainder.n] = carry;
            remainder.n++;
        }
        if (cvmcrypt_mpi_get_bit(A, (usize)i)) {
            if (remainder.n == 0)
                remainder.n = 1;
            remainder.p[0] |= 1;
        }
        /* If R >= B: R -= B in place, Q bit i = 1.
         * Loop over r_cap limbs (buffer is pre-zeroed beyond remainder.n)
         * so the borrow propagates into the extra limb when R > B. */
        if (cvmcrypt_mpi_cmp_abs(&remainder, B) >= 0) {
            mpi_uint borrow = 0;
            for (usize j = 0; j < r_cap; j++) {
                mpi_uint const bj = (j < B->n) ? B->p[j] : 0;
                mpi_uint const aj = (j < remainder.n) ? remainder.p[j] : 0;
                remainder.p[j] = aj - bj - borrow;
                borrow = (aj < bj) || (aj == bj && borrow == 1);
            }
            while (remainder.n > 0 && remainder.p[remainder.n - 1] == 0)
                remainder.n--;
            quotient.p[i / MPI_LIMB_BITS] |= (mpi_uint)1 << (i % MPI_LIMB_BITS);
        }
    }

    quotient.s = 1;
    remainder.s = 1;
    cvmcrypt_mpi_shrink(&quotient);
    cvmcrypt_mpi_shrink(&remainder);

    if (Q != NULL) {
        cvmcrypt_mpi_swap(Q, &quotient);
    }
    if (R != NULL) {
        cvmcrypt_mpi_swap(R, &remainder);
    }
    cvmcrypt_mpi_free(&quotient);
    cvmcrypt_mpi_free(&remainder);
    return true;

fail:
    cvmcrypt_mpi_free(&quotient);
    cvmcrypt_mpi_free(&remainder);
    return false;
}

bool cvmcrypt_mpi_mod_mpi(CvmMpi* R, CvmMpi const* A, CvmMpi const* N) {
    if (R == A) {
        /* Aliasing: use a temporary. */
        CvmMpi t;
        cvmcrypt_mpi_init(&t);
        bool ok = cvmcrypt_mpi_div_mpi(NULL, &t, A, N);
        if (ok)
            cvmcrypt_mpi_swap(R, &t);
        cvmcrypt_mpi_free(&t);
        return ok;
    }
    return cvmcrypt_mpi_div_mpi(NULL, R, A, N);
}

/* ------------------------------------------------------------------ */
/* modular exponentiation (square-and-multiply)                        */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_exp_mod(CvmMpi* X, CvmMpi const* A, CvmMpi const* E,
                          CvmMpi const* N) {
    if (cvmcrypt_mpi_is_zero((CvmMpi*)N))
        return false;
    if (cvmcrypt_mpi_cmp_abs(A, N) >= 0) {
        /* Reduce A mod N first. */
        CvmMpi r;
        cvmcrypt_mpi_init(&r);
        if (!cvmcrypt_mpi_mod_mpi(&r, A, N)) {
            cvmcrypt_mpi_free(&r);
            return false;
        }
        bool ok = cvmcrypt_mpi_exp_mod(X, &r, E, N);
        cvmcrypt_mpi_free(&r);
        return ok;
    }

    CvmMpi result, base;
    cvmcrypt_mpi_init(&result);
    cvmcrypt_mpi_init(&base);

    /* result = 1 */
    if (!cvmcrypt_mpi_grow(&result, 1))
        goto fail;
    result.p[0] = 1;
    result.n = 1;
    result.s = 1;

    /* base = A */
    if (!cvmcrypt_mpi_copy(&base, A))
        goto fail;

    usize bits = cvmcrypt_mpi_bitlen(E);
    for (usize i = 0; i < bits; i++) {
        if (cvmcrypt_mpi_get_bit(E, i)) {
            if (!cvmcrypt_mpi_mul_mpi(&result, &result, &base))
                goto fail;
            if (!cvmcrypt_mpi_mod_mpi(&result, &result, N))
                goto fail;
        }
        if (!cvmcrypt_mpi_mul_mpi(&base, &base, &base))
            goto fail;
        if (!cvmcrypt_mpi_mod_mpi(&base, &base, N))
            goto fail;
    }

    cvmcrypt_mpi_swap(X, &result);
    cvmcrypt_mpi_free(&result);
    cvmcrypt_mpi_free(&base);
    return true;

fail:
    cvmcrypt_mpi_free(&result);
    cvmcrypt_mpi_free(&base);
    return false;
}

/* ------------------------------------------------------------------ */
/* Montgomery multiplication                                           */
/* ------------------------------------------------------------------ */

/* Compute the Montgomery constant mm = -N^{-1} mod 2^64. */
mpi_uint cvmcrypt_mpi_montgomery_calibrate(mpi_uint N) {
    mpi_uint mm = 1;
    mpi_uint t = N;
    for (usize i = 1; i < MPI_LIMB_BITS; i++) {
        mm *= (mpi_uint)2 - t * mm; /* Newton-Raphson iteration */
        t = N * mm;
    }
    return (mpi_uint)(-(i64)mm); /* -mm mod 2^64 */
}

bool cvmcrypt_mpi_montmul(CvmMpi* X, CvmMpi const* A, CvmMpi const* B, CvmMpi const* N,
                          mpi_uint mm) {
    (void)mm;
    /* Simplified: use regular multiplication + reduction. */
    if (!cvmcrypt_mpi_mul_mpi(X, A, B))
        return false;
    return cvmcrypt_mpi_mod_mpi(X, X, N);
}

/* ------------------------------------------------------------------ */
/* modular inverse                                                     */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_inv_mod(CvmMpi* X, CvmMpi const* A, CvmMpi const* N) {
    /* Iterative extended Euclidean algorithm.
     * Maintains: r_i = t_i * A (mod N). When r becomes 1, t is the inverse.
     *   r = N, new_r = A mod N
     *   t = 0, new_t = 1
     *   while new_r != 0:
     *     q = r / new_r
     *     (r, new_r) = (new_r, r - q*new_r)
     *     (t, new_t) = (new_t, t - q*new_t)
     *   if r != 1: no inverse exists
     *   return t (if negative, add N)
     */
    CvmMpi r, new_r, t, new_t, q, tmp;
    cvmcrypt_mpi_init(&r);
    cvmcrypt_mpi_init(&new_r);
    cvmcrypt_mpi_init(&t);
    cvmcrypt_mpi_init(&new_t);
    cvmcrypt_mpi_init(&q);
    cvmcrypt_mpi_init(&tmp);

    bool ok = false;

    /* r = N, new_r = A mod N */
    if (!cvmcrypt_mpi_copy(&r, N))
        goto done;
    if (!cvmcrypt_mpi_mod_mpi(&new_r, A, N))
        goto done;
    /* t = 0, new_t = 1 */
    {
        u8 one = 1;
        if (!cvmcrypt_mpi_read_binary(&new_t, &one, 1))
            goto done;
    }

    while (!cvmcrypt_mpi_is_zero(&new_r)) {
        /* q = r / new_r */
        if (!cvmcrypt_mpi_div_mpi(&q, NULL, &r, &new_r))
            goto done;
        /* tmp = q * new_r */
        if (!cvmcrypt_mpi_mul_mpi(&tmp, &q, &new_r))
            goto done;
        /* new_r <-> r - tmp */
        {
            CvmMpi next_r;
            cvmcrypt_mpi_init(&next_r);
            /* r >= new_r always (invariant of Euclid), so r - tmp >= 0 */
            if (!cvmcrypt_mpi_sub_abs(&next_r, &r, &tmp)) {
                cvmcrypt_mpi_free(&next_r);
                goto done;
            }
            cvmcrypt_mpi_swap(&r, &new_r);      /* r = old new_r */
            cvmcrypt_mpi_swap(&new_r, &next_r); /* new_r = r - q*new_r */
            cvmcrypt_mpi_free(&next_r);
        }
        /* t update: new_t <-> t - q*new_t (signed).
         * q is always positive, so tmp.s = new_t.s. */
        {
            if (!cvmcrypt_mpi_mul_mpi(&tmp, &q, &new_t))
                goto done;
            CvmMpi next_t;
            cvmcrypt_mpi_init(&next_t);
            if (t.s == tmp.s) {
                /* Same sign: |result| = ||t| - |tmp||, sign of larger. */
                if (cvmcrypt_mpi_cmp_abs(&t, &tmp) >= 0) {
                    if (!cvmcrypt_mpi_sub_abs(&next_t, &t, &tmp)) {
                        cvmcrypt_mpi_free(&next_t);
                        goto done;
                    }
                    next_t.s = t.s;
                } else {
                    if (!cvmcrypt_mpi_sub_abs(&next_t, &tmp, &t)) {
                        cvmcrypt_mpi_free(&next_t);
                        goto done;
                    }
                    next_t.s = -t.s;
                }
            } else {
                /* Different signs: |result| = |t| + |tmp|, sign of t. */
                if (!cvmcrypt_mpi_add_abs(&next_t, &t, &tmp)) {
                    cvmcrypt_mpi_free(&next_t);
                    goto done;
                }
                next_t.s = t.s;
            }
            cvmcrypt_mpi_swap(&t, &new_t);
            cvmcrypt_mpi_swap(&new_t, &next_t);
            cvmcrypt_mpi_free(&next_t);
        }
    }

    /* r must be 1 for an inverse to exist. */
    if (r.n != 1 || r.p[0] != 1)
        goto done;

    /* If t is negative: X = N - |t| (since 0 < |t| < N when gcd = 1). */
    if (t.s < 0) {
        CvmMpi pos;
        cvmcrypt_mpi_init(&pos);
        if (!cvmcrypt_mpi_sub_abs(&pos, N, &t)) {
            cvmcrypt_mpi_free(&pos);
            goto done;
        }
        cvmcrypt_mpi_swap(X, &pos);
        cvmcrypt_mpi_free(&pos);
    } else {
        /* Reduce t mod N (t might exceed N). */
        if (!cvmcrypt_mpi_mod_mpi(X, &t, N))
            goto done;
    }

    ok = true;
done:
    cvmcrypt_mpi_free(&r);
    cvmcrypt_mpi_free(&new_r);
    cvmcrypt_mpi_free(&t);
    cvmcrypt_mpi_free(&new_t);
    cvmcrypt_mpi_free(&q);
    cvmcrypt_mpi_free(&tmp);
    return ok;
}

/* ------------------------------------------------------------------ */
/* import / export                                                     */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_read_binary(CvmMpi* X, u8 const* buf, usize buflen) {
    if (buflen == 0) {
        cvmcrypt_mpi_free(X);
        return true;
    }
    usize nlimbs = (buflen + MPI_LIMB_BYTES - 1) / MPI_LIMB_BYTES;
    if (!cvmcrypt_mpi_grow(X, nlimbs))
        return false;
    memset(X->p, 0, X->n * sizeof(mpi_uint));
    X->s = 1;

    /* Big-endian input: process from the end. */
    for (usize i = 0; i < buflen; i++) {
        usize byte_from_end = buflen - 1 - i;
        X->p[byte_from_end / MPI_LIMB_BYTES] |=
            (mpi_uint)buf[i] << ((byte_from_end % MPI_LIMB_BYTES) * 8);
    }

    cvmcrypt_mpi_shrink(X);
    return true;
}

bool cvmcrypt_mpi_write_binary(CvmMpi const* X, u8* buf, usize buflen) {
    usize bits = cvmcrypt_mpi_bitlen(X);
    usize bytes = (bits + 7) / 8;
    if (bytes > buflen)
        return false;

    memset(buf, 0, buflen);
    /* Right-align: the value occupies the LAST `bytes` bytes of the
     * buffer (big-endian, zero-padded from the left). This matches
     * PKCS#1's EM representation where leading zeros are significant. */
    u8* out = buf + (buflen - bytes);
    for (usize i = 0; i < bytes; i++) {
        usize byte_from_end = bytes - 1 - i;
        out[i] = (u8)(X->p[byte_from_end / MPI_LIMB_BYTES] >>
                      ((byte_from_end % MPI_LIMB_BYTES) * 8));
    }
    return true;
}

bool cvmcrypt_mpi_read_string_le(CvmMpi* X, u8 const* buf, usize buflen) {
    if (buflen == 0) {
        cvmcrypt_mpi_free(X);
        return true;
    }
    usize nlimbs = (buflen + MPI_LIMB_BYTES - 1) / MPI_LIMB_BYTES;
    if (!cvmcrypt_mpi_grow(X, nlimbs))
        return false;
    memset(X->p, 0, X->n * sizeof(mpi_uint));
    X->s = 1;

    for (usize i = 0; i < buflen; i++) {
        X->p[i / MPI_LIMB_BYTES] |= (mpi_uint)buf[i] << ((i % MPI_LIMB_BYTES) * 8);
    }

    cvmcrypt_mpi_shrink(X);
    return true;
}

/* ------------------------------------------------------------------ */
/* shift                                                               */
/* ------------------------------------------------------------------ */

bool cvmcrypt_mpi_shift_l(CvmMpi* X, usize count) {
    if (count == 0 || cvmcrypt_mpi_is_zero(X))
        return true;
    usize limb_shift = count / MPI_LIMB_BITS;
    usize bit_shift = count % MPI_LIMB_BITS;
    usize new_n = X->n + limb_shift + 1;
    if (new_n > MPI_MAX_LIMBS)
        return false;

    if (!cvmcrypt_mpi_grow(X, new_n))
        return false;

    if (limb_shift > 0) {
        /* Shift limbs. */
        for (usize i = X->n; i > 0; i--) {
            X->p[i - 1 + limb_shift] = X->p[i - 1];
        }
        memset(X->p, 0, limb_shift * sizeof(mpi_uint));
    }
    if (bit_shift > 0) {
        mpi_uint carry = 0;
        for (usize i = limb_shift; i < X->n + limb_shift; i++) {
            mpi_uint next = X->p[i] >> (MPI_LIMB_BITS - bit_shift);
            X->p[i] = (X->p[i] << bit_shift) | carry;
            carry = next;
        }
        if (carry)
            X->p[X->n + limb_shift] = carry;
    }
    X->n = new_n;
    cvmcrypt_mpi_shrink(X);
    return true;
}

bool cvmcrypt_mpi_shift_r(CvmMpi* X, usize count) {
    if (count == 0 || cvmcrypt_mpi_is_zero(X))
        return true;
    usize limb_shift = count / MPI_LIMB_BITS;
    usize bit_shift = count % MPI_LIMB_BITS;

    if (limb_shift >= X->n) {
        cvmcrypt_mpi_zeroize(X);
        X->n = 0;
        return true;
    }

    /* Shift limbs down. */
    for (usize i = 0; i < X->n - limb_shift; i++) {
        X->p[i] = X->p[i + limb_shift];
    }
    memset(X->p + X->n - limb_shift, 0, limb_shift * sizeof(mpi_uint));
    X->n -= limb_shift;

    if (bit_shift > 0) {
        for (usize i = 0; i < X->n; i++) {
            X->p[i] >>= bit_shift;
            if (i + 1 < X->n) {
                X->p[i] |= X->p[i + 1] << (MPI_LIMB_BITS - bit_shift);
            }
        }
    }
    cvmcrypt_mpi_shrink(X);
    return true;
}
