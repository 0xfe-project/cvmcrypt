/*
 * src/math/bignum.h
 *
 * Multi-precision integer (bignum) for RSA/ECC/x509.
 *
 * Carried over from mbedtls 3.6.7's bignum.h, bignum_core.h,
 * bignum_core.c, bignum_mod.h, bignum_mod.c, bignum_mod_raw.h,
 * bignum_mod_raw.c, bignum.c (Apache-2.0), adapted to cvm
 * conventions.
 *
 * Representation: little-endian array of u64 limbs. The mpi struct
 * holds a pointer to the limb array and the number of limbs in use.
 * Sign is stored separately (MBEDTLS-style).
 */

#ifndef CVMCRYPT_MATH_BIGNUM_H
#define CVMCRYPT_MATH_BIGNUM_H

#include "base/types.h"

typedef u64 mpi_uint; /* one limb: 64 bits */
typedef i64 mpi_sint; /* signed limb for intermediate results */

#define MPI_LIMB_BITS 64
#define MPI_LIMB_BYTES 8
#define MPI_LIMB_MAX UINT64_MAX

/* Maximum number of limbs for MPI operations. */
#define MPI_MAX_LIMBS (4096 / MPI_LIMB_BITS)

/*
 * The multi-precision integer. s represents the sign (1 = negative,
 * 0 = non-negative). n is the number of limbs in use. p is the limb
 * array, allocated with the allocator set at init time (for now,
 * rt_mem_alloc / rt_mem_free).
 */
typedef struct CvmMpi {
    i32 s;       /* sign: -1 or 1 (we use ±1, not 0/1) */
    usize n;     /* number of limbs in use */
    mpi_uint* p; /* limb array (little-endian) */
} CvmMpi;

/* Initialize / free. */
void cvmcrypt_mpi_init(CvmMpi* X);
void cvmcrypt_mpi_free(CvmMpi* X);

/* Grow to at least nblimbs. */
bool cvmcrypt_mpi_grow(CvmMpi* X, usize nblimbs);
/* Resize to exactly nblimbs, keeping value. */
bool cvmcrypt_mpi_resize(CvmMpi* X, usize nblimbs);
/* Shrink to minimal representation. */
void cvmcrypt_mpi_shrink(CvmMpi* X);

/* Copy. */
bool cvmcrypt_mpi_copy(CvmMpi* X, CvmMpi const* A);
/* Safe copy (handles aliasing). */
bool cvmcrypt_mpi_copy_assign(CvmMpi* X, CvmMpi const* A);

/* Swap (constant-time if swap is 0 or 1). */
void cvmcrypt_mpi_swap(CvmMpi* X, CvmMpi* Y);

/* Comparison. Returns -1, 0, or 1. */
i32 cvmcrypt_mpi_cmp_abs(CvmMpi const* X, CvmMpi const* Y);
i32 cvmcrypt_mpi_cmp_mpi(CvmMpi const* X, CvmMpi const* Y);

/* Bit operations. */
usize cvmcrypt_mpi_bitlen(CvmMpi const* X);
usize cvmcrypt_mpi_lsb(CvmMpi const* X);
u64 cvmcrypt_mpi_get_bit(CvmMpi const* X, usize pos);

/* Arithmetic. */
bool cvmcrypt_mpi_add_abs(CvmMpi* X, CvmMpi const* A, CvmMpi const* B);
bool cvmcrypt_mpi_sub_abs(CvmMpi* X, CvmMpi const* A, CvmMpi const* B);
bool cvmcrypt_mpi_mul_mpi(CvmMpi* X, CvmMpi const* A, CvmMpi const* B);
bool cvmcrypt_mpi_div_mpi(CvmMpi* Q, CvmMpi* R, CvmMpi const* A, CvmMpi const* B);
bool cvmcrypt_mpi_mod_mpi(CvmMpi* R, CvmMpi const* A, CvmMpi const* N);
bool cvmcrypt_mpi_inv_mod(CvmMpi* X, CvmMpi const* A, CvmMpi const* N);
bool cvmcrypt_mpi_exp_mod(CvmMpi* X, CvmMpi const* A, CvmMpi const* E, CvmMpi const* N);

/* Montgomery multiplication: X = A * B * R^-1 mod N. */
bool cvmcrypt_mpi_montmul(CvmMpi* X, CvmMpi const* A, CvmMpi const* B, CvmMpi const* N,
                          mpi_uint mm);

/* Import/export. */
bool cvmcrypt_mpi_read_binary(CvmMpi* X, u8 const* buf, usize buflen);
bool cvmcrypt_mpi_write_binary(CvmMpi const* X, u8* buf, usize buflen);
bool cvmcrypt_mpi_read_string_le(CvmMpi* X, u8 const* buf, usize buflen);

/* Shift. */
bool cvmcrypt_mpi_shift_l(CvmMpi* X, usize count);
bool cvmcrypt_mpi_shift_r(CvmMpi* X, usize count);

/* Utility. */
bool cvmcrypt_mpi_is_zero(CvmMpi const* X);
void cvmcrypt_mpi_zeroize(CvmMpi* X);

#endif /* CVMCRYPT_MATH_BIGNUM_H */
