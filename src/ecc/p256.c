/*
 * src/ecc/p256.c
 *
 * NIST P-256 ECDSA verification. Jacobian coordinates, double-and-add
 * scalar multiplication. Field arithmetic delegates to cvmcrypt bignum
 * with generic mod (fast reduction is a future optimization).
 *
 * References: SEC 2 (curve parameters), FIPS 186-4 (verify procedure),
 * Explicit-Formulas Database (dbl-2009-l, add-2007-bl).
 */

#include "ecc/p256.h"

#include "asn1/der.h"
#include "base/mem.h"
#include "base/secure.h"

/* ------------------------------------------------------------------ */
/* curve constants (SEC 2, verified against FIPS 186-4)                  */
/* ------------------------------------------------------------------ */

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static u8 const P256_P[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Gx */
static u8 const P256_GX[32] = {
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
    0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
    0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
};

/* Gy */
static u8 const P256_GY[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
    0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
    0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

/* n (group order) */
static u8 const P256_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
    0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

/* ------------------------------------------------------------------ */
/* field helpers                                                        */
/* ------------------------------------------------------------------ */

/* r = (a * b) mod p — allocates temporaries internally */
static bool fp_mul(CvmMpi* r, CvmMpi const* a, CvmMpi const* b, CvmMpi const* p) {
    CvmMpi t;
    cvmcrypt_mpi_init(&t);
    if (!cvmcrypt_mpi_mul_mpi(&t, a, b))
        goto fail;
    if (!cvmcrypt_mpi_mod_mpi(r, &t, p))
        goto fail;
    cvmcrypt_mpi_free(&t);
    return true;
fail:
    cvmcrypt_mpi_free(&t);
    return false;
}

/* r = (a + b) mod p */
static bool fp_add(CvmMpi* r, CvmMpi const* a, CvmMpi const* b, CvmMpi const* p) {
    CvmMpi t;
    cvmcrypt_mpi_init(&t);
    if (!cvmcrypt_mpi_add_abs(&t, a, b))
        goto fail;
    if (!cvmcrypt_mpi_mod_mpi(r, &t, p))
        goto fail;
    cvmcrypt_mpi_free(&t);
    return true;
fail:
    cvmcrypt_mpi_free(&t);
    return false;
}

/* r = (a - b) mod p (handles negative intermediate) */
static bool fp_sub(CvmMpi* r, CvmMpi const* a, CvmMpi const* b, CvmMpi const* p) {
    CvmMpi t;
    cvmcrypt_mpi_init(&t);
    /* t = a - b; if negative, add p */
    i32 cmp = cvmcrypt_mpi_cmp_abs(a, b);
    if (cmp >= 0) {
        if (!cvmcrypt_mpi_sub_abs(&t, a, b))
            goto fail;
        if (!cvmcrypt_mpi_mod_mpi(r, &t, p))
            goto fail;
    } else {
        /* a - b = -(b - a); result = p - (b - a) */
        if (!cvmcrypt_mpi_sub_abs(&t, b, a))
            goto fail;
        if (!cvmcrypt_mpi_mod_mpi(&t, &t, p))
            goto fail;
        /* t = (b - a) mod p; result = p - t */
        CvmMpi t2;
        cvmcrypt_mpi_init(&t2);
        if (!cvmcrypt_mpi_sub_abs(&t2, p, &t)) {
            cvmcrypt_mpi_free(&t2);
            goto fail;
        }
        if (!cvmcrypt_mpi_copy_assign(r, &t2)) {
            cvmcrypt_mpi_free(&t2);
            goto fail;
        }
        cvmcrypt_mpi_free(&t2);
    }
    cvmcrypt_mpi_free(&t);
    return true;
fail:
    cvmcrypt_mpi_free(&t);
    return false;
}

/* r = a^2 mod p */
static bool fp_sqr(CvmMpi* r, CvmMpi const* a, CvmMpi const* p) {
    return fp_mul(r, a, a, p);
}

/* ------------------------------------------------------------------ */
/* Jacobian point                                                       */
/* ------------------------------------------------------------------ */

typedef struct JacPoint {
    CvmMpi X, Y, Z;
    bool inf; /* point at infinity */
} JacPoint;

static void jac_init(JacPoint* j) {
    cvmcrypt_mpi_init(&j->X);
    cvmcrypt_mpi_init(&j->Y);
    cvmcrypt_mpi_init(&j->Z);
    j->inf = true;
}

static void jac_free(JacPoint* j) {
    cvmcrypt_mpi_free(&j->X);
    cvmcrypt_mpi_free(&j->Y);
    cvmcrypt_mpi_free(&j->Z);
}

/* Set from affine coordinates. */
static bool jac_set_affine(JacPoint* j, CvmMpi const* x, CvmMpi const* y) {
    if (!cvmcrypt_mpi_copy_assign(&j->X, x))
        return false;
    if (!cvmcrypt_mpi_copy_assign(&j->Y, y))
        return false;
    /* Z = 1 */
    u8 one = 1;
    if (!cvmcrypt_mpi_read_binary(&j->Z, &one, 1))
        return false;
    j->inf = false;
    return true;
}

/* Point doubling (dbl-2009-l from EFD, adapted for a = -3 not used). */
static bool jac_double(JacPoint* r, JacPoint const* a, CvmMpi const* p) {
    if (a->inf) {
        r->inf = true;
        return true;
    }
    if (cvmcrypt_mpi_is_zero(&a->Y)) {
        r->inf = true;
        return true;
    }

    CvmMpi A, B, C, D, E, F, t1, t2;
    cvmcrypt_mpi_init(&A);
    cvmcrypt_mpi_init(&B);
    cvmcrypt_mpi_init(&C);
    cvmcrypt_mpi_init(&D);
    cvmcrypt_mpi_init(&E);
    cvmcrypt_mpi_init(&F);
    cvmcrypt_mpi_init(&t1);
    cvmcrypt_mpi_init(&t2);
    bool ok = false;

    /* A = X^2 */
    if (!fp_sqr(&A, &a->X, p))
        goto done;
    /* B = Y^2 */
    if (!fp_sqr(&B, &a->Y, p))
        goto done;
    /* C = B^2 */
    if (!fp_sqr(&C, &B, p))
        goto done;
    /* D = 2*((X+B)^2 - A - C) */
    if (!fp_add(&t1, &a->X, &B, p))
        goto done; /* t1 = X+B */
    if (!fp_sqr(&t2, &t1, p))
        goto done; /* t2 = (X+B)^2 */
    if (!fp_sub(&t2, &t2, &A, p))
        goto done; /* t2 -= A */
    if (!fp_sub(&t2, &t2, &C, p))
        goto done; /* t2 -= C */
    if (!fp_add(&D, &t2, &t2, p))
        goto done; /* D = 2*t2 */

    /* E = 3*A + a*Z^4. For P-256, a = -3, so a*Z^4 = -3*Z^4.
     * E = 3*(A - Z^4). */
    if (!fp_sqr(&t1, &a->Z, p))
        goto done; /* t1 = Z^2 */
    if (!fp_sqr(&t1, &t1, p))
        goto done; /* t1 = Z^4 */
    if (!fp_sub(&t1, &A, &t1, p))
        goto done; /* t1 = A - Z^4 */
    if (!fp_add(&E, &t1, &t1, p))
        goto done; /* E = 2*(A - Z^4) */
    if (!fp_add(&E, &E, &t1, p))
        goto done; /* E = 3*(A - Z^4) */

    /* F = E^2 */
    if (!fp_sqr(&F, &E, p))
        goto done;

    /* X3 = F - 2*D */
    if (!fp_add(&t1, &D, &D, p))
        goto done; /* t1 = 2*D */
    if (!fp_sub(&r->X, &F, &t1, p))
        goto done;

    /* Y3 = E*(D - X3) - 8*C */
    if (!fp_sub(&t1, &D, &r->X, p))
        goto done; /* t1 = D - X3 */
    if (!fp_mul(&t2, &E, &t1, p))
        goto done; /* t2 = E*(D-X3) */
    if (!fp_add(&t1, &C, &C, p))
        goto done; /* t1 = 2C */
    if (!fp_add(&t1, &t1, &t1, p))
        goto done; /* t1 = 4C */
    if (!fp_add(&t1, &t1, &t1, p))
        goto done; /* t1 = 8C */
    if (!fp_sub(&r->Y, &t2, &t1, p))
        goto done;

    /* Z3 = 2*Y*Z */
    if (!fp_mul(&t1, &a->Y, &a->Z, p))
        goto done; /* t1 = Y*Z */
    if (!fp_add(&r->Z, &t1, &t1, p))
        goto done; /* Z3 = 2*Y*Z */

    r->inf = false;
    ok = true;
done:
    cvmcrypt_mpi_free(&A);
    cvmcrypt_mpi_free(&B);
    cvmcrypt_mpi_free(&C);
    cvmcrypt_mpi_free(&D);
    cvmcrypt_mpi_free(&E);
    cvmcrypt_mpi_free(&F);
    cvmcrypt_mpi_free(&t1);
    cvmcrypt_mpi_free(&t2);
    return ok;
}

/* Mixed addition: r = a (Jacobian) + b (affine). add-2007-bl from EFD. */
static bool jac_add_affine(JacPoint* r, JacPoint const* a, CvmMpi const* bx,
                           CvmMpi const* by, CvmMpi const* p) {
    if (a->inf) {
        /* r = b */
        if (!cvmcrypt_mpi_copy_assign(&r->X, bx))
            return false;
        if (!cvmcrypt_mpi_copy_assign(&r->Y, by))
            return false;
        u8 one = 1;
        if (!cvmcrypt_mpi_read_binary(&r->Z, &one, 1))
            return false;
        r->inf = false;
        return true;
    }

    CvmMpi Z1Z1, U2, S2, H, HH, I, J, rr, V, t1, t2;
    cvmcrypt_mpi_init(&Z1Z1);
    cvmcrypt_mpi_init(&U2);
    cvmcrypt_mpi_init(&S2);
    cvmcrypt_mpi_init(&H);
    cvmcrypt_mpi_init(&HH);
    cvmcrypt_mpi_init(&I);
    cvmcrypt_mpi_init(&J);
    cvmcrypt_mpi_init(&rr);
    cvmcrypt_mpi_init(&V);
    cvmcrypt_mpi_init(&t1);
    cvmcrypt_mpi_init(&t2);
    bool ok = false;

    /* Z1Z1 = Z1^2 */
    if (!fp_sqr(&Z1Z1, &a->Z, p))
        goto done;

    /* U2 = X2 * Z1Z1 */
    if (!fp_mul(&U2, bx, &Z1Z1, p))
        goto done;

    /* S2 = Y2 * Z1 * Z1Z1 */
    if (!fp_mul(&t1, by, &a->Z, p))
        goto done;
    if (!fp_mul(&S2, &t1, &Z1Z1, p))
        goto done;

    /* H = U2 - X1 */
    if (!fp_sub(&H, &U2, &a->X, p))
        goto done;

    /* HH = H^2 */
    if (!fp_sqr(&HH, &H, p))
        goto done;

    /* I = 4*HH */
    if (!fp_add(&I, &HH, &HH, p))
        goto done;
    if (!fp_add(&I, &I, &I, p))
        goto done;

    /* J = H*I */
    if (!fp_mul(&J, &H, &I, p))
        goto done;

    /* r = 2*(S2 - Y1) */
    if (!fp_sub(&rr, &S2, &a->Y, p))
        goto done;
    if (!fp_add(&rr, &rr, &rr, p))
        goto done;

    /* V = X1 * I */
    if (!fp_mul(&V, &a->X, &I, p))
        goto done;

    /* X3 = r^2 - J - 2*V */
    if (!fp_sqr(&r->X, &rr, p))
        goto done;
    if (!fp_sub(&r->X, &r->X, &J, p))
        goto done;
    if (!fp_add(&t1, &V, &V, p))
        goto done;
    if (!fp_sub(&r->X, &r->X, &t1, p))
        goto done;

    /* Y3 = r*(V - X3) - 2*Y1*J */
    if (!fp_sub(&t1, &V, &r->X, p))
        goto done;
    if (!fp_mul(&t2, &rr, &t1, p))
        goto done;
    if (!fp_mul(&t1, &a->Y, &J, p))
        goto done;
    if (!fp_add(&t1, &t1, &t1, p))
        goto done;
    if (!fp_sub(&r->Y, &t2, &t1, p))
        goto done;

    /* Z3 = (Z1 + H)^2 - Z1Z1 - HH */
    if (!fp_add(&t1, &a->Z, &H, p))
        goto done;
    if (!fp_sqr(&r->Z, &t1, p))
        goto done;
    if (!fp_sub(&r->Z, &r->Z, &Z1Z1, p))
        goto done;
    if (!fp_sub(&r->Z, &r->Z, &HH, p))
        goto done;

    r->inf = false;
    ok = true;
done:
    cvmcrypt_mpi_free(&Z1Z1);
    cvmcrypt_mpi_free(&U2);
    cvmcrypt_mpi_free(&S2);
    cvmcrypt_mpi_free(&H);
    cvmcrypt_mpi_free(&HH);
    cvmcrypt_mpi_free(&I);
    cvmcrypt_mpi_free(&J);
    cvmcrypt_mpi_free(&rr);
    cvmcrypt_mpi_free(&V);
    cvmcrypt_mpi_free(&t1);
    cvmcrypt_mpi_free(&t2);
    return ok;
}

/* Scalar multiply: r = k * G (G = affine generator). Double-and-add (MSB first). */
static bool jac_scalar_mult_G(JacPoint* r, CvmMpi const* k, CvmMpi const* p,
                              CvmMpi const* gx, CvmMpi const* gy) {
    JacPoint acc;
    jac_init(&acc); /* acc = infinity */

    usize bits = cvmcrypt_mpi_bitlen(k);
    if (bits == 0) {
        r->inf = true;
        return true;
    }

    for (usize i = bits; i > 0; i--) {
        /* Double */
        if (!acc.inf) {
            JacPoint dbl;
            jac_init(&dbl);
            if (!jac_double(&dbl, &acc, p)) {
                jac_free(&dbl);
                jac_free(&acc);
                return false;
            }
            jac_free(&acc);
            acc = dbl;
        }
        /* Add G if bit is set */
        if (cvmcrypt_mpi_get_bit(k, i - 1)) {
            JacPoint sum;
            jac_init(&sum);
            if (!jac_add_affine(&sum, &acc, gx, gy, p)) {
                jac_free(&sum);
                jac_free(&acc);
                return false;
            }
            jac_free(&acc);
            acc = sum;
        }
    }

    /* Move result to r */
    jac_free(r);
    *r = acc; /* transfer ownership */
    return true;
}

/* Scalar multiply: r = k * Q (Q = affine point). */
static bool jac_scalar_mult_affine(JacPoint* r, CvmMpi const* k, CvmMpi const* qx,
                                   CvmMpi const* qy, CvmMpi const* p) {
    JacPoint acc;
    jac_init(&acc);

    usize bits = cvmcrypt_mpi_bitlen(k);
    if (bits == 0) {
        r->inf = true;
        return true;
    }

    for (usize i = bits; i > 0; i--) {
        if (!acc.inf) {
            JacPoint dbl;
            jac_init(&dbl);
            if (!jac_double(&dbl, &acc, p)) {
                jac_free(&dbl);
                jac_free(&acc);
                return false;
            }
            jac_free(&acc);
            acc = dbl;
        }
        if (cvmcrypt_mpi_get_bit(k, i - 1)) {
            JacPoint sum;
            jac_init(&sum);
            if (!jac_add_affine(&sum, &acc, qx, qy, p)) {
                jac_free(&sum);
                jac_free(&acc);
                return false;
            }
            jac_free(&acc);
            acc = sum;
        }
    }

    jac_free(r);
    *r = acc;
    return true;
}

/* Convert Jacobian to affine: x = X/Z^2, y = Y/Z^3. */
static bool jac_to_affine(CvmMpi* x, CvmMpi* y, JacPoint const* j, CvmMpi const* p) {
    if (j->inf)
        return false;

    CvmMpi zinv, zinv2, zinv3;
    cvmcrypt_mpi_init(&zinv);
    cvmcrypt_mpi_init(&zinv2);
    cvmcrypt_mpi_init(&zinv3);
    bool ok = false;

    /* zinv = Z^(-1) mod p */
    if (!cvmcrypt_mpi_inv_mod(&zinv, &j->Z, p))
        goto done;
    /* zinv2 = zinv^2 */
    if (!fp_sqr(&zinv2, &zinv, p))
        goto done;
    /* zinv3 = zinv2 * zinv */
    if (!fp_mul(&zinv3, &zinv2, &zinv, p))
        goto done;
    /* x = X * zinv2 */
    if (!fp_mul(x, &j->X, &zinv2, p))
        goto done;
    /* y = Y * zinv3 */
    if (!fp_mul(y, &j->Y, &zinv3, p))
        goto done;

    ok = true;
done:
    cvmcrypt_mpi_free(&zinv);
    cvmcrypt_mpi_free(&zinv2);
    cvmcrypt_mpi_free(&zinv3);
    return ok;
}

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

void cvmcrypt_ec_init(CvmEcPoint* pt) {
    cvmcrypt_mpi_init(&pt->x);
    cvmcrypt_mpi_init(&pt->y);
}

void cvmcrypt_ec_free(CvmEcPoint* pt) {
    cvmcrypt_mpi_free(&pt->x);
    cvmcrypt_mpi_free(&pt->y);
}

EcStatus cvmcrypt_ec_import_point(CvmEcPoint* pt, u8 const* buf, usize buflen) {
    /* Expect uncompressed: 04 || X(32) || Y(32) = 65 bytes */
    if (buflen != 65 || buf[0] != 0x04)
        return EC_ERR_PARSE;
    if (!cvmcrypt_mpi_read_binary(&pt->x, buf + 1, 32))
        return EC_ERR_PARSE;
    if (!cvmcrypt_mpi_read_binary(&pt->y, buf + 33, 32))
        return EC_ERR_PARSE;
    return EC_OK;
}

bool cvmcrypt_ecdsa_verify(CvmEcPoint const* q, u8 const* hash, usize hash_len,
                           u8 const* r_buf, usize r_len, u8 const* s_buf, usize s_len) {
    CvmMpi p, n, gx, gy, r, s, e, w, u1, u2, v;
    cvmcrypt_mpi_init(&p);
    cvmcrypt_mpi_init(&n);
    cvmcrypt_mpi_init(&gx);
    cvmcrypt_mpi_init(&gy);
    cvmcrypt_mpi_init(&r);
    cvmcrypt_mpi_init(&s);
    cvmcrypt_mpi_init(&e);
    cvmcrypt_mpi_init(&w);
    cvmcrypt_mpi_init(&u1);
    cvmcrypt_mpi_init(&u2);
    cvmcrypt_mpi_init(&v);
    bool ok = false;

    /* Load curve constants. */
    if (!cvmcrypt_mpi_read_binary(&p, P256_P, 32))
        goto done;
    if (!cvmcrypt_mpi_read_binary(&n, P256_N, 32))
        goto done;
    if (!cvmcrypt_mpi_read_binary(&gx, P256_GX, 32))
        goto done;
    if (!cvmcrypt_mpi_read_binary(&gy, P256_GY, 32))
        goto done;

    /* Parse r, s. */
    if (!cvmcrypt_mpi_read_binary(&r, r_buf, r_len))
        goto done;
    if (!cvmcrypt_mpi_read_binary(&s, s_buf, s_len))
        goto done;

    /* Check 1 ≤ r < n and 1 ≤ s < n. */
    if (cvmcrypt_mpi_cmp_abs(&r, &n) >= 0)
        goto done; /* r >= n → reject */
    if (cvmcrypt_mpi_is_zero(&r))
        goto done;
    if (cvmcrypt_mpi_cmp_abs(&s, &n) >= 0)
        goto done;
    if (cvmcrypt_mpi_is_zero(&s))
        goto done;

    /* e = hash mod n (truncate to leftmost n.bitlen bits if longer). */
    {
        CvmMpi h;
        cvmcrypt_mpi_init(&h);
        if (!cvmcrypt_mpi_read_binary(&h, hash, hash_len)) {
            cvmcrypt_mpi_free(&h);
            goto done;
        }
        usize nbits = cvmcrypt_mpi_bitlen(&n);
        usize hbits = cvmcrypt_mpi_bitlen(&h);
        if (hbits > nbits) {
            /* Shift right by (hbits - nbits). */
            if (!cvmcrypt_mpi_shift_r(&h, hbits - nbits)) {
                cvmcrypt_mpi_free(&h);
                goto done;
            }
        }
        if (!cvmcrypt_mpi_mod_mpi(&e, &h, &n)) {
            cvmcrypt_mpi_free(&h);
            goto done;
        }
        cvmcrypt_mpi_free(&h);
    }

    /* w = s^(-1) mod n */
    if (!cvmcrypt_mpi_inv_mod(&w, &s, &n))
        goto done;

    /* u1 = e * w mod n */
    {
        CvmMpi t;
        cvmcrypt_mpi_init(&t);
        if (!cvmcrypt_mpi_mul_mpi(&t, &e, &w)) {
            cvmcrypt_mpi_free(&t);
            goto done;
        }
        if (!cvmcrypt_mpi_mod_mpi(&u1, &t, &n)) {
            cvmcrypt_mpi_free(&t);
            goto done;
        }
        cvmcrypt_mpi_free(&t);
    }
    /* u2 = r * w mod n */
    {
        CvmMpi t;
        cvmcrypt_mpi_init(&t);
        if (!cvmcrypt_mpi_mul_mpi(&t, &r, &w)) {
            cvmcrypt_mpi_free(&t);
            goto done;
        }
        if (!cvmcrypt_mpi_mod_mpi(&u2, &t, &n)) {
            cvmcrypt_mpi_free(&t);
            goto done;
        }
        cvmcrypt_mpi_free(&t);
    }

    /* R1 = u1 * G */
    JacPoint r1, r2;
    jac_init(&r1);
    jac_init(&r2);
    {
        bool m1 = jac_scalar_mult_G(&r1, &u1, &p, &gx, &gy);
        if (!m1) {
            jac_free(&r1);
            jac_free(&r2);
            goto done;
        }
    }
    /* R2 = u2 * Q */
    {
        bool m2 = jac_scalar_mult_affine(&r2, &u2, &q->x, &q->y, &p);
        if (!m2) {
            jac_free(&r1);
            jac_free(&r2);
            goto done;
        }
    }

    /* R = R1 + R2 (if either is infinity, use the other). */
    JacPoint result;
    jac_init(&result);
    {
        /* Convert r2 to affine, then use mixed add. */
        CvmMpi rx, ry;
        cvmcrypt_mpi_init(&rx);
        cvmcrypt_mpi_init(&ry);
        if (r1.inf && r2.inf) {
            /* Both infinity → invalid signature. */
            cvmcrypt_mpi_free(&rx);
            cvmcrypt_mpi_free(&ry);
            jac_free(&r1);
            jac_free(&r2);
            jac_free(&result);
            goto done;
        } else if (r1.inf) {
            result = r2;   /* transfer */
            r2.inf = true; /* mark as transferred (won't be freed again) */
            /* Actually this is tricky. Let me just compute properly. */
            /* Reset: */
            result = (JacPoint){0};
            jac_init(&result);
            if (!jac_to_affine(&rx, &ry, &r2, &p)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
            /* result = affine point (rx, ry) as Jacobian with Z=1 */
            if (!jac_set_affine(&result, &rx, &ry)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
        } else if (r2.inf) {
            if (!jac_to_affine(&rx, &ry, &r1, &p)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
            if (!jac_set_affine(&result, &rx, &ry)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
        } else {
            /* Neither infinity: result = r1 + r2 */
            if (!jac_to_affine(&rx, &ry, &r2, &p)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
            if (!jac_add_affine(&result, &r1, &rx, &ry, &p)) {
                cvmcrypt_mpi_free(&rx);
                cvmcrypt_mpi_free(&ry);
                jac_free(&r1);
                jac_free(&r2);
                jac_free(&result);
                goto done;
            }
        }
        cvmcrypt_mpi_free(&rx);
        cvmcrypt_mpi_free(&ry);
    }
    jac_free(&r1);
    jac_free(&r2);

    /* v = result.x mod n */
    if (result.inf) {
        jac_free(&result);
        goto done; /* point at infinity → invalid */
    }
    {
        CvmMpi rx, ry;
        cvmcrypt_mpi_init(&rx);
        cvmcrypt_mpi_init(&ry);
        bool conv = jac_to_affine(&rx, &ry, &result, &p);
        jac_free(&result);
        if (!conv) {
            cvmcrypt_mpi_free(&rx);
            cvmcrypt_mpi_free(&ry);
            goto done;
        }
        if (!cvmcrypt_mpi_mod_mpi(&v, &rx, &n)) {
            cvmcrypt_mpi_free(&rx);
            cvmcrypt_mpi_free(&ry);
            goto done;
        }
        cvmcrypt_mpi_free(&rx);
        cvmcrypt_mpi_free(&ry);
    }

    /* Valid iff v == r */
    ok = cvmcrypt_mpi_cmp_abs(&v, &r) == 0;

done:
    cvmcrypt_mpi_free(&p);
    cvmcrypt_mpi_free(&n);
    cvmcrypt_mpi_free(&gx);
    cvmcrypt_mpi_free(&gy);
    cvmcrypt_mpi_free(&r);
    cvmcrypt_mpi_free(&s);
    cvmcrypt_mpi_free(&e);
    cvmcrypt_mpi_free(&w);
    cvmcrypt_mpi_free(&u1);
    cvmcrypt_mpi_free(&u2);
    cvmcrypt_mpi_free(&v);
    return ok;
}

EcStatus cvmcrypt_ec_import_spki(CvmEcPoint* pt, u8 const* der, usize derlen) {
    /* SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey } */
    DerCursor c = der_cursor_init(der, derlen);
    DerCursor spki, algo;
    u8 const* oid;
    usize oid_len;

    if (der_read_sequence(&c, &spki) != DER_OK)
        return EC_ERR_PARSE;

    /* AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY } */
    if (der_read_sequence(&spki, &algo) != DER_OK)
        return EC_ERR_PARSE;
    if (der_read_oid(&algo, &oid, &oid_len) != DER_OK)
        return EC_ERR_PARSE;

    /* Check id-ecPublicKey: 1.2.840.10045.2.1 */
    static u8 const EC_OID[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    if (oid_len != sizeof(EC_OID) || memcmp(oid, EC_OID, sizeof(EC_OID)) != 0)
        return EC_ERR_PARSE;

    /* parameters: namedCurve OID. P-256 = 1.2.840.10045.3.1.1 */
    if (der_read_oid(&algo, &oid, &oid_len) != DER_OK)
        return EC_ERR_PARSE;
    static u8 const P256_OID[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    /* Note: P-256's OID is 1.2.840.10045.3.1.7, encoded as 2a 86 48 ce 3d 03 01 07 */
    if (oid_len != sizeof(P256_OID) || memcmp(oid, P256_OID, sizeof(P256_OID)) != 0)
        return EC_ERR_PARSE;

    /* subjectPublicKey BIT STRING */
    u8 const* pk;
    usize pk_len;
    u8 unused;
    if (der_read_bit_string(&spki, &pk, &pk_len, &unused) != DER_OK)
        return EC_ERR_PARSE;
    if (unused != 0)
        return EC_ERR_PARSE;

    /* Point: 04 || X || Y */
    return cvmcrypt_ec_import_point(pt, pk, pk_len);
}
