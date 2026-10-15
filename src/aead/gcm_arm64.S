/*
 * src/aead/gcm_arm64.S — AES-GCM fused encrypt kernel (arm64)
 *
 * 8 blocks (128 bytes) per iteration. All AES first (max pipeline),
 * then GHASH with reflected domain. Table entries loaded per block
 * from L1 (hot).
 *
 * Register map:
 *   v0-v7   : AES state → ciphertext → GHASH data
 *   v12     : POLY
 *   v13     : INC (counter increment)
 *   v14     : CTR (running counter, native u32)
 *   v15     : ACC0 running (reflected accumulator)
 *   v16     : ACC1 (low)
 *   v17     : ACCM (mid)
 *   v18     : ZERO
 *   v19-v28 : AES round keys rk0-rk9
 *   v29     : KLAST (rk10)
 *   v30-v31 : temps
 *   Table entries loaded per block into v8-v9 (from L1).
 *   x22 = table pointer (entries 0-7, reset per iteration).
 */

.globl _cvmcrypt_gcm_enc_kernel
.private_extern _cvmcrypt_gcm_enc_kernel
.align 5
_cvmcrypt_gcm_enc_kernel:
    /* x0=rk, x1=in, x2=out, x3=nbytes, x4=tbl(all 8), x5=ctr, x6=xrefl */
    stp    d8, d9,   [sp, #-96]!
    stp    d10, d11, [sp, #16]
    stp    d12, d13, [sp, #32]
    stp    d14, d15, [sp, #48]
    stp    x19, x20, [sp, #64]
    stp    x21, x22, [sp, #80]

    mov    x19, x1                          /* x19 = in */
    mov    x20, x2                          /* x20 = out */
    add    x21, x1, x3                      /* x21 = end */
    mov    x22, x4                          /* x22 = table base */

    /* Round keys + VREV32 for AESE byte order. */
    ld1    {v19.16b, v20.16b, v21.16b, v22.16b}, [x0], #64
    rev32  v19.16b, v19.16b
    rev32  v20.16b, v20.16b
    rev32  v21.16b, v21.16b
    rev32  v22.16b, v22.16b
    ld1    {v23.16b, v24.16b, v25.16b, v26.16b}, [x0], #64
    rev32  v23.16b, v23.16b
    rev32  v24.16b, v24.16b
    rev32  v25.16b, v25.16b
    rev32  v26.16b, v26.16b
    ld1    {v27.16b, v28.16b, v29.16b}, [x0]
    rev32  v27.16b, v27.16b
    rev32  v28.16b, v28.16b
    rev32  v29.16b, v29.16b

    /* POLY = {0xC2<<56, 1}, INC = {0,0,0,1}, ZERO. */
    movi   v12.16b, #0
    movz   x9, #0xc2
    lsl    x9, x9, #56
    ins    v12.d[0], x9
    mov    x9, #1
    ins    v12.d[1], x9
    movi   v13.16b, #0
    ins    v13.s[3], w9
    movi   v18.16b, #0

    /* CTR. */
    ld1    {v14.16b}, [x5]
    rev32  v14.16b, v14.16b

    /* Running accumulator. */
    ld1    {v15.16b}, [x6]

1:  /* main_loop */
    cmp    x19, x21
    b.ge   3f

    /* Counter chain: B0=CTR, B1..B7 = +INC each, CTR=B7+INC. */
    mov    v0.16b, v14.16b
    add    v1.4s, v0.4s, v13.4s
    rev32  v0.16b, v0.16b
    add    v2.4s, v1.4s, v13.4s
    rev32  v1.16b, v1.16b
    add    v3.4s, v2.4s, v13.4s
    rev32  v2.16b, v2.16b
    add    v4.4s, v3.4s, v13.4s
    rev32  v3.16b, v3.16b
    add    v5.4s, v4.4s, v13.4s
    rev32  v4.16b, v4.16b
    add    v6.4s, v5.4s, v13.4s
    rev32  v5.16b, v5.16b
    add    v7.4s, v6.4s, v13.4s
    rev32  v6.16b, v6.16b
    add    v14.4s, v7.4s, v13.4s
    rev32  v7.16b, v7.16b

    /* AES rounds 0-8 (K0-K8 = v19-v27), 8 blocks interleaved. */
    aese   v0.16b, v19.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v19.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v19.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v19.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v19.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v19.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v19.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v19.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v20.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v20.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v20.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v20.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v20.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v20.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v20.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v20.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v21.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v21.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v21.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v21.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v21.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v21.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v21.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v21.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v22.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v22.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v22.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v22.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v22.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v22.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v22.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v22.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v23.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v23.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v23.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v23.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v23.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v23.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v23.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v23.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v24.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v24.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v24.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v24.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v24.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v24.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v24.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v24.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v25.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v25.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v25.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v25.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v25.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v25.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v25.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v25.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v26.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v26.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v26.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v26.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v26.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v26.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v26.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v26.16b
    aesmc  v7.16b, v7.16b
    aese   v0.16b, v27.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v27.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v27.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v27.16b
    aesmc  v3.16b, v3.16b
    aese   v4.16b, v27.16b
    aesmc  v4.16b, v4.16b
    aese   v5.16b, v27.16b
    aesmc  v5.16b, v5.16b
    aese   v6.16b, v27.16b
    aesmc  v6.16b, v6.16b
    aese   v7.16b, v27.16b
    aesmc  v7.16b, v7.16b

    /* Final round: AESE(K9=v28) + EOR(KLAST=v29). */
    aese   v0.16b, v28.16b
    aese   v1.16b, v28.16b
    aese   v2.16b, v28.16b
    aese   v3.16b, v28.16b
    aese   v4.16b, v28.16b
    aese   v5.16b, v28.16b
    aese   v6.16b, v28.16b
    aese   v7.16b, v28.16b
    eor    v0.16b, v0.16b, v29.16b
    eor    v1.16b, v1.16b, v29.16b
    eor    v2.16b, v2.16b, v29.16b
    eor    v3.16b, v3.16b, v29.16b
    eor    v4.16b, v4.16b, v29.16b
    eor    v5.16b, v5.16b, v29.16b
    eor    v6.16b, v6.16b, v29.16b
    eor    v7.16b, v7.16b, v29.16b

    /* Load plaintext, XOR, store ciphertext. 4 × 32B. */
    ld1    {v30.16b, v31.16b}, [x19], #32
    eor    v0.16b, v0.16b, v30.16b
    eor    v1.16b, v1.16b, v31.16b
    st1    {v0.16b, v1.16b}, [x20], #32
    ld1    {v30.16b, v31.16b}, [x19], #32
    eor    v2.16b, v2.16b, v30.16b
    eor    v3.16b, v3.16b, v31.16b
    st1    {v2.16b, v3.16b}, [x20], #32
    ld1    {v30.16b, v31.16b}, [x19], #32
    eor    v4.16b, v4.16b, v30.16b
    eor    v5.16b, v5.16b, v31.16b
    st1    {v4.16b, v5.16b}, [x20], #32
    ld1    {v30.16b, v31.16b}, [x19], #32
    eor    v6.16b, v6.16b, v30.16b
    eor    v7.16b, v7.16b, v31.16b
    st1    {v6.16b, v7.16b}, [x20], #32

    /* Convert to reflected domain. */
    rev64  v0.16b, v0.16b
    rev64  v1.16b, v1.16b
    rev64  v2.16b, v2.16b
    rev64  v3.16b, v3.16b
    rev64  v4.16b, v4.16b
    rev64  v5.16b, v5.16b
    rev64  v6.16b, v6.16b
    rev64  v7.16b, v7.16b

    /* ---- GHASH 8 blocks ---- */
    mov    x22, x4                          /* reset table ptr */
    movi   v16.16b, #0                      /* ACC1 = 0 */
    movi   v17.16b, #0                      /* ACCM = 0 */

    /* Block 0: XOR with ACC, mul by entry[0] (highest power). */
    eor    v0.16b, v0.16b, v15.16b
    ext    v30.16b, v0.16b, v0.16b, #8
    eor    v30.16b, v30.16b, v0.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v16.1q, v8.1d, v0.1d
    pmull2 v15.1q, v8.2d, v0.2d
    pmull  v17.1q, v9.1d, v30.1d

    /* Blocks 1-7: mulRound. */
    ext    v30.16b, v1.16b, v1.16b, #8
    eor    v30.16b, v30.16b, v1.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v1.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v1.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v2.16b, v2.16b, #8
    eor    v30.16b, v30.16b, v2.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v2.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v2.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v3.16b, v3.16b, #8
    eor    v30.16b, v30.16b, v3.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v3.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v3.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v4.16b, v4.16b, #8
    eor    v30.16b, v30.16b, v4.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v4.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v4.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v5.16b, v5.16b, #8
    eor    v30.16b, v30.16b, v5.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v5.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v5.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v6.16b, v6.16b, #8
    eor    v30.16b, v30.16b, v6.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v6.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v6.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    ext    v30.16b, v7.16b, v7.16b, #8
    eor    v30.16b, v30.16b, v7.16b
    ld1    {v8.16b, v9.16b}, [x22], #32
    pmull  v31.1q, v8.1d, v7.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v7.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b

    /* ---- reduce (Go's exact sequence) ---- */
    eor    v17.16b, v17.16b, v15.16b
    eor    v17.16b, v17.16b, v16.16b
    ext    v30.16b, v17.16b, v18.16b, #8
    ext    v17.16b, v18.16b, v17.16b, #8
    eor    v15.16b, v15.16b, v17.16b
    eor    v16.16b, v16.16b, v30.16b
    pmull  v30.1q, v15.1d, v12.1d
    ext    v15.16b, v15.16b, v15.16b, #8
    eor    v15.16b, v15.16b, v30.16b
    pmull  v30.1q, v15.1d, v12.1d
    eor    v16.16b, v16.16b, v30.16b
    ext    v16.16b, v16.16b, v16.16b, #8
    eor    v15.16b, v15.16b, v16.16b

    b      1b

3:  /* done */
    rev32  v14.16b, v14.16b
    st1    {v14.16b}, [x5]
    st1    {v15.16b}, [x6]

    ldp    x19, x20, [sp, #64]
    ldp    x21, x22, [sp, #80]
    ldp    d8, d9,   [sp]
    ldp    d10, d11, [sp, #16]
    ldp    d12, d13, [sp, #32]
    ldp    d14, d15, [sp, #48]
    add    sp, sp, #96
    ret
