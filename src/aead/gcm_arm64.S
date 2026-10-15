/*
 * src/aead/gcm_arm64.S — AES-GCM fused kernel with software pipelining
 *
 * Pattern from ring's aesv8-gcm-armv8-ios64.S:
 *   AES(next 4 blocks) interleaved at instruction level with
 *   GHASH(previous 4 blocks). AESE and PMULL use different execution
 *   units, enabling true parallelism.
 *
 * Pipeline structure:
 *   PROLOGUE: AES first 4 blocks (no GHASH to interleave)
 *   MAIN LOOP: AES(current 4) ∥ GHASH(previous 4), interleaved
 *   EPILOGUE: GHASH last 4 blocks (no more AES)
 *
 * Register map:
 *   v0-v3   : AES state (current 4 blocks being encrypted)
 *   v4-v7   : GHASH data (previous 4 blocks, reflected domain)
 *   v8-v9   : GHASH table entry pair (loaded from L1 per block)
 *   v10-v11 : memory temps (ld1/st1)
 *   v12     : POLY
 *   v13     : INC
 *   v14     : CTR
 *   v15     : ACC0 (running accumulator)
 *   v16     : ACC1
 *   v17     : ACCM
 *   v18     : ZERO
 *   v19-v28 : AES round keys rk0-rk9
 *   v29     : KLAST
 *   v30-v31 : temps
 */

.globl _cvmcrypt_gcm_enc_kernel
.private_extern _cvmcrypt_gcm_enc_kernel
.align 5
_cvmcrypt_gcm_enc_kernel:
    stp    d8, d9,   [sp, #-96]!
    stp    d10, d11, [sp, #16]
    stp    d12, d13, [sp, #32]
    stp    d14, d15, [sp, #48]
    stp    x19, x20, [sp, #64]
    stp    x21, x22, [sp, #80]

    mov    x19, x1                          /* in */
    mov    x20, x2                          /* out */
    add    x21, x1, x3                      /* end */
    mov    x22, x4                          /* table base (entries 4-7) */

    /* Round keys + VREV32 */
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

    /* POLY, INC, ZERO */
    movi   v12.16b, #0
    movz   x9, #0xc2
    lsl    x9, x9, #56
    ins    v12.d[0], x9
    mov    x9, #1
    ins    v12.d[1], x9
    movi   v13.16b, #0
    ins    v13.s[3], w9
    movi   v18.16b, #0

    /* CTR */
    ld1    {v14.16b}, [x5]
    rev32  v14.16b, v14.16b

    /* Running accumulator */
    ld1    {v15.16b}, [x6]

/* ==== PROLOGUE: encrypt first 4 blocks into v4-v7 ==== */
    cmp    x19, x21
    b.ge   90f                              /* nothing to do */

    /* Counter chain for blocks 0-3 */
    mov    v0.16b, v14.16b
    add    v1.4s, v0.4s, v13.4s
    rev32  v0.16b, v0.16b
    add    v2.4s, v1.4s, v13.4s
    rev32  v1.16b, v1.16b
    add    v3.4s, v2.4s, v13.4s
    rev32  v2.16b, v2.16b
    add    v14.4s, v3.4s, v13.4s
    rev32  v3.16b, v3.16b
    aese   v0.16b, v19.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v19.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v19.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v19.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v20.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v20.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v20.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v20.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v21.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v21.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v21.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v21.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v22.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v22.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v22.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v22.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v23.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v23.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v23.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v23.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v24.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v24.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v24.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v24.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v25.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v25.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v25.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v25.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v26.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v26.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v26.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v26.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v27.16b
    aesmc  v0.16b, v0.16b
    aese   v1.16b, v27.16b
    aesmc  v1.16b, v1.16b
    aese   v2.16b, v27.16b
    aesmc  v2.16b, v2.16b
    aese   v3.16b, v27.16b
    aesmc  v3.16b, v3.16b
    aese   v0.16b, v28.16b
    eor    v0.16b, v0.16b, v29.16b
    aese   v1.16b, v28.16b
    eor    v1.16b, v1.16b, v29.16b
    aese   v2.16b, v28.16b
    eor    v2.16b, v2.16b, v29.16b
    aese   v3.16b, v28.16b
    eor    v3.16b, v3.16b, v29.16b

    /* XOR with pt, store ct, convert to reflected → v4-v7 */
    ld1    {v10.16b, v11.16b}, [x19], #32
    eor    v0.16b, v0.16b, v10.16b
    eor    v1.16b, v1.16b, v11.16b
    st1    {v0.16b, v1.16b}, [x20], #32
    ld1    {v10.16b, v11.16b}, [x19], #32
    eor    v2.16b, v2.16b, v10.16b
    eor    v3.16b, v3.16b, v11.16b
    st1    {v2.16b, v3.16b}, [x20], #32
    rev64  v4.16b, v0.16b
    rev64  v5.16b, v1.16b
    rev64  v6.16b, v2.16b
    rev64  v7.16b, v3.16b

/* ==== MAIN LOOP: AES(current 4 in v0-v3) ∥ GHASH(prev 4 in v4-v7) ==== */
1:
    cmp    x19, x21
    b.ge   80f                              /* go to epilogue */

    /* New counters into v0-v3 */
    mov    v0.16b, v14.16b
    add    v1.4s, v0.4s, v13.4s
    rev32  v0.16b, v0.16b
    add    v2.4s, v1.4s, v13.4s
    rev32  v1.16b, v1.16b
    add    v3.4s, v2.4s, v13.4s
    rev32  v2.16b, v2.16b
    add    v14.4s, v3.4s, v13.4s
    rev32  v3.16b, v3.16b
    aese   v0.16b, v19.16b
    aesmc  v0.16b, v0.16b
    mov    x9, x22                           /* reset tbl ptr */
    eor    v4.16b, v4.16b, v15.16b
    aese   v1.16b, v19.16b
    aesmc  v1.16b, v1.16b
    ext    v30.16b, v4.16b, v4.16b, #8
    eor    v30.16b, v30.16b, v4.16b
    aese   v2.16b, v19.16b
    aesmc  v2.16b, v2.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    pmull  v31.1q, v8.1d, v4.1d
    aese   v3.16b, v19.16b
    aesmc  v3.16b, v3.16b
    mov    v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v4.2d
    aese   v0.16b, v20.16b
    aesmc  v0.16b, v0.16b
    mov    v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    aese   v1.16b, v20.16b
    aesmc  v1.16b, v1.16b
    mov    v17.16b, v31.16b
    ext    v30.16b, v5.16b, v5.16b, #8
    aese   v2.16b, v20.16b
    aesmc  v2.16b, v2.16b
    eor    v30.16b, v30.16b, v5.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    aese   v3.16b, v20.16b
    aesmc  v3.16b, v3.16b
    pmull  v31.1q, v8.1d, v5.1d
    eor    v16.16b, v16.16b, v31.16b
    aese   v0.16b, v21.16b
    aesmc  v0.16b, v0.16b
    pmull2 v31.1q, v8.2d, v5.2d
    eor    v15.16b, v15.16b, v31.16b
    aese   v1.16b, v21.16b
    aesmc  v1.16b, v1.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b
    aese   v2.16b, v21.16b
    aesmc  v2.16b, v2.16b
    ext    v30.16b, v6.16b, v6.16b, #8
    eor    v30.16b, v30.16b, v6.16b
    aese   v3.16b, v21.16b
    aesmc  v3.16b, v3.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    aese   v0.16b, v22.16b
    aesmc  v0.16b, v0.16b
    pmull  v31.1q, v8.1d, v6.1d
    aese   v1.16b, v22.16b
    aesmc  v1.16b, v1.16b
    eor    v16.16b, v16.16b, v31.16b
    aese   v2.16b, v22.16b
    aesmc  v2.16b, v2.16b
    pmull2 v31.1q, v8.2d, v6.2d
    aese   v3.16b, v22.16b
    aesmc  v3.16b, v3.16b
    eor    v15.16b, v15.16b, v31.16b
    aese   v0.16b, v23.16b
    aesmc  v0.16b, v0.16b
    pmull  v31.1q, v9.1d, v30.1d
    aese   v1.16b, v23.16b
    aesmc  v1.16b, v1.16b
    eor    v17.16b, v17.16b, v31.16b
    aese   v2.16b, v23.16b
    aesmc  v2.16b, v2.16b
    ext    v30.16b, v7.16b, v7.16b, #8
    aese   v3.16b, v23.16b
    aesmc  v3.16b, v3.16b
    eor    v30.16b, v30.16b, v7.16b
    aese   v0.16b, v24.16b
    aesmc  v0.16b, v0.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    aese   v1.16b, v24.16b
    aesmc  v1.16b, v1.16b
    pmull  v31.1q, v8.1d, v7.1d
    aese   v2.16b, v24.16b
    aesmc  v2.16b, v2.16b
    eor    v16.16b, v16.16b, v31.16b
    aese   v3.16b, v24.16b
    aesmc  v3.16b, v3.16b
    pmull2 v31.1q, v8.2d, v7.2d
    aese   v0.16b, v25.16b
    aesmc  v0.16b, v0.16b
    eor    v15.16b, v15.16b, v31.16b
    aese   v1.16b, v25.16b
    aesmc  v1.16b, v1.16b
    pmull  v31.1q, v9.1d, v30.1d
    aese   v2.16b, v25.16b
    aesmc  v2.16b, v2.16b
    eor    v17.16b, v17.16b, v31.16b
    aese   v3.16b, v25.16b
    aesmc  v3.16b, v3.16b
    eor v17.16b, v17.16b, v15.16b
    aese   v0.16b, v26.16b
    aesmc  v0.16b, v0.16b
    eor v17.16b, v17.16b, v16.16b
    aese   v1.16b, v26.16b
    aesmc  v1.16b, v1.16b
    ext v30.16b, v17.16b, v18.16b, #8
    aese   v2.16b, v26.16b
    aesmc  v2.16b, v2.16b
    ext v17.16b, v18.16b, v17.16b, #8
    aese   v3.16b, v26.16b
    aesmc  v3.16b, v3.16b
    eor v15.16b, v15.16b, v17.16b
    aese   v0.16b, v27.16b
    aesmc  v0.16b, v0.16b
    eor v16.16b, v16.16b, v30.16b
    aese   v1.16b, v27.16b
    aesmc  v1.16b, v1.16b
    pmull v30.1q, v15.1d, v12.1d
    aese   v2.16b, v27.16b
    aesmc  v2.16b, v2.16b
    ext v15.16b, v15.16b, v15.16b, #8
    aese   v3.16b, v27.16b
    aesmc  v3.16b, v3.16b
    eor v15.16b, v15.16b, v30.16b
    aese   v0.16b, v28.16b
    eor    v0.16b, v0.16b, v29.16b
    pmull v30.1q, v15.1d, v12.1d
    aese   v1.16b, v28.16b
    eor    v1.16b, v1.16b, v29.16b
    eor v16.16b, v16.16b, v30.16b
    aese   v2.16b, v28.16b
    eor    v2.16b, v2.16b, v29.16b
    ext v16.16b, v16.16b, v16.16b, #8
    aese   v3.16b, v28.16b
    eor    v3.16b, v3.16b, v29.16b
    eor v15.16b, v15.16b, v16.16b

    /* XOR with pt, store ct, shift to v4-v7 (reflected) */
    ld1    {v10.16b, v11.16b}, [x19], #32
    eor    v0.16b, v0.16b, v10.16b
    eor    v1.16b, v1.16b, v11.16b
    st1    {v0.16b, v1.16b}, [x20], #32
    ld1    {v10.16b, v11.16b}, [x19], #32
    eor    v2.16b, v2.16b, v10.16b
    eor    v3.16b, v3.16b, v11.16b
    st1    {v2.16b, v3.16b}, [x20], #32
    rev64  v0.16b, v0.16b
    rev64  v1.16b, v1.16b
    rev64  v2.16b, v2.16b
    rev64  v3.16b, v3.16b
    /* Shift: current ct → previous for next iteration's GHASH */
    mov    v4.16b, v0.16b
    mov    v5.16b, v1.16b
    mov    v6.16b, v2.16b
    mov    v7.16b, v3.16b

    b      1b

/* ==== EPILOGUE: GHASH last 4 blocks (v4-v7), no AES to interleave ==== */
80:
    mov    x9, x22
    eor    v4.16b, v4.16b, v15.16b
    ext    v30.16b, v4.16b, v4.16b, #8
    eor    v30.16b, v30.16b, v4.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    pmull  v31.1q, v8.1d, v4.1d
    mov    v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v4.2d
    mov    v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    mov    v17.16b, v31.16b
    ext    v30.16b, v5.16b, v5.16b, #8
    eor    v30.16b, v30.16b, v5.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    pmull  v31.1q, v8.1d, v5.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v5.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b
    ext    v30.16b, v6.16b, v6.16b, #8
    eor    v30.16b, v30.16b, v6.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    pmull  v31.1q, v8.1d, v6.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v6.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b
    ext    v30.16b, v7.16b, v7.16b, #8
    eor    v30.16b, v30.16b, v7.16b
    ld1    {v8.16b, v9.16b}, [x9], #32
    pmull  v31.1q, v8.1d, v7.1d
    eor    v16.16b, v16.16b, v31.16b
    pmull2 v31.1q, v8.2d, v7.2d
    eor    v15.16b, v15.16b, v31.16b
    pmull  v31.1q, v9.1d, v30.1d
    eor    v17.16b, v17.16b, v31.16b
    eor v17.16b, v17.16b, v15.16b
    eor v17.16b, v17.16b, v16.16b
    ext v30.16b, v17.16b, v18.16b, #8
    ext v17.16b, v18.16b, v17.16b, #8
    eor v15.16b, v15.16b, v17.16b
    eor v16.16b, v16.16b, v30.16b
    pmull v30.1q, v15.1d, v12.1d
    ext v15.16b, v15.16b, v15.16b, #8
    eor v15.16b, v15.16b, v30.16b
    pmull v30.1q, v15.1d, v12.1d
    eor v16.16b, v16.16b, v30.16b
    ext v16.16b, v16.16b, v16.16b, #8
    eor v15.16b, v15.16b, v16.16b

90: /* done */
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
