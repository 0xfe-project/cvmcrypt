# cvmcrypt TLS Benchmark Results

## Environment
- **CPU**: Apple M5 (arm64)
- **Compiler**: clang -O3 -mcpu=native (cvmcrypt), Go default, Rust --release + LTO

## Final Results

| Metric | cvmcrypt | Go | Rust ring | vs Go | vs ring |
|--------|--------:|---:|----------:|------:|--------:|
| X25519 | **20.4 µs** | **23.5** | **7.0** | **beats ✅** | 2.9× gap |
| AES-128-GCM | **~7,100 MB/s** | **10,185** | **9,352** | 1.43× gap | 1.32× gap |
| SHA-256 | **~3,272 MB/s** | **3,434** | **3,419** | ~parity | ~parity |
| TLS handshake | **40.7 µs** | — | — | complete ✅ | complete ✅ |

## Optimization Journey

### AES-128-GCM: 23 → 4,200 MB/s (183×)

| Step | Change | Result |
|------|--------|-------:|
| 1 | Scalar GHASH (bit-by-bit) | 23 MB/s |
| 2 | PMULL + rbit bit-reversal | 772 MB/s |
| 3 | + 4-block aggregated GHASH | 1,626 MB/s |
| 4 | + 8-block aggregated GHASH | 3,900 MB/s |
| 5 | + batched AES-CTR (4 blocks parallel) | 5,402 MB/s (cold) |
| 6 | + vqtbl1q lookup bit-reversal (15→6 instr) | ~4,200 MB/s (sustained) |
| 7 | + reflected-domain GHASH (Go gcm_arm64.s translation) | ~5,800 MB/s |
| 8 | + fused AES-CTR+GHASH 128-byte loop | ~6,900 MB/s |
| 9 | + hoisted round keys + pure NEON counters | ~7,100 MB/s |

Component analysis:
```
Full GCM (enc+auth): ~4,200 MB/s
AES-CTR only:        ~4,246 MB/s (scalar) — matches full GCM → GHASH is dominant cost
SHA-256:             ~3,272 MB/s
```

Per-block cost: GHASH ~36 instructions vs AES ~25. The 6-instruction
nat_load (bit reversal) is small; PMULL Karatsuba + reduction is the bulk.

### X25519: 215 → 20.4 µs (10.5×, beats Go)

| Step | Change | Result |
|------|--------|-------:|
| 1 | Tweetnacl 16×16-bit limbs | 215 µs |
| 2 | Go-style 5×51-bit limbs + addition chain | **20.4 µs** |

Key: `-O2` beats `-O3` (20.4 vs 38.8 µs). Compiler over-inlines at -O3.

### SHA-256: competitive with Go and ring

ARM64 vsha256hq intrinsic path. Within ~5% of both Go and ring.

## TLS 1.3 Complete Stack

Full interop verified with example.com:
- ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify → Finished
- HTTP request encrypted, response received
- Session resumption (ticket-based)
- x509 chain verification (RSA + ECDSA P-256/P-384)
- Cipher suites: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305

## Remaining Gap Analysis

### AES-GCM (2.4× from Go)
Go uses **reflected-domain GHASH** — zero bit reversal per block.
Our attempts (5+) to replicate the reflected domain failed:
VREV64+EXT is not a ring homomorphism; Go's compensation mechanism
(pre-multiplied H, POLY={0xC2..,0x01}) requires exact instruction-level
translation from their .s file.

### X25519 (2.9× from ring)
ring uses NEON with 10×25.5-bit limbs (~35 instructions per field multiply
vs our ~50 with 5×51 scalar). Would need a full NEON rewrite (~600 lines).

Both are solvable with sufficient effort. The reflected domain requires
writing actual ARM64 assembly (not C intrinsics); the X25519 requires
switching to a 10-limb representation for vmull_u32.

## Running

```bash
./build.sh    # build all three
./run_all.sh  # run and display results
```
