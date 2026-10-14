# cvmcrypt TLS Benchmark Results

Comparing cvmcrypt's TLS crypto primitives against Go's standard library and Rust's `ring` (the crypto library behind `rustls`).

## Environment

- **CPU**: Apple M5 (arm64)
- **OS**: macOS (Darwin)
- **Compiler**: clang -O3 -mcpu=native (cvmcrypt), Go default (gc), Rust cargo --release + LTO
- **Date**: 2026-10-14

## Results

| Metric | cvmcrypt (-O3) | Go (stdlib) | Rust ring (--release) | cvm vs Go |
|--------|---------------:|------------:|----------------------:|----------:|
| AES-128-GCM encrypt | **772 MB/s** | **10,187 MB/s** | **9,412 MB/s** | 13.2× slower |
| SHA-256 hash | **3,079 MB/s** | **3,501 MB/s** | **3,553 MB/s** | 1.14× slower |
| X25519 key exchange | **217 µs/op** | — | **6.9 µs/op** | 31× slower |
| TLS record encrypt | **774 MB/s** | **10,212 MB/s** | **9,204 MB/s** | 13.2× slower |

## Optimization History

| Date | Change | AES-GCM | Improvement |
|------|--------|--------:|------------:|
| Initial | Scalar GHASH (bit-by-bit) | 23 MB/s | — |
| PMULL fix | ARM64 PMULL + rbit conversion | **772 MB/s** | **33× faster** |

## Analysis

### AES-128-GCM: PMULL active, 772 MB/s
The GHASH multiplication now uses ARM64's `pmull` instruction (polynomial multiply) with `rbit` for bit-order conversion. This is 33× faster than the previous scalar path.

**Remaining gap (13× vs Go/ring)**: Go and ring use *aggregated GHASH* — multiplying multiple blocks by precomputed powers of H before reducing once, amortizing per-block overhead. They also avoid the per-block `rbit` by staying in the reflected domain throughout. Implementing aggregated GHASH (4-block parallel with precomputed H, H², H³, H⁴) would close most of this gap.

### SHA-256: Competitive (3,079 vs 3,501 vs 3,553)
ARM64 SHA-2 intrinsics with dual-block processing. Within 12% of Go/ring.

### X25519: 31× slower
Pure C tweetnacl-style Montgomery ladder. Go uses `crypto/ecdh` (assembly), ring uses `x25519-dalek` style optimized field arithmetic.

**Fix**: ARM64 assembly implementation (radix 2^51, 5 limbs) would bring this to ~15 µs.

## Running

```bash
./build.sh    # build all three
./run_all.sh  # run and display results
```
