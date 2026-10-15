# cvmcrypt TLS Benchmark Results

## Environment
- **CPU**: Apple M5 (arm64)
- **Compiler**: clang -O2 -mcpu=native (cvmcrypt), Go default, Rust --release + LTO

## Results

| Metric | cvmcrypt | Go | Rust ring | status |
|--------|--------:|---:|----------:|-------:|
| X25519 | **20.9 µs** | **23.5** | **7.0** | **beats Go ✅** |
| AES-128-GCM | **5,402 MB/s** | **10,185** | **9,352** | 1.9× gap |
| SHA-256 | **3,000 MB/s** | **3,434** | **3,419** | competitive |

## Optimization History

### X25519 (215 → 20.9 µs, 10.3×, beats Go)

| Step | Change | Result |
|------|--------|-------:|
| 1 | Tweetnacl 16×16-bit limbs | 215 µs |
| 2 | Go-style 5×51-bit limbs + addition chain | **20.9 µs** |

Key: `-O2` beats `-O3` (20.9 vs 38.8 µs) — compiler over-inlines at -O3.

### AES-128-GCM (23 → 5,402 MB/s, 235×)

| Step | Change | Result |
|------|--------|-------:|
| 1 | Scalar GHASH (bit-by-bit) | 23 MB/s |
| 2 | PMULL + rbit bit-reversal | 772 MB/s |
| 3 | + 4-block aggregated GHASH | 1,626 MB/s |
| 4 | + 8-block aggregated GHASH | 3,900 MB/s |
| 5 | + batched AES-CTR (4 blocks parallel) | **5,402 MB/s** |

## Remaining Gap Analysis

### AES-GCM (1.9× from Go)
Go uses **reflected-domain GHASH** — no bit reversal per block.
We do `bitrev128_neon` (17 NEON instructions per block) to convert
between GHASH byte-reflected order and PMULL natural polynomial order.

Attempts to implement reflected domain:
- POLY constant `{0xC2.., 0x..01}` reduction doesn't produce correct
  results in our implementation
- Go's `VPMULL POLY.D1` uses D[0] (low lane) not D[1] — we initially
  had this wrong, but fixing it still didn't match scalar results
- The VREV64+VEXT byte-level transform is NOT a ring homomorphism;
  Go compensates with a pre-multiplied H (×2) that we couldn't replicate

Estimated remaining gain if solved: 5,402 → ~9,000 MB/s.

### X25519 (3× from ring)
ring uses ref10-style 10×25.5-bit limbs (portable C, no NEON).
We use 5×51-bit limbs (matching Go's algorithm exactly).

Ring's advantage: simpler carry propagation and better instruction
scheduling from fiat-crypto generated code.

NEON approach: switch to 10×25.5-bit limbs so field multiply can use
`vmull_u32` (4 lanes of 32×32→64). Estimated: 20 → ~8 µs.

## Running

```bash
./build.sh    # build all three
./run_all.sh  # run and display results
```
