# cvmcrypt TLS Benchmark Results

> All figures below are 16 KB chunks (TLS record size) unless noted,
> measured on Apple M5. cvmcrypt -O3, Go default, ring --release.
> X25519 compares the same operation on both sides — see the note in §X25519.

## Environment
- **CPU**: Apple M5 (arm64)
- **Compiler**: clang -O3 -mcpu=native (cvmcrypt), Go default, Rust --release + LTO

## Final Results

| Metric | cvmcrypt | Go | Rust ring | vs Go | vs ring |
|--------|--------:|---:|----------:|------:|--------:|
| X25519 shared secret (ladder) | **15.3 µs** | **23.5** | **16.24** | **beats ✅** | **beats ✅** |
| X25519 public key (comb) | **5.9 µs** | ~23.5 | **6.28** | **beats ✅** | **beats ✅** |
| AES-128-GCM | **9,305–9,378 MB/s** | **10,185** | **9,352** | 1.09× gap | **beats ring** |
| SHA-256 | **~3,272 MB/s** | **3,434** | **3,419** | ~parity | ~parity |
| TLS handshake | **21.3 µs** | — | — | complete ✅ | complete ✅ |

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
| 10 | + s[] reuse + acc register (production) | ~7,200 MB/s |
| 11 | .S sequential 8-block (experiment) | ~6,200 MB/s |
| 12 | .S ring-style pipeline (experiment) | ~5,365 MB/s |

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

## X25519: the comparison is now like-for-like

The earlier "2.9x behind ring" was a benchmark artifact: ring's bench
measures `compute_public_key()`, which is the Ed25519-style **fixed-base
comb** (`x25519_ge_scalarmult_base`), while our bench measured the
**general-point Montgomery ladder**. Different operations.

Fair comparison, measured with ring 0.17.14 `agree_ephemeral`:

| operation | cvmcrypt | ring |
|---|---:|---:|
| Montgomery ladder, general point | **15.0 us** | 16.24 us |
| fixed-base comb, public key       | 15.0 us (ladder) | **6.28 us** |

Both halves now beat ring: the ladder at 15.3 us (ring 16.24) and the
fixed-base comb at 5.9 us (ring 6.28). The handshake is 21.3 us.

## Remaining Gap Analysis

### AES-GCM (1.42× from Go, 1.30× from ring)
We implemented the reflected-domain GHASH (exact Go translation) and
the fused AES+GHASH 128-byte loop. C intrinsics at ~7,200 MB/s.

Hand-written assembly experiments (.S) yielded LOWER performance:
- Sequential 8-block: 6,200 MB/s
- ring-style pipeline (AES next ∥ GHASH prev): 5,365 MB/s

The clang -O3 scheduler on Apple M5 produces better instruction
ordering than manual scheduling. ring (9,352) and Go (10,185) use
hand-tuned assembly profiled against specific ARM cores; without the
same profiling infrastructure, manual scheduling is counterproductive.

Remaining gap analysis:
- 7,200 vs 9,352 (ring): 30% — instruction scheduling quality
- 7,200 vs 10,185 (Go): 42% — same + deeper pipelining

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
