#!/bin/bash
set -e
cd "$(dirname "$0")"

ROOT=..
CC=clang

echo "=== Building cvmcrypt bench (-O3) ==="
FI=$($CC -print-resource-dir)/include
$CC -std=c11 -O3 -Wno-format \
  -I $ROOT/vendor/cvm/rt -I $ROOT/include -I $ROOT/src -I $ROOT/tests -I $FI \
  bench_cvm.c \
  $ROOT/src/tls/client.c $ROOT/src/tls/server.c $ROOT/src/tls/record.c \
  $ROOT/src/tls/keyschedule.c $ROOT/src/tls/handshake.c $ROOT/src/tls/session.c \
  $ROOT/src/tls/crypto_cvm.c $ROOT/src/tls/verify_cvm.c \
  $ROOT/src/aead/gcm.c $ROOT/src/aead/chachapoly.c $ROOT/src/cipher/aes.c \
  $ROOT/src/stream/chacha20.c $ROOT/src/mac/poly1305.c \
  $ROOT/src/hash/sha256.c $ROOT/src/hash/sha512.c $ROOT/src/kdf/hkdf.c \
  $ROOT/src/mac/hmac.c $ROOT/src/api/aead.c $ROOT/src/api/hash.c \
  $ROOT/src/api/cipher.c $ROOT/src/api/random.c \
  $ROOT/src/kx/x25519_fast.c $ROOT/src/base/mem.c $ROOT/src/base/secure.c \
  $ROOT/src/x509/x509.c $ROOT/src/pk/rsa.c $ROOT/src/ecc/p256.c \
  $ROOT/src/math/bignum.c $ROOT/src/asn1/der.c \
  $ROOT/src/aead/asm/aes_gcm_arm64_apple.S $ROOT/src/aead/asm/ghash_arm64_apple.S \
  $ROOT/src/aead/asm/chachapoly_arm64_apple.S \
  $ROOT/tests/support/rt_stub.c \
  -o bench_cvm 2>&1 | grep -E "error|warning" | head -5 || true
if [ -x ./bench_cvm ]; then
    echo "OK: ./bench_cvm"
else
    echo "FAIL"
    exit 1
fi

echo ""
echo "=== Building Go bench ==="
if command -v go &> /dev/null; then
    go build -o bench_go bench_go.go 2>&1 | head -3
    [ -x ./bench_go ] && echo "OK: ./bench_go" || echo "FAIL"
else
    echo "SKIP: Go not installed"
fi

echo ""
echo "=== Building Rust bench (--release) ==="
if command -v cargo &> /dev/null; then
    cargo build --release 2>&1 | tail -2
    cp target/release/bench_rust . 2>/dev/null || true
    [ -x ./bench_rust ] && echo "OK: ./bench_rust" || echo "FAIL"
else
    echo "SKIP: cargo not installed"
fi

echo ""
echo "Built. Run ./run_all.sh"
