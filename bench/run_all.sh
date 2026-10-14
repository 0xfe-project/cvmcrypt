#!/bin/bash
# bench/run_all.sh — run all benchmarks and output results
set -e
cd "$(dirname "$0")"

echo "=========================================="
echo " TLS Crypto Benchmark Results"
echo " $(date '+%Y-%m-%d %H:%M') | $(uname -m)"
echo "=========================================="
echo ""

if [ -x ./bench_cvm ]; then
    echo "--- cvmcrypt (-O3) ---"
    ./bench_cvm
    echo ""
fi

if [ -x ./bench_go ]; then
    echo "--- Go (standard library) ---"
    ./bench_go
    echo ""
fi

if [ -x ./bench_rust ]; then
    echo "--- Rust ring (--release) ---"
    ./bench_rust
    echo ""
fi
