// bench/bench_go.go
//
// Go TLS throughput benchmark (uses standard library crypto/tls + net).
// Measures the same primitives as bench_cvm.c for fair comparison.
//
// Build: go build -o bench_go bench_go.go
// Run:   ./bench_go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"
)

const bufSize = 16 * 1024 * 1024 // 16MB
const numRounds = 5

func nowMs() float64 {
	return float64(time.Now().UnixNano()) / 1e6
}

func benchAESGCM(data []byte) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	rand.Read(key)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	out := make([]byte, 0, bufSize+256)

	var best float64 = 1e9
	for r := 0; r < numRounds; r++ {
		t0 := nowMs()
		for off := 0; off < len(data); off += 16384 {
			end := off + 16384
			if end > len(data) {
				end = len(data)
			}
			out = gcm.Seal(out[:0], iv, data[off:end], nil)
		}
		t1 := nowMs()
		if t1-t0 < best {
			best = t1 - t0
		}
	}
	fmt.Printf("AES-128-GCM encrypt:  %8.1f MB/s\n", float64(bufSize)/best/1000.0)
}

func benchSHA256(data []byte) {
	var best float64 = 1e9
	for r := 0; r < numRounds; r++ {
		t0 := nowMs()
		sha256.Sum256(data)
		t1 := nowMs()
		if t1-t0 < best {
			best = t1 - t0
		}
	}
	fmt.Printf("SHA-256 hash:         %8.1f MB/s\n", float64(bufSize)/best/1000.0)
}

func benchX25519() {
	// crypto/ecdh exposes X25519 as a curve: GenerateKey makes a keypair,
	// ECDH derives the shared secret. Same two operations cvmcrypt reports.
	const iters = 200
	alice, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	bob, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	bobPub := bob.PublicKey()

	start := time.Now()
	for i := 0; i < iters; i++ {
		if _, err := alice.ECDH(bobPub); err != nil {
			panic(err)
		}
	}
	shared := time.Since(start) / iters

	start = time.Now()
	for i := 0; i < iters; i++ {
		if _, err := ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			panic(err)
		}
	}
	pub := time.Since(start) / iters

	fmt.Printf("X25519 shared secret:  %.1f µs/op\n", float64(shared.Nanoseconds())/1000)
	fmt.Printf("X25519 public key:     %.1f µs/op (GenerateKey, includes keygen)\n",
		float64(pub.Nanoseconds())/1000)
	return

	// Go's crypto/ecdh doesn't expose X25519 directly in older versions.
	// Use curve25519 from x/crypto if available, otherwise skip.
	fmt.Printf("X25519 key exchange:  (see Go crypto/ecdh, uses crypto/tls internally)\n")
}

func benchTLSRecord(data []byte) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	rand.Read(key)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	aad := []byte{23, 3, 3, 0x40, 0x00}
	out := make([]byte, 0, bufSize+256)

	var best float64 = 1e9
	for r := 0; r < numRounds; r++ {
		t0 := nowMs()
		for off := 0; off < len(data); off += 16384 {
			end := off + 16384
			if end > len(data) {
				end = len(data)
			}
			aad[3] = byte((end - off + 17) >> 8)
			aad[4] = byte(end - off + 17)
			out = gcm.Seal(out[:0], iv, data[off:end], aad)
		}
		t1 := nowMs()
		if t1-t0 < best {
			best = t1 - t0
		}
	}
	fmt.Printf("TLS record encrypt:   %8.1f MB/s (incl. AAD+tag overhead)\n", float64(bufSize)/best/1000.0)
}

func main() {
	fmt.Println("Go TLS benchmark")
	fmt.Println("================")
	fmt.Println()

	data := make([]byte, bufSize)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}

	benchAESGCM(data)
	benchSHA256(data)
	benchX25519()
	benchTLSRecord(data)

	fmt.Println()
	fmt.Println("done.")
}
