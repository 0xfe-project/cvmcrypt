// bench/src/main.rs
//
// Rust TLS crypto benchmark using ring (behind rustls).

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use std::time::Instant;

const BUF_SIZE: usize = 16 * 1024 * 1024;
const NUM_ROUNDS: usize = 5;

fn bench_aes_gcm(data: &[u8]) {
    let key_bytes = [0xABu8; 16];
    let nonce_bytes = [0xCDu8; 12];
    let unbound = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let mut buf = data.to_vec();

    let mut best = f64::MAX;
    for _ in 0..NUM_ROUNDS {
        let start = Instant::now();
        for off in (0..buf.len()).step_by(16384) {
            let end = (off + 16384).min(buf.len());
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let tag = key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf[off..end]).unwrap();
            let _ = tag;
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed < best { best = elapsed; }
    }
    println!("AES-128-GCM encrypt:  {:8.1} MB/s", BUF_SIZE as f64 / best / 1000.0);
}

fn bench_sha256(data: &[u8]) {
    let mut best = f64::MAX;
    for _ in 0..NUM_ROUNDS {
        let start = Instant::now();
        let _ = digest(&SHA256, data);
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed < best { best = elapsed; }
    }
    println!("SHA-256 hash:         {:8.1} MB/s", BUF_SIZE as f64 / best / 1000.0);
}

fn bench_chachapoly(data: &[u8], out: &mut [u8]) {
    let key_bytes = [0xABu8; 32];
    let nonce_bytes = [0xCDu8; 12];
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    let mut best = f64::MAX;
    for _ in 0..NUM_ROUNDS {
        let start = Instant::now();
        for off in (0..data.len()).step_by(16384) {
            let end = (off + 16384).min(data.len());
            let chunk_len = end - off;
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let _ = key.seal_in_place_separate_tag(
                nonce,
                Aad::empty(),
                &mut out[off..off + chunk_len],
            );
        }
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed < best {
            best = elapsed;
        }
    }
    println!("ChaCha20-Poly1305:    {:8.1} MB/s", data.len() as f64 / best / 1e6);
}

fn bench_gcm_decrypt(data: &mut [u8], out: &mut [u8]) {
    let key_bytes = [0xABu8; 16];
    let nonce_bytes = [0xCDu8; 12];
    let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);

    /* pre-seal 16 KB so there is ciphertext to open */
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[..16384])
        .unwrap();
    let _ = tag;

    let mut best = f64::MAX;
    for _ in 0..NUM_ROUNDS {
        let start = Instant::now();
        for off in (0..data.len()).step_by(16384) {
            let end = (off + 16384).min(data.len());
            let chunk_len = end - off;
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let _ = key.seal_in_place_separate_tag(
                nonce,
                Aad::empty(),
                &mut out[off..off + chunk_len],
            );
        }
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed < best {
            best = elapsed;
        }
    }
    println!("AES-128-GCM decrypt: {:8.1} MB/s", data.len() as f64 / best / 1e6);
}

fn bench_x25519() {
    let rng = SystemRandom::new();
    let n = 500;
    let mut best = f64::MAX;
    for _ in 0..3 {
        let start = Instant::now();
        for _ in 0..n {
            let priv_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng).unwrap();
            let _pub = priv_key.compute_public_key().unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed < best { best = elapsed; }
    }
    println!("X25519 key exchange:  {:8.1} µs/op", best * 1000.0 / n as f64);
}

fn bench_tls_record(data: &[u8]) {
    let key_bytes = [0xABu8; 16];
    let nonce_bytes = [0xCDu8; 12];
    let unbound = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound);
    let mut buf = data.to_vec();

    let mut best = f64::MAX;
    for _ in 0..NUM_ROUNDS {
        let start = Instant::now();
        for off in (0..buf.len()).step_by(16384) {
            let end = (off + 16384).min(buf.len());
            let chunk_len = end - off;
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let aad_bytes = [23u8, 3, 3, ((chunk_len + 17) >> 8) as u8, (chunk_len + 17) as u8];
            let aad = Aad::from(&aad_bytes[..]);
            let _ = key.seal_in_place_separate_tag(nonce, aad, &mut buf[off..end]);
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed < best { best = elapsed; }
    }
    println!("TLS record encrypt:   {:8.1} MB/s (incl. AAD+tag overhead)", BUF_SIZE as f64 / best / 1000.0);
}

fn main() {
    println!("Rust (ring) TLS benchmark");
    println!("=========================");
    println!();

    let data: Vec<u8> = (0..BUF_SIZE).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8).collect();

    let mut out = vec![0u8; BUF_SIZE + 256];
    let mut data_mut = data.clone();
    bench_aes_gcm(&data);
    bench_chachapoly(&data, &mut out);
    bench_gcm_decrypt(&mut data_mut, &mut out);
    bench_sha256(&data);
    bench_x25519();
    bench_tls_record(&data);

    println!();
    println!("done.");
}
