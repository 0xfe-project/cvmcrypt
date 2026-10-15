use ring::agreement;
use ring::rand::SystemRandom;
use std::time::Instant;

fn main() {
    let rng = SystemRandom::new();
    let n = 2000;
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..n {
            let priv_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
            let _ = priv_key.compute_public_key().unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if elapsed < best { best = elapsed; }
    }
    println!("ring keygen+pub:  {:8.1} µs/op", best * 1000.0 / n as f64);
}
