use ring::agreement::{self, EphemeralPrivateKey, X25519, agree_ephemeral};
use ring::rand::SystemRandom;
use std::time::Instant;

fn main() {
    let rng = SystemRandom::new();
    let n = 1000;

    // (a) fixed-base comb: compute_public_key
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        for _ in 0..n {
            let k = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let _ = k.compute_public_key().unwrap();
        }
        let e = t.elapsed().as_secs_f64() * 1000.0;
        if e < best { best = e; }
    }
    println!("ring comb   (generate+public): {:7.2} us/op", best * 1000.0 / n as f64);

    // (b) general point ladder: agree_ephemeral
    let peer_priv = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let peer_pub_bytes = peer_priv.compute_public_key().unwrap().as_ref().to_vec();
    let peer_pub = agreement::UnparsedPublicKey::new(&X25519, peer_pub_bytes);
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        for _ in 0..n {
            let k = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let _ = agree_ephemeral(k, &peer_pub, |_s: &[u8]| -> Result<(), ring::error::Unspecified> { Ok(()) });
        }
        let e = t.elapsed().as_secs_f64() * 1000.0;
        if e < best { best = e; }
    }
    println!("ring ladder (generate+agree) : {:7.2} us/op", best * 1000.0 / n as f64);

    // (c) rng only, to subtract
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        for _ in 0..n {
            let _ = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        }
        let e = t.elapsed().as_secs_f64() * 1000.0;
        if e < best { best = e; }
    }
    println!("ring generate only           : {:7.2} us/op", best * 1000.0 / n as f64);
}
