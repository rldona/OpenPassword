//! Measures KEK derivation with the production KDF profiles.
//! Run on a device to calibrate: `cargo run --release -p op-core --example kdf_bench`.

use std::time::Instant;

use op_core::crypto::derive_kek;
use op_core::{KdfParams, SecretKey};

fn main() {
    let sk = SecretKey::from_bytes([7; 16]);
    let salt = [9; 32];
    for (name, params) in [
        ("recomendado", KdfParams::RECOMMENDED),
        ("mínimo", KdfParams::MINIMUM),
    ] {
        let mut times = Vec::new();
        let mut first = None;
        for _ in 0..3 {
            let start = Instant::now();
            let kek = derive_kek("contraseña de prueba", &sk, &salt, &params).unwrap();
            times.push(start.elapsed().as_millis());
            // Same inputs must give the same KEK every run.
            let bytes = *kek.expose();
            assert!(first.get_or_insert(bytes) == &bytes);
        }
        let kek_prefix: String = first.unwrap()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!(
            "{name:<12} m={} MiB t={} p={}: {:?} ms (KEK {kek_prefix}…)",
            params.m_kib / 1024,
            params.t,
            params.p,
            times
        );
    }
}
