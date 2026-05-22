//! Print SHA-256 compression count for verify(PK, M, σ).
//!
//! ```bash
//! cargo run -p sphincs-ref --bin sphincs-trace-stats
//! ```

use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

fn main() {
    let seed = [0u8; CRYPTO_SEEDBYTES];
    for (label, msg) in [("33B", vec![0u8; 33]), ("512B", vec![0xabu8; 512])] {
        sphincs_ref::reset_signing_rng(42);
        let (pk, sig) = sign_deterministic(&seed, &msg).expect("sign");
        let trace = verify_with_trace(&pk, &msg, &sig).expect("verify");
        println!("{label}: {} SHA-256 compressions", trace.len());
    }
}
