//! Bench NeutronNova fold on the first N compressions of a PQClean verify trace.
//!
//! ```bash
//! cargo run -p sphincs-prover --features pqclean --release --bin fold-bench -- 32
//! ```

use std::env;

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_prove_verify_timed, fold_steps_prefix, pad_steps_to_power_of_two, setup_with_default_core,
    FoldCoreCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

fn main() {
    let n: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    let seed = [0x2au8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover fold-bench";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");

    let rows: Vec<Sha256Compression> = trace
        .compressions
        .iter()
        .map(|r| Sha256Compression {
            index: r.index,
            h_in: r.h_in,
            block: r.block,
            h_out: r.h_out,
        })
        .collect();

    assert!(
        rows.len() >= n,
        "trace has {} compressions, need {}",
        rows.len(),
        n
    );

    let steps = pad_steps_to_power_of_two(fold_steps_prefix(&rows, n));
    let num_steps = steps.len();

    let setup_start = std::time::Instant::now();
    let core = FoldCoreCircuit::new();
    let (pk_fold, vk) = setup_with_default_core(&steps[0], num_steps);
    let setup_ms = setup_start.elapsed().as_millis();

    let (proof, timings) = fold_prove_verify_timed(&pk_fold, &vk, &steps, &core);
    let proof_bytes = bincode::serialize(&proof).expect("serialize").len();

    println!("fold-bench (SPHINCS+ verify trace, first {n} compressions)");
    println!("  trace total compressions: {}", rows.len());
    println!("  step instances (padded):  {num_steps}");
    println!("  setup:   {setup_ms} ms");
    println!("  prep:    {} ms", timings.prep_ms);
    println!("  prove:   {} ms", timings.prove_ms);
    println!("  verify:  {} ms", timings.verify_ms);
    println!("  proof:   {proof_bytes} bytes");
}
