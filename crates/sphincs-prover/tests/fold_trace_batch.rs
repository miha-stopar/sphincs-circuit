//! Fold many single-compression steps from the start of a full verify trace.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_and_prove, fold_steps_prefix, pad_steps_to_power_of_two, setup_with_default_core,
    verify_proof, FoldCoreCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

fn rows_spec(trace: &sphincs_ref::Sha256Trace) -> Vec<Sha256Compression> {
    trace
        .compressions
        .iter()
        .map(|r| Sha256Compression {
            index: r.index,
            h_in: r.h_in,
            block: r.block,
            h_out: r.h_out,
        })
        .collect()
}

fn fold_n(rows: &[Sha256Compression], n: usize) {
    let mut steps = fold_steps_prefix(rows, n);
    assert_eq!(steps.len(), n);
    steps = pad_steps_to_power_of_two(steps);
    let num_steps = steps.len();

    let core = FoldCoreCircuit::new();
    let (pk, vk) = setup_with_default_core(&steps[0], num_steps);
    let proof = fold_and_prove(&pk, &steps, &core);
    verify_proof(&vk, &proof, num_steps);

    let bytes = bincode::serialize(&proof).expect("serialize");
    eprintln!("folded {n} trace compressions (padded to {num_steps}): proof {} bytes", bytes.len());
}

#[test]
fn fold_first_8_trace_compressions() {
    let seed = [0x77u8; CRYPTO_SEEDBYTES];
    let msg = b"fold trace batch smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = rows_spec(&trace);
    assert!(rows.len() > 32);
    fold_n(&rows, 8);
}

#[test]
#[ignore = "32-step fold is slow; run with --release --ignored"]
fn fold_first_32_trace_compressions() {
    let seed = [0x78u8; CRYPTO_SEEDBYTES];
    let msg = b"fold trace batch 32";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    fold_n(&rows_spec(&trace), 32);
}
