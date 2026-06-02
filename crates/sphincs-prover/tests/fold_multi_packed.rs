//! Fold multiple packed local chains in one NeutronNova batch (sound segments).

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_and_prove, packed_chains_from_trace, setup_with_proto, verify_proof, FoldCoreCircuit,
    FoldPackedChainCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

const N: usize = 4;

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

#[test]
#[ignore = "folding several packed chains is slow; run with --release --ignored"]
fn fold_several_packed_local_chains() {
    let seed = [0x66u8; CRYPTO_SEEDBYTES];
    let msg = b"multi packed chain fold";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = rows_spec(&trace);

    let chains = packed_chains_from_trace::<N>(&rows);
    assert!(
        chains.len() >= 2,
        "expected at least two local chains of len >= {N}, got {}",
        chains.len()
    );

    // NeutronNova needs power-of-two step count; pad by duplicating the last chain.
    let mut instances: Vec<FoldPackedChainCircuit<N>> =
        chains.iter().map(|(_, p)| p.clone()).collect();
    while !instances.len().is_power_of_two() {
        instances.push(instances.last().unwrap().clone());
    }
    let num_steps = instances.len();
    eprintln!("folding {num_steps} packed chain instances (pad to power of two)");

    let core = FoldCoreCircuit::new();
    let (pk_fold, vk) = setup_with_proto(&instances[0], &core, num_steps);
    let proof = fold_and_prove(&pk_fold, &instances, &core);
    verify_proof(&vk, &proof, num_steps);
}
