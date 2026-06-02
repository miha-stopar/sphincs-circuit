//! Fold a prefix of the longest PQClean local SHA chain + core boundary links.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_and_prove, longest_chain_prefix, setup_with_proto, verify_proof, FoldCoreChainCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

fn compressions_spec(trace: &sphincs_ref::Sha256Trace) -> Vec<Sha256Compression> {
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

/// Default smoke size; override with `FOLD_CHAIN_STEPS=32` for a longer run.
fn max_chain_steps() -> usize {
    std::env::var("FOLD_CHAIN_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16)
}

#[test]
fn fold_local_chain_with_core_links() {
    let seed = [0x44u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover local chain fold";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");

    let max_steps = max_chain_steps();
    let rows = compressions_spec(&trace);
    let (chain, steps, links) = longest_chain_prefix(&rows, max_steps)
        .expect("trace should contain a local chain of length >= 2");

    eprintln!(
        "folding local chain: steps={} links={} (trace indices {}..={})",
        steps.len(),
        links.len(),
        chain.start,
        chain.end
    );

    let core_proto = FoldCoreChainCircuit::new(links.clone());
    let core = FoldCoreChainCircuit::new(links);

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core_proto, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
