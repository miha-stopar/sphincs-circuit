//! Fold with **shared witness** binding: step compressions pin link digests; core checks trace.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{fold_and_prove, longest_chain_bound, setup_with_proto, verify_proof};
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

fn max_bound_steps() -> usize {
    std::env::var("FOLD_BOUND_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n.is_power_of_two() && n >= 2)
        .unwrap_or(4)
}

/// Spartan2 0.9.0 NeutronNova currently fails once `num_shared > 0` (see `bound` module docs).
#[test]
#[ignore = "shared-witness NeutronNova verify fails on Spartan2 0.9.0"]
fn fold_bound_shared_links_prove_and_verify() {
    let seed = [0x33u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover bound shared fold";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_bound_steps();
    let (chain, steps, core, links) =
        longest_chain_bound(&rows, n).expect("local chain with power-of-two prefix");
    eprintln!(
        "bound fold: steps={n} shared_links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    let proto = &steps[0];
    let (pk_fold, vk) = setup_with_proto(proto, &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
