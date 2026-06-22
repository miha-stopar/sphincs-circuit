//! Demonstrates the **NeutronNova split**: N folded step circuits + one separate core circuit.
//!
//! Read [FOLDING.md §2.4](../../docs/FOLDING.md) for how Spartan2 combines them in one proof.
//!
//! This test uses:
//! - [`FoldStepCircuit`] — folding constraints (one compression per instance)
//! - [`FoldCoreChainCircuit`] — core constraints (trace link bytes, separate R1CS)
//!
//! Both are satisfied and verified together via [`fold_and_prove`]. For sound binding use
//! [`FoldStepBoundCircuit`] + [`FoldCoreBoundCircuit`] or [`FoldVerifyCoreCircuit`]; this test
//! intentionally uses unsound byte-only links in the core for illustration.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_and_prove, fold_prove_verify_timed, longest_chain_prefix, setup_with_proto, verify_proof,
    FoldCoreChainCircuit, FoldStepCircuit,
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

#[test]
fn fold_split_step_circuits_and_separate_core() {
    let seed = [0x2eu8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover split step+core demo";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");

    const N: usize = 4;
    let rows = compressions_spec(&trace);
    let (chain, steps, links) =
        longest_chain_prefix(&rows, N).expect("local chain with >= 4 compressions");

    eprintln!("=== NeutronNova split (see docs/FOLDING.md §2.4) ===");
    eprintln!(
        "C_step: {} instances, each proves Compress(h_in, block)  [trace {}..={}]",
        steps.len(),
        chain.start,
        chain.end
    );
    eprintln!(
        "C_core: {} link equalities (witness bytes in core only, not step wires)",
        links.len()
    );
    eprintln!("NIFS: folds step instances → (U_fold, W_fold); core is NOT folded");
    eprintln!("Proof: batched sum-check over folded step + core R1CS");

    let core = FoldCoreChainCircuit::new(links);
    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());

    let (_proof, t) = fold_prove_verify_timed(&pk_fold, &vk, &steps, &core);
    eprintln!(
        "prep {} ms | prove {} ms | verify {} ms",
        t.prep_ms, t.prove_ms, t.verify_ms
    );

    // Idempotent check
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());

    // Sanity: step and core are different SpartanCircuit types
    let _: &FoldStepCircuit = &steps[0];
    let _ = FoldCoreChainCircuit::new(vec![]);
}
