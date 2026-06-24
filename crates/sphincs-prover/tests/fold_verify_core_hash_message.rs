//! Phase 2 smoke: folded bound steps + real `hash_message` core (`FoldVerifyCoreCircuit`).

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_circuit::hash_message_mgf_buf;
use sphincs_prover::{
    fold_and_prove, longest_chain_bound, padded_message, setup_with_proto, sig_r, verify_proof,
    FoldVerifyCoreCircuit,
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

fn max_steps() -> usize {
    std::env::var("FOLD_VERIFY_CORE_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n.is_power_of_two() && n >= 2)
        .unwrap_or(4)
}

/// Bound steps (uniform selector) + core running `hash_message` + shared link checks.
#[test]
fn fold_verify_core_hash_message_smoke() {
    let seed = [0x44u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover verify core hash_message smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_steps();
    let (chain, steps, _old_core, links) =
        longest_chain_bound(&rows, n).expect("local chain with power-of-two prefix");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);

    let core = FoldVerifyCoreCircuit::hash_message(pk, message, mlen, r, hm_mgf, digests);

    eprintln!(
        "verify-core smoke: steps={n} links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// `hash_message` core + plain folded steps (no shared witness). Isolates core gadget size.
#[test]
fn fold_verify_core_hash_message_plain_steps() {
    let seed = [0x45u8; CRYPTO_SEEDBYTES];
    let msg = b"verify core plain steps";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let core = FoldVerifyCoreCircuit::hash_message(pk, message, mlen, r, hm_mgf, vec![]);

    use sphincs_prover::{fold_steps_prefix, pad_steps_to_power_of_two, setup_with_proto, FoldStepCircuit};
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);
    let mut steps: Vec<FoldStepCircuit> = fold_steps_prefix(&rows, 4);
    steps = pad_steps_to_power_of_two(steps);

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
