//! Sound in-circuit local chain: one NeutronNova step = `N` wired compressions.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_circuit::witness::step_input_from_row;
use sphincs_prover::{
    fold_and_prove, longest_chain_prefix, setup_with_proto, verify_proof, FoldCoreCircuit,
    FoldPackedChainCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

const N: usize = 8;

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
fn fold_packed_chain_proves_and_verifies() {
    let seed = [0x55u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover packed chain";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (chain, _, _) = longest_chain_prefix(&rows, N).expect("local chain len >= N");
    let inputs: Vec<_> = rows[chain.start..=chain.end]
        .iter()
        .map(step_input_from_row)
        .collect();
    let packed = FoldPackedChainCircuit::<N>::from_slice(&inputs).expect("N rows");
    eprintln!(
        "packed chain: N={N} trace indices {}..={} (one NeutronNova step)",
        chain.start, chain.end
    );

    // Spartan2 NeutronNova needs ≥2 step instances (power-of-two padding); duplicate the same chain.
    let core = FoldCoreCircuit::new();
    let (pk_fold, vk) = setup_with_proto(&packed, &core, 2);
    let steps = [packed.clone(), packed];
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, 2);
}
