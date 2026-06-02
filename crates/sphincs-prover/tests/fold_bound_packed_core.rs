//! Sound step↔core binding: packed chain wires + trace boundary checks in one step circuit.

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_circuit::LocalChain;
use sphincs_prover::{
    chain_boundary_links, fold_and_prove, longest_chain_prefix, setup_with_proto, verify_proof,
    FoldCoreCircuit, FoldPackedCoreBoundCircuit,
};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

const N: usize = 4;

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
fn fold_packed_core_bound_proves_and_verifies() {
    let seed = [0x61u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover packed core bound";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (chain, step_rows, links) =
        longest_chain_prefix(&rows, N).expect("local chain len >= N");
    let inputs: Vec<_> = step_rows.iter().map(|s| *s.input()).collect();
    let packed =
        FoldPackedCoreBoundCircuit::<N>::from_slice(&inputs, links.clone()).expect("N rows");
    eprintln!(
        "packed+core bound: N={N} links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    let sub = LocalChain {
        start: chain.start,
        end: chain.start + N - 1,
        len: N,
    };
    let boundary = chain_boundary_links(&rows, &sub);
    assert_eq!(boundary, links);

    let core = FoldCoreCircuit::new();
    let (pk_fold, vk) = setup_with_proto(&packed, &core, 2);
    let steps = [packed.clone(), packed];
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, 2);
}
