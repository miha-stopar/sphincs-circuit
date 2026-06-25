//! Phase 2c: [`FoldVerifyCoreCircuit::with_public_io`] — Spartan public `(mlen, PK, M)`.
//!
//! # Background
//!
//! Variant A ([DECISIONS.md](../../docs/DECISIONS.md)): public `PK`, padded `M`, `mlen`; private `σ`
//! and trace. This test checks NeutronNova prove/verify when `C_core` exposes 1033 public scalars
//! instead of the dummy `[0]` placeholder.
//!
//! Encoding: `sphincs_circuit::verify_public_io` / `docs/VERIFY_CORE.md` §Public Spartan IO.
//!
//! # Run
//!
//! ```bash
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
//! ```

#![cfg(feature = "pqclean")]

use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
use circuit_spec::Sha256Compression;
use spartan2::traits::circuit::SpartanCircuit;
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

#[test]
fn fold_verify_core_hash_message_public_io_smoke() {
    let seed = [0x55u8; CRYPTO_SEEDBYTES];
    let msg = b"public io smoke: mlen pk message";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (_chain, steps, _old_core, links) =
        longest_chain_bound(&rows, 4).expect("local chain");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);

    let core = FoldVerifyCoreCircuit::hash_message(pk, message, mlen, r, hm_mgf, digests)
        .with_public_io();

    assert!(core.public_io);
    assert_eq!(
        core.public_values().expect("public").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    eprintln!(
        "public_io smoke: steps={} links={} public_scalars={}",
        steps.len(),
        links.len(),
        VERIFY_PUBLIC_NUM_SCALARS,
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
