//! NeutronNova tests: offloaded verify core + folded steps sharing one `comm_W_shared`.
//!
//! ```bash
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_offloaded
//! ```

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_circuit::{
    hash_message_mgf_buf, parse_mgf_output, seeded_state, thash::SPX_N, FORS_F_CALLS,
};
use sphincs_prover::{
    fold_and_prove_general, longest_chain_bound, next_power_of_two_steps,
    offload_shared_context_from_pqclean, setup_with_proto, sig_r, thash_f_offload_steps_fold,
    verify_proof, FoldStepBoundOffloadCircuit, FoldVerifyCoreCircuit, OffloadSharedContext,
    ThashFBusRegion, padded_message,
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

fn max_hm_steps() -> usize {
    std::env::var("FOLD_VERIFY_CORE_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n.is_power_of_two() && n >= 2)
        .unwrap_or(4)
}

/// `hash_message` bound steps + offloaded verify core share links + thash bus columns.
#[test]
fn fold_verify_core_offloaded_hash_message_smoke() {
    let seed = [0x5au8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core hash_message smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_hm_steps();
    let (_chain, bound_steps, _old_core, links) =
        longest_chain_bound(&rows, n).expect("local chain");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let hm = parse_mgf_output(&hm_mgf);

    let ctx = offload_shared_context_from_pqclean(&pk, &sig, &hm, digests.clone());
    let core = FoldVerifyCoreCircuit::offloaded(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        digests.clone(),
        ctx.offload.clone(),
    );

    let steps: Vec<FoldStepBoundOffloadCircuit> = bound_steps
        .iter()
        .map(|b| FoldStepBoundOffloadCircuit::from_bound(b, ctx.clone()))
        .collect();

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// FORS leaf `thash`-F steps + offloaded core (unified shared; HM links empty).
#[test]
fn fold_verify_core_offloaded_fors_f_smoke() {
    let seed = [0x6bu8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core fors f smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let hm = parse_mgf_output(&hm_mgf);

    let ctx = offload_shared_context_from_pqclean(&pk, &sig, &hm, vec![]);
    let core = FoldVerifyCoreCircuit::offloaded(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        vec![],
        ctx.offload.clone(),
    );

    let pub_seed = {
        let mut s = [0u8; SPX_N];
        s.copy_from_slice(&pk[..SPX_N]);
        s
    };
    let seeded = seeded_state(&pub_seed);
    let fors_f = ctx.offload.fors_f.clone();
    assert_eq!(fors_f.len(), FORS_F_CALLS);
    let n = next_power_of_two_steps(FORS_F_CALLS);
    let steps = thash_f_offload_steps_fold(
        seeded,
        fors_f,
        OffloadSharedContext::new(vec![], ctx.offload.clone()),
        ThashFBusRegion::ForsF,
        n,
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
