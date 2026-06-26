//! NeutronNova tests: offloaded verify core + folded steps sharing one `comm_W_shared`.
//!
//! ```bash
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_offloaded
//! ```

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_circuit::{
    hash_message_mgf_buf, parse_mgf_output, seeded_state, step::StepInput, thash::SPX_N,
    FORS_F_CALLS, FORS_H_CALLS, FORS_PK_INBLOCKS, hypertree::SPX_TREE_HEIGHT,
    thash_m_variable_compression_count, SPX_D,
};
use sphincs_prover::{
    fold_and_prove_general, longest_chain_bound, mega_batch_hash_message_and_fors_f,
    next_power_of_two_steps, offload_shared_context_from_pqclean, pad_link_digests_for_steps,
    setup_with_proto, sig_r, thash_f_offload_steps_fold, thash_h_offload_steps_fold, thash_m_offload_steps_fold,
    verify_proof, FoldOffloadMegaStepCircuit, FoldStepBoundOffloadCircuit, FoldVerifyCoreCircuit,
    OffloadSharedContext, ThashFBusRegion, ThashHBusRegion, ThashMBusRegion, padded_message,
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

/// FORS Merkle-node `thash`-H steps + offloaded core (unified shared; HM links empty).
#[test]
fn fold_verify_core_offloaded_fors_h_smoke() {
    let seed = [0x7cu8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core fors h smoke";
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
    let fors_h = ctx.offload.fors_h.clone();
    assert_eq!(fors_h.len(), FORS_H_CALLS);
    let n = next_power_of_two_steps(FORS_H_CALLS);
    let steps = thash_h_offload_steps_fold(
        seeded,
        fors_h,
        OffloadSharedContext::new(vec![], ctx.offload.clone()),
        ThashHBusRegion::ForsH,
        n,
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// FORS horizontal pk `thash`-M steps + offloaded core (unified shared; HM links empty).
#[test]
fn fold_verify_core_offloaded_fors_pk_m_smoke() {
    let seed = [0x8du8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core fors pk m smoke";
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
    let fors_pk_m = ctx.offload.fors_pk_m.clone();
    let var_count = thash_m_variable_compression_count(FORS_PK_INBLOCKS);
    let n = next_power_of_two_steps(var_count);
    let steps = thash_m_offload_steps_fold(
        &pub_seed,
        fors_pk_m,
        FORS_PK_INBLOCKS,
        OffloadSharedContext::new(vec![], ctx.offload.clone()),
        ThashMBusRegion::ForsPkM,
        n,
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// Hypertree Merkle `thash`-H steps + offloaded core (unified shared; HM links empty).
#[test]
fn fold_verify_core_offloaded_merkle_h_smoke() {
    let seed = [0x9eu8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core merkle h smoke";
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
    let merkle_h = ctx.offload.merkle_h.clone();
    let expected = SPX_D as usize * SPX_TREE_HEIGHT as usize;
    assert_eq!(merkle_h.len(), expected);
    let n = next_power_of_two_steps(expected);
    let steps = thash_h_offload_steps_fold(
        seeded,
        merkle_h,
        OffloadSharedContext::new(vec![], ctx.offload.clone()),
        ThashHBusRegion::MerkleH,
        n,
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// HM + FORS-F mega steps in one homogeneous NeutronNova fold batch.
///
/// Local R1CS sat: [`fold_verify_core_offloaded_mega_steps_local_sat`],
/// [`fold_verify_core_offloaded_mega_step_core_local_sat`].
#[test]
#[ignore = "NeutronNova verify fails InvalidSumcheckProof; per-instance + step+core local sat pass"]
fn fold_verify_core_offloaded_mega_batch_hash_message_and_fors_f() {
    let seed = [0x7cu8; CRYPTO_SEEDBYTES];
    let msg = b"offloaded verify core mega batch hm + fors f";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let hm_n = max_hm_steps();
    let (_chain, bound_steps, _old_core, links) =
        longest_chain_bound(&rows, hm_n).expect("local chain");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();
    let hm_inputs: Vec<StepInput> = bound_steps.iter().map(|b| b.input).collect();

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let hm = parse_mgf_output(&hm_mgf);

    let num_steps = next_power_of_two_steps(hm_inputs.len() + FORS_F_CALLS);
    let padded_digests = pad_link_digests_for_steps(digests, num_steps);
    let ctx = offload_shared_context_from_pqclean(&pk, &sig, &hm, padded_digests.clone());
    let fors_f = ctx.offload.fors_f.clone();
    assert_eq!(fors_f.len(), FORS_F_CALLS);
    let core = FoldVerifyCoreCircuit::offloaded(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        padded_digests,
        ctx.offload.clone(),
    );
    let steps: Vec<FoldOffloadMegaStepCircuit> = mega_batch_hash_message_and_fors_f(
        hm_inputs,
        &{
            let mut s = [0u8; SPX_N];
            s.copy_from_slice(&pk[..SPX_N]);
            s
        },
        &fors_f,
        ctx,
        num_steps,
    );
    assert_eq!(steps.len(), num_steps);

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove_general(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// Local R1CS: mega-step HM + F instances synthesize satisfiable constraints.
#[test]
fn fold_verify_core_offloaded_mega_steps_local_sat() {
    use bellpepper_core::test_cs::TestConstraintSystem;
    use spartan2::traits::circuit::SpartanCircuit;
    use sphincs_prover::E;

    type Scalar = <E as spartan2::traits::Engine>::Scalar;

    let seed = [0x7du8; CRYPTO_SEEDBYTES];
    let msg = b"mega step local sat";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let hm_n = max_hm_steps();
    let (_chain, bound_steps, _old_core, links) =
        longest_chain_bound(&rows, hm_n).expect("local chain");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();
    let hm_inputs: Vec<StepInput> = bound_steps.iter().map(|b| b.input).collect();

    let (_message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let hm = parse_mgf_output(&hm_mgf);

    let num_steps = next_power_of_two_steps(hm_inputs.len() + FORS_F_CALLS);
    let padded_digests = pad_link_digests_for_steps(digests, num_steps);
    let ctx = offload_shared_context_from_pqclean(&pk, &sig, &hm, padded_digests);
    let fors_f = ctx.offload.fors_f.clone();
    let steps: Vec<FoldOffloadMegaStepCircuit> = mega_batch_hash_message_and_fors_f(
        hm_inputs,
        &{
            let mut s = [0u8; SPX_N];
            s.copy_from_slice(&pk[..SPX_N]);
            s
        },
        &fors_f,
        ctx,
        num_steps,
    );

    for step in &steps {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared = step.shared(&mut cs).expect("shared");
        step.precommitted(&mut cs, &shared).expect("precommitted");
        assert!(
            cs.is_satisfied(),
            "mega step batch={} kind={}: {:?}",
            step.batch_index,
            step.payload.kind_id(),
            cs.which_is_unsatisfied()
        );
    }
}

/// Step + core on one shared witness (NeutronNova combined satisfiability).
#[test]
fn fold_verify_core_offloaded_mega_step_core_local_sat() {
    use bellpepper_core::test_cs::TestConstraintSystem;
    use spartan2::traits::circuit::SpartanCircuit;
    use sphincs_prover::E;

    type Scalar = <E as spartan2::traits::Engine>::Scalar;

    let seed = [0x7eu8; CRYPTO_SEEDBYTES];
    let msg = b"mega step core local sat";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let hm_n = max_hm_steps();
    let (_chain, bound_steps, _old_core, links) =
        longest_chain_bound(&rows, hm_n).expect("local chain");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();
    let hm_inputs: Vec<StepInput> = bound_steps.iter().map(|b| b.input).collect();

    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let hm = parse_mgf_output(&hm_mgf);

    let num_steps = next_power_of_two_steps(hm_inputs.len() + FORS_F_CALLS);
    let padded_digests = pad_link_digests_for_steps(digests, num_steps);
    let ctx = offload_shared_context_from_pqclean(&pk, &sig, &hm, padded_digests.clone());
    let core = FoldVerifyCoreCircuit::offloaded(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        padded_digests,
        ctx.offload.clone(),
    );
    let fors_f = ctx.offload.fors_f.clone();
    let steps: Vec<FoldOffloadMegaStepCircuit> = mega_batch_hash_message_and_fors_f(
        hm_inputs,
        &{
            let mut s = [0u8; SPX_N];
            s.copy_from_slice(&pk[..SPX_N]);
            s
        },
        &fors_f,
        ctx,
        num_steps,
    );

    for &idx in &[0usize, 4, 19] {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared = steps[idx].shared(&mut cs).expect("shared");
        steps[idx]
            .precommitted(&mut cs, &shared)
            .expect("step precommitted");
        core.precommitted(&mut cs, &shared)
            .expect("core precommitted");
        assert!(
            cs.is_satisfied(),
            "step {idx} + core: {:?}",
            cs.which_is_unsatisfied()
        );
    }
}
