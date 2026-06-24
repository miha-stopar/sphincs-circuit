//! Phase 2b/2c NeutronNova tests: full [`synthesize_verify_core`] inside [`FoldVerifyCoreCircuit`].
//!
//! # Background
//!
//! Phase 2a (`fold_verify_core_hash_message`) only runs `hash_message` in `C_core`. Phase 2b wires
//! the **entire** M2 verify pipeline (FORS + 7× hypertree + `root == PK.root`) via
//! [`VerifyCorePhase::Full`]. Phase 2c removed the separate `hm_expected` oracle — witness is built
//! via [`fold_verify_core_from_pqclean`] using `hm_mgf` + `parse_mgf_output` + `intermediate_roots_oracle`.
//!
//! **Design doc:** `docs/VERIFY_CORE.md`
//!
//! # Test matrix
//!
//! | Test | NeutronNova stage | Steps | Shared links | CI default |
//! |------|-------------------|-------|--------------|------------|
//! | `fold_verify_core_full_setup` | `setup` only (R1CS shape + equalize) | bound (`FOLD_VERIFY_CORE_STEPS`, default 4) | yes | `#[ignore]` ~7 min release |
//! | `fold_verify_core_full_prep_prove` | `prep_prove` (witness gen) | bound | yes | `#[ignore]` |
//! | `fold_verify_core_full_smoke` | prove + verify | bound | yes | `#[ignore]` |
//! | `fold_verify_core_full_plain_steps` | prove + verify | plain `FoldStepCircuit` | no | `#[ignore]` |
//!
//! # Run commands
//!
//! ```bash
//! # Shape check (minimum recommended before touching Full)
//! cargo test -p sphincs-prover --features pqclean --release \
//!   --test fold_verify_core_full fold_verify_core_full_setup -- --ignored --nocapture
//!
//! # Full suite (slow)
//! cargo test -p sphincs-prover --features pqclean --release \
//!   --test fold_verify_core_full -- --ignored --nocapture
//! ```
//!
//! # Environment
//!
//! - `FOLD_VERIFY_CORE_STEPS` — power-of-two step count for bound tests (default `4`).

#![cfg(feature = "pqclean")]

use circuit_spec::Sha256Compression;
use sphincs_prover::{
    fold_and_prove, fold_verify_core_from_pqclean, longest_chain_bound, setup_with_proto,
    verify_proof,
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

/// NeutronNova `setup` for full verify core — synthesizes `S_step` + `S_core`, runs `equalize`.
///
/// Confirms the full M2 gadget compiles into an R1CS shape compatible with folded steps.
/// Does **not** generate witnesses (faster than `prep_prove`, but still ~7 min in `--release`).
#[test]
#[ignore = "full verify core setup is slow (~7 min release); run with --release --ignored"]
fn fold_verify_core_full_setup() {
    use spartan2::neutronnova_zk::NeutronNovaZkSNARK;
    use sphincs_prover::E;

    let seed = [0x46u8; CRYPTO_SEEDBYTES];
    let msg = b"verify core full setup";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_steps();
    let (chain, steps, _old_core, links) =
        longest_chain_bound(&rows, n).expect("local chain with power-of-two prefix");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests);

    eprintln!(
        "verify-core full setup: steps={n} links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    NeutronNovaZkSNARK::<E>::setup(&steps[0], &core, steps.len()).expect("setup");
}

/// NeutronNova `prep_prove` — generates shared + precommitted witnesses for all instances.
///
/// Much slower than `setup`; aborted in debug after 10+ minutes in initial bring-up.
#[test]
#[ignore = "full verify core prep_prove is slow; run with --release --ignored"]
fn fold_verify_core_full_prep_prove() {
    use spartan2::neutronnova_zk::NeutronNovaZkSNARK;
    use sphincs_prover::E;

    let seed = [0x46u8; CRYPTO_SEEDBYTES];
    let msg = b"verify core full prep";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_steps();
    let (chain, steps, _old_core, links) =
        longest_chain_bound(&rows, n).expect("local chain with power-of-two prefix");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests);

    eprintln!(
        "verify-core full prep: steps={n} links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    let (pk_fold, _vk) = setup_with_proto(&steps[0], &core, steps.len());
    NeutronNovaZkSNARK::<E>::prep_prove(&pk_fold, &steps, &core, true).expect("prep_prove");
}

/// End-to-end: bound steps + full core → prove → verify.
#[test]
#[ignore = "full verify core is large; run with --release --ignored"]
fn fold_verify_core_full_smoke() {
    let seed = [0x47u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover verify core full smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_steps();
    let (chain, steps, _old_core, links) =
        longest_chain_bound(&rows, n).expect("local chain with power-of-two prefix");
    let digests: Vec<_> = links.iter().map(|(left, _)| *left).collect();

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests);

    eprintln!(
        "verify-core full smoke: steps={n} links={} trace indices {}..={}",
        links.len(),
        chain.start,
        chain.end
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// Full core with plain steps (empty `shared`) — isolates core gadget from link binding.
#[test]
#[ignore = "full verify core is large; run with --release --ignored"]
fn fold_verify_core_full_plain_steps() {
    let seed = [0x48u8; CRYPTO_SEEDBYTES];
    let msg = b"verify core full plain steps";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

    let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![]);

    use sphincs_prover::{fold_steps_prefix, pad_steps_to_power_of_two, setup_with_proto, FoldStepCircuit};
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);
    let mut steps: Vec<FoldStepCircuit> = fold_steps_prefix(&rows, 4);
    steps = pad_steps_to_power_of_two(steps);

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}
