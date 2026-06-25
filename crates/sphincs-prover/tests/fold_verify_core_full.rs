//! Phase 2b/2c NeutronNova tests: full [`synthesize_verify_core`] inside [`FoldVerifyCoreCircuit`].
//!
//! # Background
//!
//! Phase 2a (`fold_verify_core_hash_message`) only runs `hash_message` in `C_core`. Phase 2b wires
//! the **entire** M2 verify pipeline (FORS + 7× hypertree + `root == PK.root`) via
//! [`VerifyCorePhase::Full`]. Phase 2c removed the separate `hm_expected` oracle — witness is built
//! via [`fold_verify_core_from_pqclean`] using `hm_mgf` only (no `hm_expected`, no `intermediate_roots`).
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
//! | `fold_verify_core_full_public_io_setup` | `setup` only | bound | yes | `#[ignore]` release |
//! | `fold_verify_core_full_public_io_smoke` | prove + verify | bound | yes | `#[ignore]` release |
//! | `fold_verify_core_full_trace_linked_setup` | `setup` only | `hash_message` span | no | `#[ignore]` release |
//! | `fold_verify_core_full_public_io_trace_linked_setup` | `setup` only | `hash_message` span | no | `#[ignore]` release |
//! | `fold_verify_core_full_public_io_trace_smoke` | prove + verify | bound | yes | `#[ignore]` release |
//! | `fold_verify_core_full_variable_public_mlen_trace_setup` | `setup` only | `hash_message` span | no | `#[ignore]` release |
//!
//! # Run commands
//!
//! See **`docs/VERIFY_CORE_TESTS.md`** §Tier D. Minimum shape check:
//!
//! ```bash
//! # Shape check (minimum recommended before touching Full)
//! cargo test -p sphincs-prover --features pqclean --release \
//!   --test fold_verify_core_full fold_verify_core_full_setup -- --ignored --nocapture
//!
//! # Full core + public_io setup
//! cargo test -p sphincs-prover --features pqclean --release \
//!   --test fold_verify_core_full fold_verify_core_full_public_io_setup -- --ignored --nocapture
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
    fold_and_prove, fold_verify_core_from_pqclean, hash_message_full_span_plain,
    hash_message_trace_inputs_from_kat, longest_chain_bound, padded_message, setup_with_proto,
    sig_r, verify_proof,
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

/// Full core + public IO (1033 scalars) — NeutronNova `setup` / equalize only.
///
/// ```bash
/// cargo test -p sphincs-prover --features pqclean --release \
///   --test fold_verify_core_full fold_verify_core_full_public_io_setup -- --ignored --nocapture
/// ```
#[test]
#[ignore = "full verify core + public_io setup is large; run with --release --ignored"]
fn fold_verify_core_full_public_io_setup() {
    use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
    use spartan2::traits::circuit::SpartanCircuit;

    let seed = [0x49u8; CRYPTO_SEEDBYTES];
    let msg = b"full core public io setup";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);
    let n = max_steps();
    let (_chain, steps, _old, links) = longest_chain_bound(&rows, n).expect("chain");
    let digests: Vec<_> = links.iter().map(|(l, _)| *l).collect();

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests).with_public_io();
    assert_eq!(
        core.public_values().expect("pv").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    let (_pk_fold, _vk) = setup_with_proto(&steps[0], &core, steps.len());
    eprintln!("full public_io setup ok: steps={n}");
}

/// Full core + public IO — end-to-end prove + verify (bound steps).
///
/// ```bash
/// cargo test -p sphincs-prover --features pqclean --release \
///   --test fold_verify_core_full fold_verify_core_full_public_io_smoke -- --ignored --nocapture
/// ```
#[test]
#[ignore = "full verify core + public_io prove is large; run with --release --ignored"]
fn fold_verify_core_full_public_io_smoke() {
    use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
    use spartan2::traits::circuit::SpartanCircuit;

    let seed = [0x4au8; CRYPTO_SEEDBYTES];
    let msg = b"full core public io smoke prove verify";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);
    let n = max_steps();
    let (chain, steps, _old, links) = longest_chain_bound(&rows, n).expect("chain");
    let digests: Vec<_> = links.iter().map(|(l, _)| *l).collect();

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests).with_public_io();
    assert_eq!(
        core.public_values().expect("pv").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// Full core + trace-linked `hash_message` — NeutronNova `setup` / equalize only.
#[test]
#[ignore = "full verify core + trace setup is large; run with --release --ignored"]
fn fold_verify_core_full_trace_linked_setup() {
    use spartan2::neutronnova_zk::NeutronNovaZkSNARK;
    use sphincs_prover::E;

    let seed = [0x4bu8; CRYPTO_SEEDBYTES];
    let msg = b"span";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (_message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let (_span, steps, trace_inputs) =
        hash_message_full_span_plain(&rows, &r, &pk, mlen).expect("hash_message span");

    let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![])
        .with_hash_message_trace(trace_inputs);

    NeutronNovaZkSNARK::<E>::setup(&steps[0], &core, steps.len()).expect("setup");
}

/// Full core + `public_io` + trace-linked `hash_message` — `setup` only.
#[test]
#[ignore = "full verify core + public_io + trace setup is large; run with --release --ignored"]
fn fold_verify_core_full_public_io_trace_linked_setup() {
    use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
    use spartan2::traits::circuit::SpartanCircuit;

    let seed = [0x4cu8; CRYPTO_SEEDBYTES];
    let msg = b"span";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (_message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let (_span, steps, trace_inputs) =
        hash_message_full_span_plain(&rows, &r, &pk, mlen).expect("hash_message span");

    let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![])
        .with_hash_message_trace(trace_inputs)
        .with_public_io();
    assert_eq!(
        core.public_values().expect("pv").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    let (_pk_fold, _vk) = setup_with_proto(&steps[0], &core, steps.len());
    eprintln!("full public_io trace setup ok: steps={}", steps.len());
}

/// Full core + `public_io` + trace — end-to-end prove + verify.
#[test]
#[ignore = "full verify core + public_io + trace prove is large; run with --release --ignored"]
fn fold_verify_core_full_public_io_trace_smoke() {
    use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
    use spartan2::traits::circuit::SpartanCircuit;

    let seed = [0x4du8; CRYPTO_SEEDBYTES];
    let msg = b"full core public io trace smoke";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let n = max_steps();
    let (_chain, steps, _old, links) = longest_chain_bound(&rows, n).expect("chain");
    let digests: Vec<_> = links.iter().map(|(l, _)| *l).collect();

    let trace_inputs =
        hash_message_trace_inputs_from_kat(&rows, &pk, &sig, msg).expect("hash_message trace");

    let core = fold_verify_core_from_pqclean(pk, sig, msg, digests)
        .with_hash_message_trace(trace_inputs)
        .with_public_io();

    assert_eq!(
        core.public_values().expect("pv").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    let (pk_fold, vk) = setup_with_proto(&steps[0], &core, steps.len());
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, steps.len());
}

/// Full core + variable public `mlen` + trace — `setup` only.
#[test]
#[ignore = "full verify core variable mlen + trace setup is large; run with --release --ignored"]
fn fold_verify_core_full_variable_public_mlen_trace_setup() {
    use circuit_spec::VERIFY_PUBLIC_NUM_SCALARS;
    use spartan2::traits::circuit::SpartanCircuit;

    let seed = [0x4eu8; CRYPTO_SEEDBYTES];
    let msg = b"span";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    let rows = compressions_spec(&trace);

    let (_message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let (_span, steps, trace_inputs) =
        hash_message_full_span_plain(&rows, &r, &pk, mlen).expect("hash_message span");

    let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![])
        .with_hash_message_trace(trace_inputs)
        .with_public_io()
        .with_variable_public_mlen();
    assert_eq!(
        core.public_values().expect("pv").len(),
        VERIFY_PUBLIC_NUM_SCALARS
    );

    let (_pk_fold, _vk) = setup_with_proto(&steps[0], &core, steps.len());
    eprintln!("full variable public mlen trace setup ok");
}
