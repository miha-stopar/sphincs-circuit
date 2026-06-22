//! NeutronNova fold + Spartan2 prove for SPHINCS+ verify (M3).
//!
//! ## Step vs core (two R1CS, one proof)
//!
//! Spartan2 NeutronNova always uses **two** circuit types:
//!
//! - **`C_step`** ([`FoldStepCircuit`]): one SHA-256 compression per instance; N instances are
//!   **folded** (NIFS) into `(U_fold, W_fold)`.
//! - **`C_core`** ([`FoldCoreCircuit`], [`FoldCoreChainCircuit`], …): **not** folded; its own
//!   `(U_core, W_core)` is built in parallel. The zk proof **batches** sum-checks over the folded
//!   step polynomials and the core polynomials (see [FOLDING.md §2.4](../../docs/FOLDING.md)).
//!
//! That batching is what “core + folding constraints combined” means in code. It does **not** by
//! itself equate step compression wires to core witnesses — use [`SpartanCircuit::shared`] for that
//! ([`FoldStepBoundCircuit`] / [`FoldCoreBoundCircuit`], or [`FoldVerifyCoreCircuit`] for real
//! SPHINCS+ glue), or pack glue into one step ([`FoldPackedChainCircuit`],
//! [`FoldPackedCoreBoundCircuit`]).
//!
//! **Demo (split):** `cargo test -p sphincs-prover --features pqclean --test fold_split_step_core`

mod bound;
mod core;
mod fold;
mod packed;
mod trace;
mod verify_core;

pub use bound::{
    bound_steps_from_inputs, FoldCoreBoundCircuit, FoldPackedCoreBoundCircuit, FoldStepBoundCircuit,
};
pub use core::{FoldCoreChainCircuit, FoldCoreCircuit};
pub use verify_core::{FoldVerifyCoreCircuit, VerifyCorePhase, message_bytes, sig_r};
pub use fold::{
    fold_and_prove, fold_prove_verify_timed, setup, setup_with_default_core, setup_with_proto,
    verify_proof, FoldProof, FoldProverKey, FoldStepCircuit, FoldVerifierKey, ProveTimings,
};
pub use packed::FoldPackedChainCircuit;
pub use trace::{
    chain_boundary_links, fold_steps_from_rows, fold_steps_prefix, link_digests_from_boundary,
    longest_chain_bound, longest_chain_packed, longest_chain_prefix, longest_local_chain,
    packed_chains_from_trace, pad_steps_to_power_of_two,
};
