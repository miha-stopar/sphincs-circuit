//! NeutronNova fold + Spartan2 prove for SPHINCS+ verify (M3).
//!
//! Track A split:
//! - **Step circuit** (`FoldStepCircuit`): one PQClean trace compression row.
//! - **Packed step** ([`FoldPackedChainCircuit`]): `N` compressions, sound `h_out→h_in` wires.
//! - **Core circuit** (`FoldCoreCircuit` / [`FoldCoreChainCircuit`]): SPHINCS+ glue.
//!
//! ## Shared witness (Spartan2)
//!
//! All prover circuits return **no** variables from [`SpartanCircuit::shared`] (`Ok(vec![])`).
//! Witness layout is therefore:
//!
//! ```text
//! W = [ shared (empty) | precommitted (compress + inputize) | rest (empty) ]
//! ```
//!
//! NeutronNova still runs `shared_witness` from `step_circuits[0]` (required by Spartan2), but
//! `num_shared = 0` — nothing is shared across instances or with the core. Chain linking is
//! either in-circuit ([`FoldPackedChainCircuit`]) or duplicated trace bytes in
//! [`FoldCoreChainCircuit`] (not yet bound to step wires). Future M3: allocate PK/σ endpoints
//! in `shared` once we link fold IO to the core.

mod core;
mod fold;
mod packed;
mod trace;

pub use core::{FoldCoreChainCircuit, FoldCoreCircuit};
pub use fold::{
    fold_and_prove, fold_prove_verify_timed, setup, setup_with_default_core, setup_with_proto,
    verify_proof, FoldProof, FoldProverKey, FoldStepCircuit, FoldVerifierKey, ProveTimings,
};
pub use packed::FoldPackedChainCircuit;
pub use trace::{
    chain_boundary_links, fold_steps_from_rows, fold_steps_prefix, longest_chain_packed,
    longest_chain_prefix, longest_local_chain, packed_chains_from_trace,
    pad_steps_to_power_of_two,
};
