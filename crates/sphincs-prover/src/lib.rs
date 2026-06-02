//! NeutronNova fold + Spartan2 prove for SPHINCS+ verify (M3).
//!
//! Track A split:
//! - **Step circuit** (`FoldStepCircuit`): one PQClean trace compression row.
//! - **Core circuit** (`FoldCoreCircuit` / [`FoldCoreChainCircuit`]): SPHINCS+ glue;
//!   chain boundaries today, full verify + fold IO later.

mod core;
mod fold;
mod trace;

pub use core::{FoldCoreChainCircuit, FoldCoreCircuit};
pub use fold::{
    fold_and_prove, setup, setup_with_default_core, setup_with_proto, verify_proof, FoldProof,
    FoldProverKey, FoldStepCircuit, FoldVerifierKey,
};
pub use trace::{
    chain_boundary_links, fold_steps_from_rows, longest_chain_prefix, longest_local_chain,
};
