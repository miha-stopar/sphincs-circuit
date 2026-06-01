//! NeutronNova fold + Spartan2 prove for SPHINCS+ verify (M3).
//!
//! Track A split:
//! - **Step circuit** (`FoldStepCircuit`): one PQClean trace compression row.
//! - **Core circuit** (`FoldCoreCircuit`): SPHINCS+ glue (verify core); stub until
//!   full `synthesize_verify_core` is ported to [`SpartanCircuit`].

mod fold;

pub use fold::{
    fold_and_prove, setup, setup_with_proto, verify_proof, FoldCoreCircuit, FoldProof,
    FoldProverKey, FoldStepCircuit, FoldVerifierKey,
};
