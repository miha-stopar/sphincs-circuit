//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1:** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **M2 (current):** `thash` gadget (domain-separated hash) + `compute_root`
//!   gadget (Merkle path), both validated bit-for-bit against PQClean. These are
//!   the shared building blocks of FORS, WOTS+, and the hypertree.
//! **Next:** FORS / WOTS gadgets, top-level verify glue, NeutronNova fold, Spartan2 prove.

pub mod merkle;
pub mod sha256_compress;
pub mod step;
pub mod thash;

pub use merkle::synthesize_compute_root;
pub use sha256_compress::{synthesize_compression, synthesize_compression_with_stats, StepStats};
pub use step::{StepCircuit, StepInput};
pub use thash::{
    synthesize_thash, synthesize_thash_with_stats, thash_digest_bits, thash_preimage, ThashStats,
};
