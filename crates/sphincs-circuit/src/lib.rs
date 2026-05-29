//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1:** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **M2 (current):** `thash` gadget — the SPHINCS+ domain-separated hash used by
//!   FORS, WOTS+, and the Merkle trees; validated bit-for-bit against PQClean.
//! **Next:** FORS / WOTS / `compute_root` gadgets, NeutronNova fold, Spartan2 prove.

pub mod sha256_compress;
pub mod step;
pub mod thash;

pub use sha256_compress::{synthesize_compression, synthesize_compression_with_stats, StepStats};
pub use step::{StepCircuit, StepInput};
pub use thash::{synthesize_thash, synthesize_thash_with_stats, thash_preimage, ThashStats};
