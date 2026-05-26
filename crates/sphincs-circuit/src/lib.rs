//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1 (current):** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **Next:** core gadgets, NeutronNova fold, Spartan2 prove.

pub mod sha256_compress;
pub mod step;

pub use sha256_compress::{synthesize_compression, synthesize_compression_with_stats, StepStats};
pub use step::{StepCircuit, StepInput};
