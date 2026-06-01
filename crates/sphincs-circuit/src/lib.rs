//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1:** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **M2 (current):** full verify core sub-gadgets + top-level glue in `verify`.
//! **Next:** NeutronNova fold, Spartan2 prove, end-to-end witness vs trace diff.

pub mod fors;
pub mod hash_msg;
pub mod hypertree;
pub mod merkle;
pub mod sha256_compress;
pub mod step;
pub mod thash;
pub mod verify;
pub mod wots;

pub use fors::{
    fors_pk_from_sig_bits, message_to_indices, synthesize_fors_pk_from_sig, SPX_FORS_BYTES,
    SPX_FORS_MSG_BYTES, SPX_FORS_TREES,
};
pub use hash_msg::{
    hash_message_mgf_buf, hash_message_native, synthesize_hash_message, HashMessageOutput,
    SPX_DGST_BYTES,
};
pub use hypertree::{
    hypertree_layer_bits, hypertree_layer_from_root_bits, synthesize_hypertree_layer,
    SPX_TREE_HEIGHT,
};
pub use merkle::{compute_root_bits, synthesize_compute_root};
pub use sha256_compress::{synthesize_compression, synthesize_compression_with_stats, StepStats};
pub use step::{StepCircuit, StepInput};
pub use thash::{
    enforce_bits_equal_bytes, synthesize_thash, synthesize_thash_with_stats, thash_digest_bits,
    thash_preimage, ThashStats,
};
pub use verify::synthesize_verify_core;
pub use wots::{
    chain_lengths, gen_chain, synthesize_wots_pk_from_sig, wots_pk_from_sig_bits, SPX_WOTS_BYTES,
    SPX_WOTS_LEN,
};
