//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1:** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **M2 (current):** full verify core sub-gadgets + top-level glue in `verify`.
//! **M2:** complete — verify core + trace witness alignment in `witness`.
//! **M3:** NeutronNova fold — [`FoldVerifyCoreCircuit`] in `sphincs-prover` (see `docs/VERIFY_CORE.md`).
//! **Phase 2c:** `hm_expected` removed — parse `mhash`/`tree`/`leaf_idx` from constrained `hm_mgf`
//! witness via [`synthesize_hash_message_parsed`] / [`parse_mgf_output`].
//! **Next:** full trace KAT, public IO, in-circuit address bit mux, `intermediate_roots` from witness.

pub mod chain;
pub mod shared_link;
pub mod fors;
pub mod hash_msg;
pub mod hypertree;
pub mod merkle;
pub mod sha256_compress;
pub mod step;
pub mod thash;
pub mod verify;
pub mod witness;
pub mod wots;

pub use chain::{enforce_sha256_words_equal, synthesize_sha256_state_equal};
pub use sha256_compress::synthesize_compression_chain_for_fold;
pub use fors::{
    fors_pk_from_sig_bits, message_to_indices, synthesize_fors_pk_from_sig, SPX_FORS_BYTES,
    SPX_FORS_MSG_BYTES, SPX_FORS_TREES,
};
/// `hash_message` gadgets and Phase 2c parse helpers (`parse_mgf_output`, `synthesize_hash_message_parsed`).
pub use hash_msg::{
    hash_message_mgf_buf, hash_message_native, hash_message_output_from_mgf_bits,
    parse_mgf_output, synthesize_hash_message, synthesize_hash_message_parsed, HashMessageOutput,
    SPX_DGST_BYTES,
};
pub use hypertree::{
    hypertree_layer_bits, hypertree_layer_from_root_bits, synthesize_hypertree_layer,
    SPX_TREE_HEIGHT,
};
pub use merkle::{compute_root_bits, synthesize_compute_root};
pub use shared_link::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_cond_link_eq_u32,
    enforce_words_eq_shared, link_shared_slice, one_hot_select, u32_words_from_shared, DIGEST_WORDS,
};
pub use sha256_compress::{
    synthesize_compression, synthesize_compression_chain_for_fold_with_links,
    synthesize_compression_for_fold_h_words, synthesize_compression_for_fold_with_out,
    synthesize_compression_with_stats, StepStats,
};
pub use chain::enforce_digest_bytes_eq_words;
pub use step::{StepCircuit, StepInput};
pub use thash::{
    enforce_bits_equal_bytes, synthesize_thash, synthesize_thash_with_stats, thash_digest_bits,
    thash_preimage, ThashStats,
};
pub use verify::{
    enforce_message_padding, enforce_message_padding_witness, synthesize_verify_core, SPX_D,
    SIG_AFTER_FORS, SIG_R_BYTES, SPX_ADDR_TYPE_HASHTREE, SPX_ADDR_TYPE_WOTS, SPX_ADDR_TYPE_WOTSPK,
};
pub use witness::{
    local_chain_segments, step_input_from_row, trace_stats, witness_from_compressions,
    LocalChain, TraceStats,
};
pub use wots::{
    chain_lengths, gen_chain, synthesize_wots_pk_from_sig, wots_pk_from_sig_bits, SPX_WOTS_BYTES,
    SPX_WOTS_LEN,
};
