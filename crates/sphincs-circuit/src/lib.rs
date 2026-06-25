//! Track A R1CS: SPHINCS+ verify via folded SHA-256 compression steps + core glue.
//!
//! **M1:** bit-accurate one-compression step (`C_step`) using bellpepper SHA-256.
//! **M2 (current):** full verify core sub-gadgets + top-level glue in `verify`.
//! **M2:** complete — verify core + trace witness alignment in `witness`.
//! **M3:** NeutronNova fold — [`FoldVerifyCoreCircuit`] in `sphincs-prover` (see `docs/VERIFY_CORE.md`).
//! **Phase 2c:** `hm_expected` removed; public `(mlen, PK, M)` via [`verify_public_io`].
//! **Next:** variable public `mlen`, full trace KAT, optional in-circuit address bit mux.

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
pub mod verify_public_io;
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
    hash_message_compression_budget, hash_message_first_block_message_bytes,
    hash_message_mgf_buf, hash_message_native, hash_message_output_from_mgf_bits,
    hash_message_seed_path, hash_message_tail_message_bytes, parse_mgf_output,
    synthesize_hash_message, synthesize_hash_message_parsed, synthesize_hash_message_parsed_public,
    HashMessageOutput, HashMessageSeedPath, SPX_DGST_BYTES, HASH_MESSAGE_INBUF_BYTES,
    HASH_MESSAGE_PREFIX_BYTES,
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
    thash_preimage, witness_bytes_from_bits, ThashStats,
};
pub use verify::{
    enforce_message_padding, enforce_message_padding_witness, synthesize_verify_core,
    synthesize_verify_core_public, SPX_D,
    SIG_AFTER_FORS, SIG_R_BYTES, SPX_ADDR_TYPE_HASHTREE, SPX_ADDR_TYPE_WOTS, SPX_ADDR_TYPE_WOTSPK,
};
pub use verify_public_io::{
    enforce_public_inactive_chunks_zero, enforce_public_matches_statement,
    enforce_public_mlen_in_range, inputize_verify_public, pack_verify_public,
    public_message_sha_bits, public_pk_sha_bits, public_mlen_as_u32, InputizedVerifyPublic,
};
pub use witness::{
    local_chain_segments, step_input_from_row, trace_stats, witness_from_compressions,
    LocalChain, TraceStats,
};
pub use wots::{
    chain_lengths, gen_chain, synthesize_wots_pk_from_sig, wots_pk_from_sig_bits,
    wots_pk_from_sig_root_bits, SPX_WOTS_BYTES, SPX_WOTS_LEN,
};
