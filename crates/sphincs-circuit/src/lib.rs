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
pub mod hash_message_trace;
pub mod hypertree;
pub mod merkle;
pub mod satcheck;
pub mod sha256_compress;
pub mod step;
pub mod thash;
pub mod thash_link;
pub mod verify;
pub mod verify_public_io;
pub mod witness;
pub mod wots;

pub use chain::{enforce_sha256_words_equal, synthesize_sha256_state_equal};
pub use sha256_compress::synthesize_compression_chain_for_fold;
pub use fors::{
    fors_pk_bus_values, fors_pk_from_sig_bits, fors_pk_from_sig_bits_linked, message_to_indices,
    synthesize_fors_pk_from_sig, FORS_F_CALLS, FORS_H_CALLS, SPX_FORS_BYTES, SPX_FORS_MSG_BYTES,
    SPX_FORS_TREES,
};
/// `hash_message` gadgets and Phase 2c parse helpers (`parse_mgf_output`, `synthesize_hash_message_parsed`).
pub use hash_msg::{
    enforce_public_mlen_seed_path, hash_message_bits_from_public_muxed,
    hash_message_compression_budget, hash_message_first_block_message_bytes,
    hash_message_mgf_buf, hash_message_native, hash_message_output_from_mgf_bits,
    hash_message_seed_hash_native, hash_message_seed_hash_native_long, hash_message_seed_path,
    hash_message_tail_message_bytes, parse_mgf_output, synthesize_hash_message,
    synthesize_hash_message_parsed, synthesize_hash_message_parsed_public, HashMessageOutput,
    HashMessageSeedPath, SPX_DGST_BYTES, HASH_MESSAGE_INBUF_BYTES, HASH_MESSAGE_PREFIX_BYTES,
};
pub use hash_message_trace::{
    hash_message_compression_count_exact, hash_message_mgf1_compression_count,
    hash_message_seed_compression_count, locate_hash_message_trace_span,
    locate_hash_message_trace_span_for_mlen, sha256_compression_count_fresh,
    synthesize_hash_message_with_seed_trace, synthesize_hash_message_with_trace,
    synthesize_hash_message_parsed_with_trace,
    HashMessageTraceInputs, HashMessageTraceSpan,
};
pub use hypertree::{
    hypertree_layer_bits, hypertree_layer_from_root_bits, hypertree_layer_from_root_bits_linked,
    hypertree_layer_from_root_bits_offloaded, synthesize_hypertree_layer, SPX_TREE_HEIGHT,
};
pub use merkle::{
    addr_with_height_index, compute_root_bits, compute_root_bits_linked, compute_root_h_bus_values,
    synthesize_compute_root,
};
pub use shared_link::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_cond_link_eq_u32,
    enforce_words_eq_shared, link_shared_slice, one_hot_select, u32_words_from_shared, DIGEST_WORDS,
};
pub use sha256_compress::{
    synthesize_compression, synthesize_compression_chain_for_fold_with_links,
    synthesize_compression_chain_for_fold_with_shared, synthesize_compression_trace_row_for_fold, synthesize_compression_for_fold_h_words,
    synthesize_compression_for_fold_with_out, synthesize_compression_with_stats, StepStats,
};
pub use chain::enforce_digest_bytes_eq_words;
pub use step::{StepCircuit, StepInput};
pub use thash::{
    enforce_bits_equal_bytes, synthesize_thash, synthesize_thash_with_stats, thash_digest_bits,
    thash_preimage, witness_bytes_from_bits, ThashStats,
};
pub use thash_link::{
    alloc_thash_f_bus, alloc_thash_f_slot, alloc_thash_h_bus, alloc_thash_h_slot,
    enforce_num_eq_be_bits, gen_chain_linked, scalar_from_be_bytes, seeded_state, thash_f_block,
    thash_f_chain_bus_values, thash_f_core_link, thash_f_full_digest, thash_f_out, thash_f_step,
    thash_f_step_values, thash_h_block, thash_h_core_link, thash_h_out, thash_h_step,
    thash_h_step_values, ThashFBusValue, ThashHBusValue, F_PREIMAGE_BYTES, H_PREIMAGE_BYTES,
    THASH_F_SLOT_LEN, THASH_H_SLOT_LEN,
};
pub use verify::{
    enforce_message_padding, enforce_message_padding_witness, synthesize_verify_core,
    synthesize_verify_core_offloaded, synthesize_verify_core_public,
    synthesize_verify_core_public_with_trace, synthesize_verify_core_with_trace,
    synthesize_verify_core_wots_linked, verify_core_fors_f_bus_len, verify_core_fors_h_bus_len,
    verify_core_hypertree_h_bus_len, verify_core_wots_bus_len, VerifyCoreBuses, SPX_D,
    SIG_AFTER_FORS, SIG_R_BYTES, SPX_ADDR_TYPE_HASHTREE, SPX_ADDR_TYPE_WOTS, SPX_ADDR_TYPE_WOTSPK,
};
pub use verify_public_io::{
    enforce_public_inactive_chunks_zero, enforce_public_inactive_chunks_zero_variable,
    enforce_public_matches_pk_message, enforce_public_matches_statement,
    enforce_public_mlen_in_range, inputize_verify_public, pack_verify_public,
    public_message_bits_for_mlen, public_message_sha_bits, public_mlen_as_u32,
    public_mlen_geq_constant, public_mlen_is_short_path, public_pk_sha_bits,
    InputizedVerifyPublic,
};
pub use witness::{
    local_chain_segments, step_input_from_row, trace_stats, witness_from_compressions,
    LocalChain, TraceStats,
};
pub use wots::{
    chain_lengths, gen_chain, synthesize_wots_pk_from_sig, wots_pk_bus_values,
    wots_pk_from_sig_bits, wots_pk_from_sig_bits_linked, wots_pk_from_sig_root_bits,
    wots_pk_from_sig_root_bits_linked, wots_step_count, SPX_WOTS_BYTES, SPX_WOTS_LEN,
};
