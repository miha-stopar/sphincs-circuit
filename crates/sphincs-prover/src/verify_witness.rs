//! PQClean-derived witness for [`super::FoldVerifyCoreCircuit`] with [`super::VerifyCorePhase::Full`].
//!
//! # Role
//!
//! [`synthesize_verify_core`] needs:
//!
//! - `hm_mgf` — raw 30-byte MGF1 output (**enforced in R1CS**; `mhash`/`tree`/`leaf_idx` parsed from it)
//! - `signature`, `pk`, padded `message`, `mlen`
//!
//! WOTS `chain_lengths` follow witness `root_bits` inside the gadget — **no** `intermediate_roots` field.
//!
//! # Consistency requirements
//!
//! 1. `hm_mgf == hash_message_mgf_buf(r, pk, msg, mlen)`
//! 2. `link_digests[k]` = trace bytes at local-chain boundaries (when using bound steps)
//!
//! # Testing
//!
//! See **`docs/VERIFY_CORE_TESTS.md`** (quick start + full tier guide).
//!
//! ```bash
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message
//! cargo test -p sphincs-prover --features pqclean --release --test fold_verify_core_full \
//!   fold_verify_core_full_setup -- --ignored --nocapture
//! ```
//!
//! See **`docs/VERIFY_CORE.md`**.

use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};
use sphincs_circuit::{
    fors::fors_pk_bus_values,
    fors::SPX_FORS_BYTES,
    hash_message_mgf_buf, hash_msg::HashMessageOutput, hypertree::SPX_TREE_AUTH_BYTES,
    hypertree::SPX_TREE_HEIGHT, hypertree::wots_pk_leaf_m_bus_value,
    merkle::compute_root_h_bus_values, thash::SPX_N, thash_link::ThashMBusValue,
    wots::wots_pk_bus_values, VerifyCoreOffloadWitness,
    SPX_D, SPX_WOTS_BYTES, SPX_ADDR_TYPE_HASHTREE, SPX_ADDR_TYPE_WOTS, SPX_ADDR_TYPE_WOTSPK,
    SIG_AFTER_FORS, SIG_R_BYTES,
};

use crate::verify_core::{padded_message, sig_r, FoldVerifyCoreCircuit};

/// Replay PQClean verify to collect the 16-byte root **before** each hypertree layer.
///
/// **Debug / test helper only** — not required by [`FoldVerifyCoreCircuit::full`] anymore.
/// The circuit chains `root_bits` internally; this oracle is for cross-checking native replay.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-prover --features pqclean intermediate_roots_oracle -- --nocapture
/// ```
pub fn intermediate_roots_oracle(
    pk: &[u8; SPHINCS_PK_BYTES],
    sig: &[u8; SPHINCS_SIG_BYTES],
    hm: &HashMessageOutput,
) -> [[u8; SPX_N]; SPX_D] {
    use sphincs_circuit::hypertree::SPX_TREE_HEIGHT;

    let pub_seed = {
        let mut s = [0u8; SPX_N];
        s.copy_from_slice(&pk[..SPX_N]);
        s
    };
    let mut sig_off = SIG_AFTER_FORS;

    let tree = hm.tree;
    let idx_leaf = hm.leaf_idx;

    let mut fors_addr = [0u8; 22];
    fors_addr[9] = SPX_ADDR_TYPE_WOTS;
    fors_addr[1..9].copy_from_slice(&tree.to_be_bytes());
    fors_addr[12] = (idx_leaf >> 8) as u8;
    fors_addr[13] = idx_leaf as u8;

    let mut fors_sig = [0u8; SPX_FORS_BYTES];
    fors_sig.copy_from_slice(&sig[SIG_R_BYTES..SIG_AFTER_FORS]);

    let mut roots = [[0u8; SPX_N]; SPX_D];
    roots[0] = sphincs_ref::fors_pk_from_sig_oracle(&pub_seed, &fors_addr, &fors_sig, &hm.mhash);

    let mut root = roots[0];
    let mut tree = hm.tree;
    let mut idx_leaf = hm.leaf_idx;

    for layer in 0..SPX_D {
        roots[layer] = root;

        let mut wots_addr = [0u8; 22];
        wots_addr[9] = SPX_ADDR_TYPE_WOTS;
        wots_addr[1..9].copy_from_slice(&tree.to_be_bytes());
        wots_addr[12] = (idx_leaf >> 8) as u8;
        wots_addr[13] = idx_leaf as u8;

        let mut tree_addr = [0u8; 22];
        tree_addr[0] = layer as u8;
        tree_addr[1..9].copy_from_slice(&tree.to_be_bytes());
        tree_addr[9] = SPX_ADDR_TYPE_HASHTREE;

        let mut wots_pk_addr = [0u8; 22];
        wots_pk_addr[..9].copy_from_slice(&tree_addr[..9]);
        wots_pk_addr[12] = (idx_leaf >> 8) as u8;
        wots_pk_addr[13] = idx_leaf as u8;
        wots_pk_addr[9] = SPX_ADDR_TYPE_WOTSPK;

        let mut sig_wots = [0u8; SPX_WOTS_BYTES];
        sig_wots.copy_from_slice(&sig[sig_off..sig_off + SPX_WOTS_BYTES]);
        sig_off += SPX_WOTS_BYTES;

        let auth = &sig[sig_off..sig_off + SPX_TREE_AUTH_BYTES];
        sig_off += SPX_TREE_AUTH_BYTES;

        let wots_pk =
            sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &wots_addr, &sig_wots, &root);
        let leaf = sphincs_ref::thash_oracle(&pub_seed, &wots_pk_addr, &wots_pk);
        root = sphincs_ref::compute_root_oracle(
            &pub_seed,
            &tree_addr,
            &leaf,
            idx_leaf,
            0,
            auth,
            SPX_TREE_HEIGHT,
        );

        idx_leaf = (tree & ((1u64 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree >>= SPX_TREE_HEIGHT;
    }

    roots
}

/// Build a Phase Full [`FoldVerifyCoreCircuit`] from a PQClean KAT `(pk, sig, msg)`.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-prover --features pqclean --release --test fold_verify_core_full \
///   fold_verify_core_full_setup -- --ignored --nocapture
/// ```
pub fn fold_verify_core_from_pqclean(
    pk: [u8; SPHINCS_PK_BYTES],
    sig: [u8; SPHINCS_SIG_BYTES],
    msg: &[u8],
    link_digests: Vec<[u8; 32]>,
) -> FoldVerifyCoreCircuit {
    assert!(msg.len() <= MESSAGE_MAX_BYTES);
    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    FoldVerifyCoreCircuit::full(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        link_digests,
    )
}

/// Collect native offloaded `thash` bus values for a PQClean KAT (mirrors
/// `sphincs_circuit::verify::tests::valid_signature_satisfies_core_offloaded`).
#[cfg(feature = "pqclean")]
pub fn offload_witness_from_pqclean(
    pk: &[u8; SPHINCS_PK_BYTES],
    sig: &[u8; SPHINCS_SIG_BYTES],
    hm: &HashMessageOutput,
) -> VerifyCoreOffloadWitness {
    let pub_seed = {
        let mut s = [0u8; SPX_N];
        s.copy_from_slice(&pk[..SPX_N]);
        s
    };

    let mut tree = hm.tree;
    let mut idx_leaf = hm.leaf_idx;

    let mut fors_addr = [0u8; 22];
    fors_addr[9] = SPX_ADDR_TYPE_WOTS;
    fors_addr[1..9].copy_from_slice(&tree.to_be_bytes());
    fors_addr[12] = (idx_leaf >> 8) as u8;
    fors_addr[13] = idx_leaf as u8;

    let mut fors_sig = [0u8; SPX_FORS_BYTES];
    fors_sig.copy_from_slice(&sig[SIG_R_BYTES..SIG_AFTER_FORS]);

    let (fors_f, fors_h, fors_pk_m) =
        fors_pk_bus_values(&pub_seed, &fors_addr, &fors_sig, &hm.mhash);
    let mut root = sphincs_ref::fors_pk_from_sig_oracle(&pub_seed, &fors_addr, &fors_sig, &hm.mhash);

    let mut sig_off = SIG_AFTER_FORS;
    let mut wots = Vec::new();
    let mut wots_pk_m: Vec<ThashMBusValue> = Vec::new();
    let mut merkle_h = Vec::new();

    for layer in 0..SPX_D {
        let mut wots_addr = [0u8; 22];
        wots_addr[9] = SPX_ADDR_TYPE_WOTS;
        wots_addr[0] = layer as u8;
        wots_addr[1..9].copy_from_slice(&tree.to_be_bytes());
        wots_addr[12] = (idx_leaf >> 8) as u8;
        wots_addr[13] = idx_leaf as u8;

        let mut tree_addr = [0u8; 22];
        tree_addr[0] = layer as u8;
        tree_addr[1..9].copy_from_slice(&tree.to_be_bytes());
        tree_addr[9] = SPX_ADDR_TYPE_HASHTREE;

        let mut wots_pk_addr = [0u8; 22];
        wots_pk_addr[..9].copy_from_slice(&tree_addr[..9]);
        wots_pk_addr[12] = (idx_leaf >> 8) as u8;
        wots_pk_addr[13] = idx_leaf as u8;
        wots_pk_addr[9] = SPX_ADDR_TYPE_WOTSPK;

        let mut sig_wots = [0u8; SPX_WOTS_BYTES];
        sig_wots.copy_from_slice(&sig[sig_off..sig_off + SPX_WOTS_BYTES]);
        sig_off += SPX_WOTS_BYTES;
        let auth = &sig[sig_off..sig_off + SPX_TREE_AUTH_BYTES];
        sig_off += SPX_TREE_AUTH_BYTES;

        wots.extend(wots_pk_bus_values(&pub_seed, &wots_addr, &sig_wots, &root));

        let wots_pk =
            sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &wots_addr, &sig_wots, &root);
        wots_pk_m.push(wots_pk_leaf_m_bus_value(&pub_seed, &wots_pk_addr, &wots_pk));
        let leaf = sphincs_ref::thash_oracle(&pub_seed, &wots_pk_addr, &wots_pk);
        let (h_vals, layer_root) = compute_root_h_bus_values(
            &pub_seed, &tree_addr, &leaf, idx_leaf, 0, auth, SPX_TREE_HEIGHT,
        );
        merkle_h.extend(h_vals);
        root = layer_root;
        idx_leaf = (tree & ((1u64 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree >>= SPX_TREE_HEIGHT;
    }

    VerifyCoreOffloadWitness {
        fors_f,
        fors_h,
        fors_pk_m,
        wots,
        wots_pk_m,
        merkle_h,
    }
}

/// Build a Phase Offloaded [`FoldVerifyCoreCircuit`] from a PQClean KAT.
#[cfg(feature = "pqclean")]
pub fn fold_verify_core_offloaded_from_pqclean(
    pk: [u8; SPHINCS_PK_BYTES],
    sig: [u8; SPHINCS_SIG_BYTES],
    msg: &[u8],
    link_digests: Vec<[u8; 32]>,
    hm: &HashMessageOutput,
) -> FoldVerifyCoreCircuit {
    assert!(msg.len() <= MESSAGE_MAX_BYTES);
    let (message, mlen) = padded_message(msg);
    let r = sig_r(&sig);
    let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
    let offload = offload_witness_from_pqclean(&pk, &sig, hm);
    FoldVerifyCoreCircuit::offloaded(
        pk,
        message,
        mlen,
        sig,
        r,
        hm_mgf,
        link_digests,
        offload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sphincs_ref::{sign_deterministic, CRYPTO_SEEDBYTES};

    #[test]
    fn fold_verify_core_from_pqclean_builds_full_circuit() {
        let seed = [1u8; CRYPTO_SEEDBYTES];
        let msg = b"witness builder smoke";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![]);
        assert_eq!(core.phase, crate::verify_core::VerifyCorePhase::Full);
        assert!(core.signature.is_some());
        assert!(!core.public_io);
    }

    #[test]
    fn fold_verify_core_from_pqclean_with_public_io() {
        let seed = [2u8; CRYPTO_SEEDBYTES];
        let msg = b"witness builder public io";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![]).with_public_io();
        assert!(core.public_io);
        assert_eq!(core.phase, crate::verify_core::VerifyCorePhase::Full);
    }

    #[test]
    fn fold_verify_core_from_pqclean_with_hash_message_trace() {
        use circuit_spec::Sha256Compression;
        use sphincs_ref::verify_with_trace;

        let seed = [3u8; CRYPTO_SEEDBYTES];
        let msg = b"span";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let rows: Vec<Sha256Compression> = trace
            .compressions
            .iter()
            .map(|r| Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();
        let trace_inputs =
            crate::trace::hash_message_trace_inputs_from_kat(&rows, &pk, &sig, msg).expect("span");
        let core = fold_verify_core_from_pqclean(pk, sig, msg, vec![])
            .with_hash_message_trace(trace_inputs);
        assert!(core.hash_message_trace.is_some());
        assert_eq!(core.phase, crate::verify_core::VerifyCorePhase::Full);
    }
}
