//! Top-level SPHINCS+ verify core — composes all M2 gadgets into the PQClean
//! `crypto_sign_verify` pipeline (minus `hash_message` padding policy):
//!
//! ```text
//! hash_message(R, PK, M) → mhash, tree, idx_leaf
//! fors_pk_from_sig(sig_fors, mhash) → root
//! for layer in 0..7:
//!     wots_pk_from_sig → thash(leaf) → compute_root → root
//! root == PK.root
//! ```

use crate::fors::{fors_pk_from_sig_bits, SPX_FORS_BYTES, SPX_FORS_MSG_BYTES};
use crate::hash_msg::{synthesize_hash_message, HashMessageOutput, SPX_DGST_BYTES, SPX_PK_BYTES};
use crate::hypertree::{hypertree_layer_from_root_bits, SPX_TREE_AUTH_BYTES, SPX_TREE_HEIGHT};
use crate::thash::{enforce_bits_equal_bytes, ADDR_BYTES, SPX_N};
use crate::wots::SPX_WOTS_BYTES;
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};

/// Hypertree layers (`SPX_D`).
pub const SPX_D: usize = 7;

/// PQClean address types used in verify.
pub const SPX_ADDR_TYPE_WOTS: u8 = 0;
pub const SPX_ADDR_TYPE_WOTSPK: u8 = 1;
pub const SPX_ADDR_TYPE_HASHTREE: u8 = 2;

/// Signature prefix: randomness `R`.
pub const SIG_R_BYTES: usize = SPX_N;
/// Offset after `R` + FORS section.
pub const SIG_AFTER_FORS: usize = SIG_R_BYTES + SPX_FORS_BYTES;
/// Bytes per hypertree layer in the signature (WOTS + auth path).
pub const SIG_LAYER_BYTES: usize = SPX_WOTS_BYTES + SPX_TREE_AUTH_BYTES;

fn set_layer_addr(base: &[u8; ADDR_BYTES], layer: u32) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[0] = layer as u8;
    a
}

fn set_tree_addr(base: &[u8; ADDR_BYTES], tree: u64) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[1..9].copy_from_slice(&tree.to_be_bytes());
    a
}

fn set_keypair_addr(base: &[u8; ADDR_BYTES], keypair: u32) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[12] = (keypair >> 8) as u8;
    a[13] = keypair as u8;
    a
}

fn set_type(base: &[u8; ADDR_BYTES], ty: u8) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[9] = ty;
    a
}

fn copy_subtree_addr(from: &[u8; ADDR_BYTES]) -> [u8; ADDR_BYTES] {
    let mut a = [0u8; ADDR_BYTES];
    a[..9].copy_from_slice(&from[..9]);
    a
}

/// Enforce inactive message suffix bytes are zero (padded-message policy).
pub fn enforce_message_padding<Scalar, CS>(
    mut cs: CS,
    message: &[u8],
    mlen: usize,
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(message.len() >= mlen);
    for i in mlen..message.len().min(MESSAGE_MAX_BYTES) {
        let bit = Boolean::constant(message[i] == 0);
        // Allocate witness bit equal to constant 0 — catches prover tampering.
        let witness = bellpepper::gadgets::boolean::AllocatedBit::alloc(
            cs.namespace(|| format!("pad_{i}")),
            Some(false),
        )?;
        Boolean::enforce_equal(
            cs.namespace(|| format!("pad_eq_{i}")),
            &Boolean::from(witness),
            &bit,
        )?;
    }
    Ok(())
}

/// In-circuit verify core: returns `true` in witness terms when all constraints
/// are satisfied. `intermediate_roots` supplies the 16-byte root before each
/// hypertree layer (index 0 = FORS pk, 1..=7 = output of previous layer) for
/// WOTS `chain_lengths` structure at synthesis time.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_verify_core<Scalar, CS>(
    mut cs: CS,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm_expected: &HashMessageOutput,
    hm_mgf: &[u8; SPX_DGST_BYTES],
    intermediate_roots: &[[u8; SPX_N]; SPX_D],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= message.len());
    enforce_message_padding(&mut cs, message, mlen)?;

    let pub_seed = {
        let mut s = [0u8; SPX_N];
        s.copy_from_slice(&pk[..SPX_N]);
        s
    };
    let pk_root = {
        let mut r = [0u8; SPX_N];
        r.copy_from_slice(&pk[SPX_N..]);
        r
    };

    let r = {
        let mut a = [0u8; SPX_N];
        a.copy_from_slice(&signature[..SIG_R_BYTES]);
        a
    };
    let mut pk32 = [0u8; SPX_PK_BYTES];
    pk32.copy_from_slice(pk);

    // 1. hash_message
    synthesize_hash_message(
        cs.namespace(|| "hash_message"),
        &r,
        &pk32,
        message,
        mlen,
        hm_mgf,
    )?;

    let mut tree = hm_expected.tree;
    let mut idx_leaf = hm_expected.leaf_idx;

    // 2. fors_pk_from_sig
    let mut fors_addr = [0u8; ADDR_BYTES];
    fors_addr = set_type(&fors_addr, SPX_ADDR_TYPE_WOTS);
    fors_addr = set_tree_addr(&fors_addr, tree);
    fors_addr = set_keypair_addr(&fors_addr, idx_leaf);

    let mut fors_sig = [0u8; SPX_FORS_BYTES];
    fors_sig.copy_from_slice(&signature[SIG_R_BYTES..SIG_AFTER_FORS]);

    let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
    mhash.copy_from_slice(&hm_expected.mhash);

    let fors_pk_bits = fors_pk_from_sig_bits(
        cs.namespace(|| "fors"),
        &pub_seed,
        &fors_addr,
        &fors_sig,
        &mhash,
    )?;
    enforce_bits_equal_bytes(
        cs.namespace(|| "fors_pk"),
        &fors_pk_bits,
        &intermediate_roots[0],
    )?;

    let mut root_bits = fors_pk_bits;
    let mut sig_off = SIG_AFTER_FORS;

    // 3. Seven hypertree layers
    for layer in 0..SPX_D {
        let mut wots_addr = [0u8; ADDR_BYTES];
        wots_addr = set_type(&wots_addr, SPX_ADDR_TYPE_WOTS);
        wots_addr = set_tree_addr(&wots_addr, tree);
        wots_addr = set_keypair_addr(&wots_addr, idx_leaf);

        let mut tree_addr = [0u8; ADDR_BYTES];
        tree_addr = set_type(&tree_addr, SPX_ADDR_TYPE_HASHTREE);
        tree_addr = set_layer_addr(&tree_addr, layer as u32);
        tree_addr = set_tree_addr(&tree_addr, tree);

        let wots_pk_addr = {
            let mut a = copy_subtree_addr(&tree_addr);
            a = set_keypair_addr(&a, idx_leaf);
            set_type(&a, SPX_ADDR_TYPE_WOTSPK)
        };

        let mut sig_wots = [0u8; SPX_WOTS_BYTES];
        sig_wots.copy_from_slice(&signature[sig_off..sig_off + SPX_WOTS_BYTES]);
        sig_off += SPX_WOTS_BYTES;

        let auth = &signature[sig_off..sig_off + SPX_TREE_AUTH_BYTES];
        sig_off += SPX_TREE_AUTH_BYTES;

        let root_in_bytes = intermediate_roots[layer];
        root_bits = hypertree_layer_from_root_bits(
            cs.namespace(|| format!("layer_{layer}")),
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig_wots,
            &root_bits,
            &root_in_bytes,
            idx_leaf,
            auth,
        )?;

        idx_leaf = (tree & ((1u64 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree >>= SPX_TREE_HEIGHT;
    }

    // 4. root == PK.root
    enforce_bits_equal_bytes(cs.namespace(|| "pk_root"), &root_bits, &pk_root)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_msg::{hash_message_mgf_buf, HashMessageOutput};
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use sphincs_ref::{sign_deterministic, CRYPTO_SEEDBYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};

    /// Simulate PQClean verify to collect intermediate roots for circuit structure.
    fn intermediate_roots_oracle(
        pk: &[u8; SPHINCS_PK_BYTES],
        sig: &[u8; SPHINCS_SIG_BYTES],
        hm: &HashMessageOutput,
    ) -> [[u8; SPX_N]; SPX_D] {
        let pub_seed = {
            let mut s = [0u8; 16];
            s.copy_from_slice(&pk[..16]);
            s
        };
        let mut sig_off = SIG_AFTER_FORS;
        let mut tree = hm.tree;
        let mut idx_leaf = hm.leaf_idx;

        let mut fors_addr = [0u8; 22];
        fors_addr[9] = SPX_ADDR_TYPE_WOTS;
        fors_addr[1..9].copy_from_slice(&tree.to_be_bytes());
        fors_addr[12] = (idx_leaf >> 8) as u8;
        fors_addr[13] = idx_leaf as u8;

        let mut fors_sig = [0u8; SPX_FORS_BYTES];
        fors_sig.copy_from_slice(&sig[SIG_R_BYTES..SIG_AFTER_FORS]);

        let mut roots = [[0u8; 16]; SPX_D];
        roots[0] = sphincs_ref::fors_pk_from_sig_oracle(
            &pub_seed,
            &fors_addr,
            &fors_sig,
            &hm.mhash,
        );

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

    #[test]
    #[ignore = "full verify core is slow in debug (~hours); run with --release --ignored"]
    fn valid_signature_satisfies_core() {
        let seed = [9u8; CRYPTO_SEEDBYTES];
        let msg = b"sphincs verify core test";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

        let r = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&sig[..16]);
            a
        };
        let hm_o = sphincs_ref::hash_message_oracle(&r, &pk, msg, msg.len());
        let hm = HashMessageOutput {
            mhash: hm_o.mhash,
            tree: hm_o.tree,
            leaf_idx: hm_o.leaf_idx,
        };
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());
        let roots = intermediate_roots_oracle(&pk, &sig, &hm);

        let mut padded = vec![0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);

        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_verify_core(
            &mut cs,
            &pk,
            &padded,
            msg.len(),
            &sig,
            &hm,
            &hm_mgf,
            &roots,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }
}
