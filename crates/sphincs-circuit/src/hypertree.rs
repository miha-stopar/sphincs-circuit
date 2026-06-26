//! One hypertree layer gadget — the inner loop of SPHINCS+ verification.
//!
//! For layer `i` in `0..SPX_D` (7 layers), PQClean `sign.c:crypto_sign_verify` does:
//!   1. `wots_pk_from_sig(wots_pk, sig, root, …)` — recover WOTS+ pk from sig,
//!      using the current `root` as the signed message (FORS pk on layer 0).
//!   2. `thash(leaf, wots_pk, SPX_WOTS_LEN=35, …)` — hash pk to a Merkle leaf.
//!   3. `compute_root(root, leaf, idx_leaf, 0, auth, SPX_TREE_HEIGHT=9, …)`.
//!
//! **WOTS topology:** `chain_lengths` are computed from witness root bits at synthesis
//! ([`crate::thash::witness_bytes_from_bits`]) — no separate `root_in_bytes` / `intermediate_roots`
//! hint parameter. Max-unroll in-circuit `chain_lengths` (topology independent of witness root)
//! remains future work — see `docs/CIRCUIT.md`.

use crate::merkle::{compute_root_bits, compute_root_bits_linked};
use crate::thash::{enforce_digest_equals, thash_digest_bits, ADDR_BYTES, SPX_N};
use crate::thash_link::{thash_m_bus_value, thash_m_bus_len, thash_m_core_link, ThashMBusValue, WOTS_PK_INBLOCKS};
use crate::wots::{wots_pk_from_sig_root_bits, wots_pk_from_sig_root_bits_linked, SPX_WOTS_BYTES};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};

/// Hypertree Merkle height (`SPX_TREE_HEIGHT`).
pub const SPX_TREE_HEIGHT: u32 = 9;
/// Hypertree auth-path bytes per layer.
pub const SPX_TREE_AUTH_BYTES: usize = SPX_TREE_HEIGHT as usize * SPX_N;

/// PQClean address type for the WOTS+ pk leaf hash.
pub const SPX_ADDR_TYPE_WOTSPK: u8 = 1;

/// Overlay `type` (offset 9) onto a copy of the base address.
fn addr_with_type(base: &[u8; ADDR_BYTES], ty: u8) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[9] = ty;
    a
}

/// In-circuit one hypertree layer: `root_in_bits` → WOTS recover → leaf thash → Merkle walk.
///
/// `root_in_bits` must be the 128-bit digest wires from the previous stage (FORS pk on layer 0,
/// prior layer output otherwise). WOTS [`chain_lengths`](crate::wots::chain_lengths) follow the
/// witness root bytes read from those bits at synthesis time.
#[allow(clippy::too_many_arguments)]
pub fn hypertree_layer_from_root_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    wots_addr: &[u8; ADDR_BYTES],
    wots_pk_addr: &[u8; ADDR_BYTES],
    tree_addr: &[u8; ADDR_BYTES],
    sig_wots: &[u8; SPX_WOTS_BYTES],
    root_in_bits: &[Boolean],
    idx_leaf: u32,
    auth_path: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let wots_pk_bits = wots_pk_from_sig_root_bits(
        cs.namespace(|| "wots"),
        pub_seed,
        wots_addr,
        sig_wots,
        root_in_bits,
    )?;

    let leaf_addr = addr_with_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
    let leaf_bits = thash_digest_bits(
        cs.namespace(|| "leaf"),
        pub_seed,
        &leaf_addr,
        &wots_pk_bits,
    )?;

    compute_root_bits(
        cs.namespace(|| "tree"),
        pub_seed,
        tree_addr,
        &leaf_bits,
        idx_leaf,
        0,
        auth_path,
        SPX_TREE_HEIGHT,
    )
}

/// Trace-linked [`hypertree_layer_from_root_bits`]: the WOTS chain `thash`-F steps
/// are offloaded to `wots_bus` (folded steps), while the leaf `thash` and Merkle
/// `compute_root` remain in-core (those families are offloaded in a later increment).
///
/// `wots_bus` must be sized for this layer's WOTS recovery
/// (`THASH_F_SLOT_LEN * wots_step_count(witness root)`).
#[allow(clippy::too_many_arguments)]
pub fn hypertree_layer_from_root_bits_linked<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    wots_addr: &[u8; ADDR_BYTES],
    wots_pk_addr: &[u8; ADDR_BYTES],
    tree_addr: &[u8; ADDR_BYTES],
    sig_wots: &[u8; SPX_WOTS_BYTES],
    root_in_bits: &[Boolean],
    idx_leaf: u32,
    auth_path: &[u8],
    wots_bus: &[AllocatedNum<Scalar>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let wots_pk_bits = wots_pk_from_sig_root_bits_linked(
        cs.namespace(|| "wots"),
        wots_addr,
        sig_wots,
        root_in_bits,
        wots_bus,
    )?;

    let leaf_addr = addr_with_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
    let leaf_bits = thash_digest_bits(
        cs.namespace(|| "leaf"),
        pub_seed,
        &leaf_addr,
        &wots_pk_bits,
    )?;

    compute_root_bits(
        cs.namespace(|| "tree"),
        pub_seed,
        tree_addr,
        &leaf_bits,
        idx_leaf,
        0,
        auth_path,
        SPX_TREE_HEIGHT,
    )
}

/// Native `thash`-M bus values for the WOTS-pk leaf hash of one hypertree layer.
pub fn wots_pk_leaf_m_bus_value(
    pub_seed: &[u8; SPX_N],
    wots_pk_addr: &[u8; ADDR_BYTES],
    wots_pk: &[u8; SPX_WOTS_BYTES],
) -> ThashMBusValue {
    thash_m_bus_value(pub_seed, wots_pk_addr, wots_pk)
}

/// Fully offloaded hypertree layer: WOTS chains (`wots_bus`), WOTS-pk leaf
/// `thash`-M (`wots_pk_m_bus`), and Merkle `H` levels (`merkle_h_bus`) are shared-bus
/// links to folded steps.
///
/// `wots_pk_m_bus` length = [`thash_m_bus_len`](crate::thash_link::thash_m_bus_len)(`WOTS_PK_INBLOCKS`).
#[allow(clippy::too_many_arguments)]
pub fn hypertree_layer_from_root_bits_offloaded<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    wots_addr: &[u8; ADDR_BYTES],
    wots_pk_addr: &[u8; ADDR_BYTES],
    tree_addr: &[u8; ADDR_BYTES],
    sig_wots: &[u8; SPX_WOTS_BYTES],
    root_in_bits: &[Boolean],
    idx_leaf: u32,
    auth_path: &[u8],
    wots_bus: &[AllocatedNum<Scalar>],
    wots_pk_m_bus: &[AllocatedNum<Scalar>],
    merkle_h_bus: &[AllocatedNum<Scalar>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(wots_pk_m_bus.len(), thash_m_bus_len(WOTS_PK_INBLOCKS));

    let wots_pk_bits = wots_pk_from_sig_root_bits_linked(
        cs.namespace(|| "wots"),
        wots_addr,
        sig_wots,
        root_in_bits,
        wots_bus,
    )?;

    let leaf_addr = addr_with_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
    let leaf_bits = thash_m_core_link(
        cs.namespace(|| "leaf"),
        &leaf_addr,
        &wots_pk_bits,
        WOTS_PK_INBLOCKS,
        wots_pk_m_bus,
    )?;

    compute_root_bits_linked(
        cs.namespace(|| "tree"),
        tree_addr,
        &leaf_bits,
        idx_leaf,
        0,
        auth_path,
        SPX_TREE_HEIGHT,
        merkle_h_bus,
    )
}

/// Like [`hypertree_layer_from_root_bits`] but allocates `root_in` from bytes.
#[allow(clippy::too_many_arguments)]
pub fn hypertree_layer_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    wots_addr: &[u8; ADDR_BYTES],
    wots_pk_addr: &[u8; ADDR_BYTES],
    tree_addr: &[u8; ADDR_BYTES],
    sig_wots: &[u8; SPX_WOTS_BYTES],
    root_in: &[u8; SPX_N],
    idx_leaf: u32,
    auth_path: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::thash::alloc_input_bits;

    let root_bits = alloc_input_bits(&mut cs, "root_in", root_in)?;
    hypertree_layer_from_root_bits(
        cs,
        pub_seed,
        wots_addr,
        wots_pk_addr,
        tree_addr,
        sig_wots,
        &root_bits,
        idx_leaf,
        auth_path,
    )
}

/// Synthesize one hypertree layer and enforce the output root equals `expected_root`.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_hypertree_layer<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    wots_addr: &[u8; ADDR_BYTES],
    wots_pk_addr: &[u8; ADDR_BYTES],
    tree_addr: &[u8; ADDR_BYTES],
    sig_wots: &[u8; SPX_WOTS_BYTES],
    root_in: &[u8; SPX_N],
    idx_leaf: u32,
    auth_path: &[u8],
    expected_root: &[u8; SPX_N],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let root_bits = hypertree_layer_bits(
        cs.namespace(|| "layer"),
        pub_seed,
        wots_addr,
        wots_pk_addr,
        tree_addr,
        sig_wots,
        root_in,
        idx_leaf,
        auth_path,
    )?;
    enforce_digest_equals(cs.namespace(|| "root_eq"), &root_bits, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    /// Expected root for one layer, composed from existing PQClean oracles.
    fn layer_oracle(
        pub_seed: &[u8; 16],
        wots_addr: &[u8; 22],
        wots_pk_addr: &[u8; 22],
        tree_addr: &[u8; 22],
        sig_wots: &[u8; SPX_WOTS_BYTES],
        root_in: &[u8; 16],
        idx_leaf: u32,
        auth: &[u8],
    ) -> [u8; 16] {
        let wots_pk = sphincs_ref::wots_pk_from_sig_oracle(pub_seed, wots_addr, sig_wots, root_in);
        let leaf = sphincs_ref::thash_oracle(pub_seed, wots_pk_addr, &wots_pk);
        sphincs_ref::compute_root_oracle(pub_seed, tree_addr, &leaf, idx_leaf, 0, auth, SPX_TREE_HEIGHT)
    }

    fn run(
        pub_seed: &[u8; 16],
        wots_addr: &[u8; 22],
        wots_pk_addr: &[u8; 22],
        tree_addr: &[u8; 22],
        sig_wots: &[u8; SPX_WOTS_BYTES],
        root_in: &[u8; 16],
        idx_leaf: u32,
        auth: &[u8],
        expected: &[u8; 16],
    ) -> bool {
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_hypertree_layer(
            &mut cs,
            pub_seed,
            wots_addr,
            wots_pk_addr,
            tree_addr,
            sig_wots,
            root_in,
            idx_leaf,
            auth,
            expected,
        )
        .expect("synth");
        cs.is_satisfied()
    }

    #[test]
    fn matches_composed_oracle() {
        let pub_seed = [0x51u8; 16];
        let mut wots_addr = [0u8; 22];
        wots_addr[9] = 0; // WOTS
        wots_addr[13] = 42;
        let mut wots_pk_addr = wots_addr;
        wots_pk_addr[9] = SPX_ADDR_TYPE_WOTSPK;
        let mut tree_addr = [0u8; 22];
        tree_addr[9] = 2; // HASHTREE
        let sig: Vec<u8> = (0..SPX_WOTS_BYTES).map(|i| (i % 251) as u8).collect();
        let sig: [u8; SPX_WOTS_BYTES] = sig.try_into().unwrap();
        let root_in = [0x99u8; 16];
        let auth: Vec<u8> = (0..SPX_TREE_AUTH_BYTES).map(|i| (255 - i) as u8).collect();

        let expected = layer_oracle(
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig,
            &root_in,
            7,
            &auth,
        );
        assert!(run(
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig,
            &root_in,
            7,
            &auth,
            &expected,
        ));
    }

    #[test]
    fn wrong_root_is_unsatisfiable() {
        let pub_seed = [0x12u8; 16];
        let wots_addr = [0u8; 22];
        let wots_pk_addr = {
            let mut a = wots_addr;
            a[9] = SPX_ADDR_TYPE_WOTSPK;
            a
        };
        let tree_addr = {
            let mut a = [0u8; 22];
            a[9] = 2;
            a
        };
        let sig = [0x55u8; SPX_WOTS_BYTES];
        let root_in = [0xffu8; 16]; // all-high → fast WOTS chains
        let auth = [0x33u8; SPX_TREE_AUTH_BYTES];

        let mut expected = layer_oracle(
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig,
            &root_in,
            0,
            &auth,
        );
        expected[0] ^= 1;
        assert!(!run(
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig,
            &root_in,
            0,
            &auth,
            &expected,
        ));
    }
}
