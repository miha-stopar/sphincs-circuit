//! FORS public-key recovery gadget — `fors_pk_from_sig`, mirroring PQClean
//! `fors.c`. This is the first step of SPHINCS+ verification after
//! `hash_message`: recover the FORS root from the signature and message hash.
//!
//! For each of the 14 parallel FORS trees (height 12):
//!   1. Read a 12-bit leaf index from `mhash` (`message_to_indices`).
//!   2. `fors_sk_to_leaf`: `thash(leaf, sig_sk, 1)` — hash the secret-key part.
//!   3. `compute_root`: walk the 12-level auth path to a per-tree root.
//! Finally: `thash(pk, all_roots, 14)` — horizontal hash across tree roots.
//!
//! The per-tree indices (and hence Merkle parities / addresses) are known at
//! synthesis time, matching the C reference's data-dependent structure.

use crate::merkle::{addr_with_height_index, compute_root_bits};
use crate::thash::{alloc_input_bits, enforce_digest_equals, thash_digest_bits, ADDR_BYTES, SPX_N};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// FORS tree height (`SPX_FORS_HEIGHT`).
pub const SPX_FORS_HEIGHT: u32 = 12;
/// Number of parallel FORS trees (`SPX_FORS_TREES`).
pub const SPX_FORS_TREES: usize = 14;
/// Message hash bytes consumed for index extraction (`SPX_FORS_MSG_BYTES`).
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT as usize * SPX_FORS_TREES + 7) / 8;
/// FORS signature byte length (`SPX_FORS_BYTES`).
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT as usize + 1) * SPX_FORS_TREES * SPX_N;

/// PQClean address type constants used by FORS.
pub const SPX_ADDR_TYPE_FORSTREE: u8 = 3;
pub const SPX_ADDR_TYPE_FORSPK: u8 = 4;

/// Extract `SPX_FORS_TREES` leaf indices (each `SPX_FORS_HEIGHT` bits) from the
/// message hash. Matches PQClean `fors.c:message_to_indices`.
pub fn message_to_indices(mhash: &[u8; SPX_FORS_MSG_BYTES]) -> [u32; SPX_FORS_TREES] {
    let mut indices = [0u32; SPX_FORS_TREES];
    let mut offset = 0usize;
    for idx in indices.iter_mut() {
        for j in 0..SPX_FORS_HEIGHT as usize {
            let bit = ((mhash[offset >> 3] >> (offset & 7)) & 1) as u32;
            *idx ^= bit << j;
            offset += 1;
        }
    }
    indices
}

/// Overlay `type` (offset 9) onto a copy of the base address.
fn addr_with_type(base: &[u8; ADDR_BYTES], ty: u8) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[9] = ty;
    a
}

/// In-circuit `fors_pk_from_sig`: recover the 128-bit FORS public key wires.
pub fn fors_pk_from_sig_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    sig: &[u8; SPX_FORS_BYTES],
    mhash: &[u8; SPX_FORS_MSG_BYTES],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let indices = message_to_indices(mhash);
    let mut tree_roots_bits = Vec::with_capacity(SPX_FORS_TREES * SPX_N * 8);
    let mut sig_off = 0usize;

    for (i, &leaf_idx) in indices.iter().enumerate() {
        let idx_offset = (i as u32) << SPX_FORS_HEIGHT;

        // fors_tree_addr: FORSTREE, tree_height=0, tree_index=leaf_idx+idx_offset
        let mut tree_addr = addr_with_type(addr_base, SPX_ADDR_TYPE_FORSTREE);
        tree_addr = addr_with_height_index(&tree_addr, 0, leaf_idx.wrapping_add(idx_offset));

        // fors_sk_to_leaf: thash(leaf, sig_sk, 1)
        let sk_bits = alloc_input_bits(
            &mut cs.namespace(|| format!("tree_{i}_sk")),
            "sk",
            &sig[sig_off..sig_off + SPX_N],
        )?;
        sig_off += SPX_N;

        let leaf_bits = thash_digest_bits(
            cs.namespace(|| format!("tree_{i}_leaf")),
            pub_seed,
            &tree_addr,
            &sk_bits,
        )?;

        // compute_root through auth path
        let auth = &sig[sig_off..sig_off + SPX_FORS_HEIGHT as usize * SPX_N];
        sig_off += SPX_FORS_HEIGHT as usize * SPX_N;

        let root_bits = compute_root_bits(
            cs.namespace(|| format!("tree_{i}_root")),
            pub_seed,
            &tree_addr,
            &leaf_bits,
            leaf_idx,
            idx_offset,
            auth,
            SPX_FORS_HEIGHT,
        )?;
        tree_roots_bits.extend(root_bits);
    }

    // thash(pk, roots, SPX_FORS_TREES)
    let pk_addr = addr_with_type(addr_base, SPX_ADDR_TYPE_FORSPK);
    thash_digest_bits(
        cs.namespace(|| "fors_pk"),
        pub_seed,
        &pk_addr,
        &tree_roots_bits,
    )
}

/// Synthesize `fors_pk_from_sig` and enforce the recovered key equals `expected_pk`.
pub fn synthesize_fors_pk_from_sig<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    sig: &[u8; SPX_FORS_BYTES],
    mhash: &[u8; SPX_FORS_MSG_BYTES],
    expected_pk: &[u8; SPX_N],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let pk_bits = fors_pk_from_sig_bits(
        cs.namespace(|| "fors"),
        pub_seed,
        addr_base,
        sig,
        mhash,
    )?;
    enforce_digest_equals(cs.namespace(|| "pk_eq"), &pk_bits, expected_pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    fn run(
        pub_seed: &[u8; 16],
        addr: &[u8; 22],
        sig: &[u8; SPX_FORS_BYTES],
        mhash: &[u8; SPX_FORS_MSG_BYTES],
        expected: &[u8; 16],
    ) -> bool {
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_fors_pk_from_sig(&mut cs, pub_seed, addr, sig, mhash, expected).expect("synth");
        cs.is_satisfied()
    }

    #[test]
    fn message_to_indices_reads_12_bits_per_tree() {
        let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
        // First tree index = 0b1011_0100_1101 = 0x4d3
        for (j, bit) in [1u8, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0].iter().enumerate() {
            if *bit == 1 {
                mhash[j >> 3] |= 1 << (j & 7);
            }
        }
        let idx = message_to_indices(&mhash);
        assert_eq!(idx[0], 715); // 1+2+8+64+128+512
        assert_eq!(idx[1], 0);
    }

    #[test]
    fn matches_pqclean() {
        let pub_seed = [0x31u8; 16];
        let mut addr = [0u8; 22];
        addr[13] = 9; // keypair address
        let sig: Vec<u8> = (0..SPX_FORS_BYTES).map(|i| (i % 251) as u8).collect();
        let sig: [u8; SPX_FORS_BYTES] = sig.try_into().unwrap();
        let mhash: [u8; SPX_FORS_MSG_BYTES] = core::array::from_fn(|i| (i * 11 + 3) as u8);

        let expected = sphincs_ref::fors_pk_from_sig_oracle(&pub_seed, &addr, &sig, &mhash);
        assert!(run(&pub_seed, &addr, &sig, &mhash, &expected));
    }

    #[test]
    fn wrong_pk_is_unsatisfiable() {
        let pub_seed = [0x77u8; 16];
        let addr = [0u8; 22];
        let sig: Vec<u8> = (0..SPX_FORS_BYTES).map(|i| (i * 5 % 256) as u8).collect();
        let sig: [u8; SPX_FORS_BYTES] = sig.try_into().unwrap();
        let mhash = [0x42u8; SPX_FORS_MSG_BYTES];

        let mut expected = sphincs_ref::fors_pk_from_sig_oracle(&pub_seed, &addr, &sig, &mhash);
        expected[0] ^= 1;
        assert!(!run(&pub_seed, &addr, &sig, &mhash, &expected));
    }
}
