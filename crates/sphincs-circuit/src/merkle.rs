//! `compute_root` gadget — reconstructs a Merkle root from a leaf and an
//! authentication path, exactly as PQClean `utils.c:compute_root`. Used by both
//! FORS (`tree_height = SPX_FORS_HEIGHT = 12`) and the hypertree
//! (`tree_height = SPX_TREE_HEIGHT = 9`).
//!
//! Each level is one `thash(..., 2)`: the current 32-byte buffer (two SPX_N
//! children) is hashed to a 16-byte parent, then combined with the next
//! `auth_path` sibling. The 16-byte output of one level is **wired** into the
//! next level via [`crate::thash::thash_digest_bits`] — this is the in-circuit
//! "chain linking" that folding alone does not provide.
//!
//! `leaf_idx` / `idx_offset` are treated as known at synthesis time (the circuit
//! structure follows the same branches as the C reference). The left/right
//! placement at each level and the per-level address are therefore fixed
//! constants; only the 16-byte node values are circuit wires. A fully
//! index-private variant (booleans + muxes) is a later hardening step.

use crate::thash::{alloc_input_bits, enforce_digest_equals, thash_digest_bits, ADDR_BYTES, SPX_N};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// Overlay `tree_height` (offset 17) and `tree_index` (offset 18..22, big-endian
/// `u32`) onto a copy of the base address — mirrors `set_tree_height` /
/// `set_tree_index` in PQClean `address.c`.
fn addr_with_height_index(base: &[u8; ADDR_BYTES], height: u32, index: u32) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[17] = height as u8;
    a[18..22].copy_from_slice(&index.to_be_bytes());
    a
}

/// Synthesize `compute_root`: constrain that folding the `leaf` up through the
/// `auth_path` yields `expected_root`.
///
/// `auth_path` is `tree_height` sibling nodes (`tree_height · SPX_N` bytes).
#[allow(clippy::too_many_arguments)]
pub fn synthesize_compute_root<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    leaf: &[u8; SPX_N],
    leaf_idx: u32,
    idx_offset: u32,
    auth_path: &[u8],
    tree_height: u32,
    expected_root: &[u8; SPX_N],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let th = tree_height as usize;
    assert!(th >= 1, "tree_height must be >= 1");
    assert_eq!(auth_path.len(), th * SPX_N, "auth_path must be tree_height SPX_N-blocks");

    // Allocate leaf + every auth_path sibling as witness bits.
    let leaf_bits = alloc_input_bits(&mut cs, "leaf", leaf)?;
    let sibling_bits: Vec<Vec<Boolean>> = (0..th)
        .map(|j| {
            let s = &auth_path[j * SPX_N..(j + 1) * SPX_N];
            alloc_input_bits(&mut cs, &format!("auth_{j}"), s)
        })
        .collect::<Result<_, _>>()?;

    let mut li = leaf_idx;
    let mut io = idx_offset;

    // Level 0 buffer: leaf and the first sibling, ordered by leaf parity.
    // C: if (leaf_idx & 1) { buffer.right = leaf; buffer.left = auth } else { ... }
    let (mut left, mut right) = if li & 1 == 1 {
        (sibling_bits[0].clone(), leaf_bits)
    } else {
        (leaf_bits, sibling_bits[0].clone())
    };

    // tree_height - 1 intermediate levels.
    for i in 0..th - 1 {
        li >>= 1;
        io >>= 1;
        let addr = addr_with_height_index(addr_base, (i + 1) as u32, li.wrapping_add(io));

        let mut in_bits = left;
        in_bits.extend_from_slice(&right);
        let node = thash_digest_bits(
            cs.namespace(|| format!("level_{i}")),
            pub_seed,
            &addr,
            &in_bits,
        )?;

        // Output node becomes one child; next sibling becomes the other.
        if li & 1 == 1 {
            right = node;
            left = sibling_bits[i + 1].clone();
        } else {
            left = node;
            right = sibling_bits[i + 1].clone();
        }
    }

    // Final level: hash the buffer straight into the root (no sibling copy).
    li >>= 1;
    io >>= 1;
    let addr = addr_with_height_index(addr_base, tree_height, li.wrapping_add(io));
    let mut in_bits = left;
    in_bits.extend_from_slice(&right);
    let root = thash_digest_bits(cs.namespace(|| "root"), pub_seed, &addr, &in_bits)?;

    enforce_digest_equals(cs.namespace(|| "root_eq"), &root, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    fn run(
        pub_seed: &[u8; 16],
        addr: &[u8; 22],
        leaf: &[u8; 16],
        leaf_idx: u32,
        idx_offset: u32,
        auth: &[u8],
        tree_height: u32,
        expected: &[u8; 16],
    ) -> bool {
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_compute_root(
            &mut cs, pub_seed, addr, leaf, leaf_idx, idx_offset, auth, tree_height, expected,
        )
        .expect("synth");
        cs.is_satisfied()
    }

    #[test]
    fn matches_pqclean_fors_height() {
        let pub_seed = [0x11u8; 16];
        let addr = [0x22u8; 22];
        let leaf = [0x33u8; 16];
        let th = 12u32; // SPX_FORS_HEIGHT
        let auth: Vec<u8> = (0..th as usize * 16).map(|i| i as u8).collect();
        // Exercise several indices (different parity patterns).
        for &(leaf_idx, idx_offset) in &[(0u32, 0u32), (1, 0), (1234, 0), (4095, 7), (2048, 16)] {
            let expected =
                sphincs_ref::compute_root_oracle(&pub_seed, &addr, &leaf, leaf_idx, idx_offset, &auth, th);
            assert!(
                run(&pub_seed, &addr, &leaf, leaf_idx, idx_offset, &auth, th, &expected),
                "FORS-height mismatch at idx={leaf_idx} off={idx_offset}"
            );
        }
    }

    #[test]
    fn matches_pqclean_hypertree_height() {
        let pub_seed = [0xa1u8; 16];
        let addr = {
            let mut a = [0u8; 22];
            for (i, b) in a.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(5).wrapping_add(1);
            }
            a
        };
        let leaf = [0x7eu8; 16];
        let th = 9u32; // SPX_TREE_HEIGHT
        let auth: Vec<u8> = (0..th as usize * 16).map(|i| (200 - i) as u8).collect();
        for &(leaf_idx, idx_offset) in &[(0u32, 0u32), (1, 0), (255, 0), (256, 256), (511, 0)] {
            let expected =
                sphincs_ref::compute_root_oracle(&pub_seed, &addr, &leaf, leaf_idx, idx_offset, &auth, th);
            assert!(
                run(&pub_seed, &addr, &leaf, leaf_idx, idx_offset, &auth, th, &expected),
                "HT-height mismatch at idx={leaf_idx} off={idx_offset}"
            );
        }
    }

    #[test]
    fn single_level_tree() {
        let pub_seed = [4u8; 16];
        let addr = [5u8; 22];
        let leaf = [6u8; 16];
        let auth = [7u8; 16]; // tree_height = 1
        let expected = sphincs_ref::compute_root_oracle(&pub_seed, &addr, &leaf, 0, 0, &auth, 1);
        assert!(run(&pub_seed, &addr, &leaf, 0, 0, &auth, 1, &expected));
    }

    #[test]
    fn wrong_root_is_unsatisfiable() {
        let pub_seed = [1u8; 16];
        let addr = [2u8; 22];
        let leaf = [3u8; 16];
        let th = 9u32;
        let auth: Vec<u8> = (0..th as usize * 16).map(|i| i as u8).collect();
        let mut expected = sphincs_ref::compute_root_oracle(&pub_seed, &addr, &leaf, 5, 0, &auth, th);
        expected[0] ^= 1; // corrupt the claimed root

        assert!(!run(&pub_seed, &addr, &leaf, 5, 0, &auth, th, &expected));
    }

    #[test]
    fn tampered_auth_path_is_unsatisfiable() {
        let pub_seed = [9u8; 16];
        let addr = [8u8; 22];
        let leaf = [7u8; 16];
        let th = 9u32;
        let auth: Vec<u8> = (0..th as usize * 16).map(|i| i as u8).collect();
        let expected = sphincs_ref::compute_root_oracle(&pub_seed, &addr, &leaf, 3, 0, &auth, th);

        // Flip a bit in the witness auth_path; the recomputed root no longer matches.
        let mut bad_auth = auth.clone();
        bad_auth[20] ^= 1;
        assert!(!run(&pub_seed, &addr, &leaf, 3, 0, &bad_auth, th, &expected));
    }
}
