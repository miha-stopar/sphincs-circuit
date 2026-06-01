//! `thash` gadget — the SPHINCS+ domain-separated hash used by FORS, WOTS+, and
//! the Merkle trees. This is the first real `C_core` building block.
//!
//! PQClean `thash_sha2_simple.c` computes, for `inblocks` blocks of `SPX_N`:
//!
//! 1. clone `state_seeded` (SHA-256 after absorbing one block `pub_seed ‖ 0^{48}`),
//! 2. finalize over `buf = addr(22) ‖ in(inblocks·16)`,
//! 3. truncate the 32-byte digest to `SPX_N = 16` bytes.
//!
//! Because the seeded state is exactly one absorbed 64-byte block, this equals a
//! single full SHA-256 over the concatenation:
//!
//! ```text
//!   thash(in, inblocks) = SHA256( pub_seed(16) ‖ 0^{48} ‖ addr(22) ‖ in )[0:16]
//! ```
//!
//! The gadget hashes that exact preimage with the bellpepper SHA-256 gadget
//! (which performs message padding internally) and constrains the first 128
//! output bits to equal the expected `thash` output. Bit-exactness against
//! PQClean is checked in the tests via `sphincs_ref::thash_oracle`.

use bellpepper::gadgets::boolean::{AllocatedBit, Boolean};
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// SPHINCS+-SHA2-128s output length (bytes).
pub const SPX_N: usize = 16;
/// SHA-256 address prefix copied into the `thash` buffer.
pub const ADDR_BYTES: usize = 22;
/// Seeded prefix: `pub_seed(16) ‖ zeros(48)` = one SHA-256 block.
pub const SEED_BLOCK_BYTES: usize = 64;

/// Statistics from synthesizing one `thash` (requires a `Comparable` CS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThashStats {
    pub num_constraints: usize,
    pub preimage_bytes: usize,
}

/// Build the canonical SHA-256 preimage for a `thash` call:
/// `pub_seed(16) ‖ zeros(48) ‖ addr(22) ‖ in`.
pub fn thash_preimage(pub_seed: &[u8; SPX_N], addr: &[u8; ADDR_BYTES], input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % SPX_N, 0, "input must be whole SPX_N blocks");
    assert!(!input.is_empty(), "thash needs at least one block");
    let mut p = Vec::with_capacity(SEED_BLOCK_BYTES + ADDR_BYTES + input.len());
    p.extend_from_slice(pub_seed);
    p.resize(SPX_N + (SEED_BLOCK_BYTES - SPX_N), 0u8); // append 48 zero bytes
    p.extend_from_slice(addr);
    p.extend_from_slice(input);
    p
}

fn bytes_to_bits_be(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Allocate `bytes` as big-endian witness bits.
pub fn alloc_input_bits<Scalar, CS>(
    cs: &mut CS,
    label: &str,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    bytes_to_bits_be(bytes)
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            AllocatedBit::alloc(cs.namespace(|| format!("{label}_bit_{i}")), Some(b))
                .map(Boolean::from)
        })
        .collect()
}

/// Core `thash` as a composable gadget: returns the 128 output bits
/// (`SHA256(pub_seed ‖ 0^{48} ‖ addr ‖ in)[0:16]`) so the result can be wired
/// into the next gadget (a Merkle parent, a WOTS chain step, …).
///
/// `in_bits` carries the `in` argument (`inblocks · SPX_N` bytes, big-endian);
/// it may be freshly allocated witness bits or forwarded from a previous gadget.
/// `pub_seed` and `addr` are treated as compile-time constants here (they come
/// from the public key and the deterministic address structure).
pub fn thash_digest_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    in_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    debug_assert_eq!(in_bits.len() % (SPX_N * 8), 0, "in_bits must be whole blocks");

    // Constant prefix: pub_seed(16) ‖ zeros(48) ‖ addr(22).
    let mut prefix = Vec::with_capacity(SEED_BLOCK_BYTES + ADDR_BYTES);
    prefix.extend_from_slice(pub_seed);
    prefix.resize(SEED_BLOCK_BYTES, 0u8);
    prefix.extend_from_slice(addr);

    let mut preimage_bits: Vec<Boolean> = bytes_to_bits_be(&prefix)
        .into_iter()
        .map(Boolean::constant)
        .collect();
    preimage_bits.extend_from_slice(in_bits);

    let digest = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;
    Ok(digest.into_iter().take(SPX_N * 8).collect())
}

/// Enforce that `bits` equals `expected` bytes (big-endian), bit-for-bit.
pub fn enforce_bits_equal_bytes<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
    expected: &[u8],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(bits.len(), expected.len() * 8);
    let expected_bits = bytes_to_bits_be(expected);
    for (i, (computed, &exp)) in bits.iter().zip(expected_bits.iter()).enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("bit_eq_{i}")),
            computed,
            &Boolean::constant(exp),
        )?;
    }
    Ok(())
}

/// Enforce that a 128-bit digest equals the 16-byte `expected` value.
pub fn enforce_digest_equals<Scalar, CS>(
    mut cs: CS,
    digest_bits: &[Boolean],
    expected: &[u8; SPX_N],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let expected_bits = bytes_to_bits_be(expected);
    for (i, (computed, &exp)) in digest_bits.iter().zip(expected_bits.iter()).enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("out_bit_{i}")),
            computed,
            &Boolean::constant(exp),
        )?;
    }
    Ok(())
}

/// Synthesize `thash`: constrain `SHA256(preimage)[0:16] == expected_out`.
///
/// All preimage bits are allocated as witness variables (so this produces a
/// genuine R1CS, not a constant fold). `expected_out` is enforced as a constant
/// here; when composed into `C_core` it will instead be wired to the next
/// gadget's input (e.g. a WOTS chain step or a Merkle node).
pub fn synthesize_thash<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    input: &[u8],
    expected_out: &[u8; SPX_N],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(input.len() % SPX_N, 0, "input must be whole SPX_N blocks");
    assert!(!input.is_empty(), "thash needs at least one block");

    let in_bits = alloc_input_bits(&mut cs, "in", input)?;
    let digest = thash_digest_bits(cs.namespace(|| "thash"), pub_seed, addr, &in_bits)?;
    enforce_digest_equals(cs.namespace(|| "eq"), &digest, expected_out)
}

/// Like [`synthesize_thash`], also returning constraint count (test / bench helper).
pub fn synthesize_thash_with_stats<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    input: &[u8],
    expected_out: &[u8; SPX_N],
) -> Result<ThashStats, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar> + bellpepper_core::Comparable<Scalar>,
{
    let before = cs.num_constraints();
    synthesize_thash(&mut cs, pub_seed, addr, input, expected_out)?;
    Ok(ThashStats {
        num_constraints: cs.num_constraints() - before,
        preimage_bytes: SEED_BLOCK_BYTES + ADDR_BYTES + input.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    fn check(pub_seed: &[u8; 16], addr: &[u8; 22], input: &[u8]) -> bool {
        let expected = sphincs_ref::thash_oracle(pub_seed, addr, input);
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_thash(&mut cs, pub_seed, addr, input, &expected).expect("synth");
        cs.is_satisfied()
    }

    #[test]
    fn thash_matches_pqclean_for_all_inblocks() {
        let pub_seed = [0x11u8; 16];
        let addr = [0x22u8; 22];
        // inblocks used in verify: 1 (WOTS chain / FORS leaf), 2 (Merkle node),
        // 14 (FORS root), 35 (WOTS public key compression).
        for inblocks in [1usize, 2, 14, 35] {
            let input: Vec<u8> = (0..inblocks * 16).map(|i| i as u8).collect();
            assert!(check(&pub_seed, &addr, &input), "inblocks={inblocks} mismatch");
        }
    }

    #[test]
    fn thash_matches_pqclean_for_varied_values() {
        let pub_seed = [0xa5u8; 16];
        let addr = {
            let mut a = [0u8; 22];
            for (i, b) in a.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(3);
            }
            a
        };
        let input: Vec<u8> = (0..32).map(|i| (255 - i) as u8).collect(); // 2 blocks
        assert!(check(&pub_seed, &addr, &input));
    }

    #[test]
    fn wrong_expected_output_is_unsatisfiable() {
        let pub_seed = [7u8; 16];
        let addr = [8u8; 22];
        let input = [9u8; 16];
        let mut expected = sphincs_ref::thash_oracle(&pub_seed, &addr, &input);
        expected[0] ^= 1; // corrupt one bit of the claimed output

        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_thash(&mut cs, &pub_seed, &addr, &input, &expected).expect("synth");
        assert!(!cs.is_satisfied(), "corrupted output must not satisfy");
    }

    #[test]
    fn reports_constraint_count() {
        let pub_seed = [1u8; 16];
        let addr = [2u8; 22];
        let input = [3u8; 16]; // inblocks = 1
        let expected = sphincs_ref::thash_oracle(&pub_seed, &addr, &input);

        let cs = TestConstraintSystem::<Fr>::new();
        let stats =
            synthesize_thash_with_stats(cs, &pub_seed, &addr, &input, &expected).unwrap();
        // 102-byte preimage → 2 SHA-256 blocks → ~2 compressions worth of constraints.
        assert_eq!(stats.preimage_bytes, 102);
        assert!(stats.num_constraints > 20_000, "got {}", stats.num_constraints);
        assert!(stats.num_constraints < 80_000, "got {}", stats.num_constraints);
    }
}
