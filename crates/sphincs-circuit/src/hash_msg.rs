//! `hash_message` + `mgf1_256` gadgets — derive the FORS message hash and
//! hypertree indices from `R ‖ PK ‖ M`, mirroring PQClean `hash_sha2.c`.
//!
//! This is the only verify sub-gadget whose SHA-256 work grows with `|M|`
//! (in 64-byte steps). Today `mlen` is a **synthesis-time constant** on the circuit
//! struct: the gadget hashes exactly `R(16) ‖ pk(32) ‖ M[0..mlen]` and the compression
//! trace must match that fixed length. The v1 **relation** still exposes public `mlen`
//! ([`circuit_spec::VerifyPublic`]); variable public `mlen` (runtime public input +
//! muxed SHA preimage) lands in Phase 2 `Full` / final Spartan IO — not in the current
//! `FoldVerifyCoreCircuit` smoke path. See `docs/HACKMD_NEUTRONNOVA_PLAN.md` §Phase 2.

use crate::fors::SPX_FORS_MSG_BYTES;
use crate::thash::{alloc_input_bits, enforce_bits_equal_bytes, SPX_N};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use circuit_spec::MESSAGE_MAX_BYTES;
use sha2::{Digest, Sha256};

/// Public key size (`SPX_PK_BYTES`).
pub const SPX_PK_BYTES: usize = 32;
/// Hypertree index bit width: `SPX_TREE_HEIGHT * (SPX_D - 1)` = 9 × 6.
pub const SPX_TREE_BITS: u32 = 54;
/// Tree-index bytes in the MGF1 output.
pub const SPX_TREE_BYTES: usize = 7;
/// Leaf-index bit width (`SPX_TREE_HEIGHT`).
pub const SPX_LEAF_BITS: u32 = 9;
/// Leaf-index bytes in the MGF1 output.
pub const SPX_LEAF_BYTES: usize = 2;
/// Total MGF1 output bytes (`SPX_FORS_MSG_BYTES + tree + leaf`).
pub const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES;

/// Outputs of `hash_message`.
///
/// In `synthesize_verify_core`, only the raw MGF1 bytes (`hm_mgf`) are enforced
/// in-circuit today; `mhash` / `tree` / `leaf_idx` should match `parse_mgf_output(hm_mgf)`
/// but are still passed separately as synthesis-time hints — see `docs/CIRCUIT.md`
/// §Synthesis-time hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageOutput {
    pub mhash: [u8; SPX_FORS_MSG_BYTES],
    pub tree: u64,
    pub leaf_idx: u32,
}

/// `mgf1_256` — expand `seed` to `out.len()` bytes. Matches `hash_sha2.c:mgf1_256`.
pub fn mgf1_sha256(out: &mut [u8], seed: &[u8]) {
    let mut inbuf = Vec::with_capacity(seed.len() + 4);
    inbuf.extend_from_slice(seed);

    let full_blocks = out.len() / 32;
    for i in 0..full_blocks {
        inbuf.truncate(seed.len());
        inbuf.extend_from_slice(&(i as u32).to_be_bytes());
        let digest = Sha256::digest(&inbuf);
        out[i * 32..(i + 1) * 32].copy_from_slice(&digest);
    }
    let remainder = out.len() - full_blocks * 32;
    if remainder > 0 {
        inbuf.truncate(seed.len());
        inbuf.extend_from_slice(&(full_blocks as u32).to_be_bytes());
        let digest = Sha256::digest(&inbuf);
        out[full_blocks * 32..].copy_from_slice(&digest[..remainder]);
    }
}

fn bytes_to_ull(b: &[u8]) -> u64 {
    let mut out = 0u64;
    for &x in b {
        out = (out << 8) | u64::from(x);
    }
    out
}

fn parse_mgf_output(buf: &[u8; SPX_DGST_BYTES]) -> HashMessageOutput {
    let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
    mhash.copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
    let tree = bytes_to_ull(&buf[SPX_FORS_MSG_BYTES..SPX_FORS_MSG_BYTES + SPX_TREE_BYTES])
        & ((!0u64) >> (64 - SPX_TREE_BITS));
    let leaf_idx = bytes_to_ull(&buf[SPX_FORS_MSG_BYTES + SPX_TREE_BYTES..]) as u32
        & ((!0u32) >> (32 - SPX_LEAF_BITS));
    HashMessageOutput {
        mhash,
        tree,
        leaf_idx,
    }
}

/// Native `hash_message` (for tests / witness generation). Matches PQClean.
pub fn hash_message_native(
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> HashMessageOutput {
    assert!(mlen <= message.len());
    let mut hasher = Sha256::new();
    hasher.update(r);
    hasher.update(pk);
    hasher.update(&message[..mlen]);
    let seed_tail = hasher.finalize();

    let mut seed = [0u8; 2 * SPX_N + 32];
    seed[..SPX_N].copy_from_slice(r);
    seed[SPX_N..2 * SPX_N].copy_from_slice(&pk[..SPX_N]);
    seed[2 * SPX_N..].copy_from_slice(&seed_tail);

    let mut buf = [0u8; SPX_DGST_BYTES];
    mgf1_sha256(&mut buf, &seed);
    parse_mgf_output(&buf)
}

/// Raw 30-byte MGF1 output (before interpreting tree/leaf fields).
pub fn hash_message_mgf_buf(
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> [u8; SPX_DGST_BYTES] {
    assert!(mlen <= message.len());
    let mut hasher = Sha256::new();
    hasher.update(r);
    hasher.update(pk);
    hasher.update(&message[..mlen]);
    let seed_tail = hasher.finalize();

    let mut seed = [0u8; 2 * SPX_N + 32];
    seed[..SPX_N].copy_from_slice(r);
    seed[SPX_N..2 * SPX_N].copy_from_slice(&pk[..SPX_N]);
    seed[2 * SPX_N..].copy_from_slice(&seed_tail);

    let mut buf = [0u8; SPX_DGST_BYTES];
    mgf1_sha256(&mut buf, &seed);
    buf
}

fn constant_bits_be(bytes: &[u8]) -> Vec<Boolean> {
    bytes_to_bits_be(bytes)
        .into_iter()
        .map(Boolean::constant)
        .collect()
}

/// In-circuit `mgf1_256` from wired `seed_bits` (must already be 384 bits for 128s).
pub fn mgf1_digest_bits<Scalar, CS>(
    mut cs: CS,
    seed_bits: &[Boolean],
    out_len: usize,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut out_bits = Vec::with_capacity(out_len * 8);
    let full_blocks = out_len / 32;

    for i in 0..full_blocks {
        let counter = constant_bits_be(&((i as u32).to_be_bytes()));
        let mut in_bits = seed_bits.to_vec();
        in_bits.extend_from_slice(&counter);
        let digest = sha256(cs.namespace(|| format!("mgf1_{i}")), &in_bits)?;
        out_bits.extend(digest.into_iter().take(32 * 8));
    }

    let remainder = out_len - full_blocks * 32;
    if remainder > 0 {
        let counter = constant_bits_be(&((full_blocks as u32).to_be_bytes()));
        let mut in_bits = seed_bits.to_vec();
        in_bits.extend_from_slice(&counter);
        let digest = sha256(cs.namespace(|| "mgf1_last"), &in_bits)?;
        out_bits.extend(digest.into_iter().take(remainder * 8));
    }

    Ok(out_bits)
}

/// In-circuit `hash_message` for a fixed `mlen` (synthesis-time constant).
/// Returns MGF1 output bits and the parsed output (from witness, for structure).
pub fn hash_message_bits<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> Result<(Vec<Boolean>, HashMessageOutput), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= message.len());
    assert!(mlen <= MESSAGE_MAX_BYTES);

    let mut preimage = Vec::with_capacity(SPX_N + SPX_PK_BYTES + mlen);
    preimage.extend_from_slice(r);
    preimage.extend_from_slice(pk);
    preimage.extend_from_slice(&message[..mlen]);

    let preimage_bits = alloc_input_bits(&mut cs, "hm_preimage", &preimage)?;
    let seed_hash_bits = sha256(cs.namespace(|| "hm_seed"), &preimage_bits)?;

    // seed = R ‖ pk.seed ‖ SHA256(R‖pk‖M) — wire the hash output into mgf1 input.
    let r_bits: Vec<Boolean> = bytes_to_bits_be(r).into_iter().map(Boolean::constant).collect();
    let pk_seed_bits: Vec<Boolean> = bytes_to_bits_be(&pk[..SPX_N])
        .into_iter()
        .map(Boolean::constant)
        .collect();
    let mut seed_bits = r_bits;
    seed_bits.extend_from_slice(&pk_seed_bits);
    seed_bits.extend(seed_hash_bits);

    let mgf_bits = mgf1_digest_bits(cs.namespace(|| "mgf1"), &seed_bits, SPX_DGST_BYTES)?;

    // Parse witness for caller (structure hints at synthesis time).
    let mut buf = [0u8; SPX_DGST_BYTES];
    for (i, chunk) in buf.iter_mut().enumerate() {
        let start = i * 8;
        let mut byte = 0u8;
        for (j, bit) in mgf_bits[start..start + 8].iter().enumerate() {
            if bit.get_value().unwrap_or(false) {
                byte |= 1 << (7 - j);
            }
        }
        *chunk = byte;
    }

    Ok((mgf_bits, parse_mgf_output(&buf)))
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

/// Synthesize `hash_message` and enforce MGF1 output matches `expected_mgf` (30 bytes).
pub fn synthesize_hash_message<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
    expected_mgf: &[u8; SPX_DGST_BYTES],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let (mgf_bits, _) = hash_message_bits(cs.namespace(|| "hm"), r, pk, message, mlen)?;
    enforce_bits_equal_bytes(cs.namespace(|| "mgf_out"), &mgf_bits, expected_mgf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn native_matches_pqclean_short_message() {
        let r = [0x01u8; 16];
        let pk = [0x02u8; 32];
        let msg = b"hello sphincs";
        let mlen = msg.len();

        let native = hash_message_native(&r, &pk, msg, mlen);
        let oracle = sphincs_ref::hash_message_oracle(&r, &pk, msg, mlen);
        assert_eq!(native.mhash, oracle.mhash);
        assert_eq!(native.tree, oracle.tree);
        assert_eq!(native.leaf_idx, oracle.leaf_idx);
    }

    #[test]
    fn native_matches_pqclean_longer_message() {
        let r = [0x03u8; 16];
        let pk = [0x04u8; 32];
        let msg = vec![0x55u8; 200]; // spans multiple SHA-256 blocks
        let mlen = msg.len();

        let native = hash_message_native(&r, &pk, &msg, mlen);
        let oracle = sphincs_ref::hash_message_oracle(&r, &pk, &msg, mlen);
        assert_eq!(native, HashMessageOutput {
            mhash: oracle.mhash,
            tree: oracle.tree,
            leaf_idx: oracle.leaf_idx,
        });
    }

    #[test]
    fn circuit_matches_pqclean_short_message() {
        let r = [0x11u8; 16];
        let pk = [0x22u8; 32];
        let msg = b"test message for hash_message gadget";
        let mlen = msg.len();
        let oracle = sphincs_ref::hash_message_oracle(&r, &pk, msg, mlen);
        let expected_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
        // Sanity: parsed fields match oracle.
        let parsed = parse_mgf_output(&expected_mgf);
        assert_eq!(parsed.mhash, oracle.mhash);
        assert_eq!(parsed.tree, oracle.tree);
        assert_eq!(parsed.leaf_idx, oracle.leaf_idx);

        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_hash_message(&mut cs, &r, &pk, msg, mlen, &expected_mgf).expect("synth");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn mgf1_30_bytes_is_one_sha256() {
        let seed = [0xabu8; 48];
        let mut out = [0u8; SPX_DGST_BYTES];
        mgf1_sha256(&mut out, &seed);
        let mut inbuf = seed.to_vec();
        inbuf.extend_from_slice(&0u32.to_be_bytes());
        let digest = Sha256::digest(&inbuf);
        assert_eq!(&out[..], &digest[..SPX_DGST_BYTES]);
    }
}
