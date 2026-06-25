//! `hash_message` + `mgf1_256` gadgets — derive the FORS message hash and
//! hypertree indices from `R ‖ PK ‖ M`, mirroring PQClean `hash_sha2.c`.
//!
//! This is the only verify sub-gadget whose SHA-256 work grows with `|M|`
//! (in 64-byte steps). Today `mlen` is a **synthesis-time constant** on the circuit
//! struct: the gadget hashes exactly `R(16) ‖ pk(32) ‖ M[0..mlen]` and the compression
//! trace must match that fixed length. The v1 **relation** still exposes public `mlen`
//! ([`circuit_spec::VerifyPublic`]); variable public `mlen` (runtime public input +
//! Variable public `mlen` (runtime public input +
//! muxed SHA preimage) lands in Phase 2c+ — see `docs/VARIABLE_MLEN.md`.
//!
//! ## Phase 2c — parsed fields from witness MGF1
//!
//! [`synthesize_hash_message_parsed`] enforces `mgf_bits == expected_mgf` and returns
//! [`HashMessageOutput`] via [`hash_message_output_from_mgf_bits`] / [`parse_mgf_output`].
//! No separate trusted `hm_expected` parameter. Address topology still uses synthesis-time
//! `u64`/`u32` from witness assignments (optional future: in-circuit bit mux).
//!
//! **Tests:** `cargo test -p sphincs-circuit parsed_output_matches_native`

use crate::fors::SPX_FORS_MSG_BYTES;
use crate::thash::{alloc_input_bits, enforce_bits_equal_bytes, SPX_N};
use crate::verify_public_io::{
    public_message_sha_bits, public_mlen_is_short_path, public_pk_sha_bits, InputizedVerifyPublic,
};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use circuit_spec::MESSAGE_MAX_BYTES;
use sha2::{Digest, Sha256};

/// Public key size (`SPX_PK_BYTES`).
pub const SPX_PK_BYTES: usize = 32;
/// `R ‖ PK` prefix bytes in `hash_message` seed hash (`SPX_N + SPX_PK_BYTES`).
pub const HASH_MESSAGE_PREFIX_BYTES: usize = SPX_N + SPX_PK_BYTES;
/// PQClean `SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES` for 128s (`hash_sha2.c`).
pub const HASH_MESSAGE_INBUF_BYTES: usize = 64;
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
/// In `synthesize_verify_core`, `mhash` / `tree` / `leaf_idx` are derived from witness
/// `mgf_bits` via [`hash_message_output_from_mgf_bits`] (PQClean mask), not a separate
/// trusted parameter — see [`synthesize_hash_message_parsed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageOutput {
    pub mhash: [u8; SPX_FORS_MSG_BYTES],
    pub tree: u64,
    pub leaf_idx: u32,
}

/// PQClean `hash_sha2.c:hash_message` branch for the seed SHA (`R ‖ PK ‖ M`).
///
/// Variable public `mlen` in one universal circuit must mux between these paths and align
/// compression count with the folded trace. See `docs/VARIABLE_MLEN.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashMessageSeedPath {
    /// `48 + mlen < 64` — single `shaX_inc_finalize` on `R ‖ PK ‖ M`.
    ShortFinalize,
    /// One `shaX_inc_blocks` on a padded 64-byte buffer, then `shaX_inc_finalize` on `M` tail.
    LongBlockThenFinalize,
}

/// Which PQClean branch applies at synthesis / prove time for message length `mlen`.
pub fn hash_message_seed_path(mlen: usize) -> HashMessageSeedPath {
    if HASH_MESSAGE_PREFIX_BYTES + mlen < HASH_MESSAGE_INBUF_BYTES {
        HashMessageSeedPath::ShortFinalize
    } else {
        HashMessageSeedPath::LongBlockThenFinalize
    }
}

/// Message bytes absorbed into the first full 64-byte block (long path only).
pub fn hash_message_first_block_message_bytes(mlen: usize) -> usize {
    HASH_MESSAGE_INBUF_BYTES
        .saturating_sub(HASH_MESSAGE_PREFIX_BYTES)
        .min(mlen)
}

/// Message bytes hashed in the `inc_finalize` tail (long path only).
pub fn hash_message_tail_message_bytes(mlen: usize) -> usize {
    match hash_message_seed_path(mlen) {
        HashMessageSeedPath::ShortFinalize => 0,
        HashMessageSeedPath::LongBlockThenFinalize => {
            mlen.saturating_sub(hash_message_first_block_message_bytes(mlen))
        }
    }
}

/// Rough compression budget for `hash_message` (seed + MGF1), per [FOLDING.md](../../docs/FOLDING.md).
///
/// Exact counts should be confirmed against PQClean instrumentation before trace linking.
pub fn hash_message_compression_budget(mlen: usize) -> usize {
    2 + mlen.div_ceil(64)
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

/// Native PQClean parse of the 30-byte MGF1 buffer (masks tree / leaf fields).
///
/// Applies `SPX_TREE_BITS` / `SPX_LEAF_BITS` masks — unused high bits in the tree/leaf byte
/// fields may be non-zero in PQClean output; masking happens here, not via extra R1CS constraints.
///
/// **In-circuit path:** [`synthesize_hash_message_parsed`] enforces `mgf_bits == hm_mgf`, then calls
/// [`hash_message_output_from_mgf_bits`] which reads witness assignments via `Boolean::get_value()`
/// and runs this function. FORS/hypertree **address bytes** still use the resulting `u64`/`u32` as
/// synthesis-time constants (optional future: wire tree/leaf bits into address gadgets).
///
/// **Witness prep:** used only by debug [`intermediate_roots_oracle`] in `sphincs-prover` — not a circuit input.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit parsed_output_matches_native
/// ```
pub fn parse_mgf_output(buf: &[u8; SPX_DGST_BYTES]) -> HashMessageOutput {
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

/// Native seed hash `SHA256(R ‖ PK ‖ M[0..mlen])` — PQClean short path.
pub fn hash_message_seed_hash_native(
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(r);
    h.update(pk);
    h.update(&message[..mlen]);
    h.finalize().into()
}

/// Native seed hash via PQClean long path (`inc_blocks` + `inc_finalize` tail).
pub fn hash_message_seed_hash_native_long(
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> [u8; 32] {
    let first = hash_message_first_block_message_bytes(mlen);
    let mut block = [0u8; HASH_MESSAGE_INBUF_BYTES];
    block[..SPX_N].copy_from_slice(r);
    block[SPX_N..SPX_N + SPX_PK_BYTES].copy_from_slice(pk);
    block[SPX_N + SPX_PK_BYTES..SPX_N + SPX_PK_BYTES + first].copy_from_slice(&message[..first]);
    let mut h = Sha256::new();
    h.update(&block);
    if mlen > first {
        h.update(&message[first..mlen]);
    }
    h.finalize().into()
}

fn boolean_mux<Scalar, CS>(
    mut cs: CS,
    cond: &Boolean,
    when_true: &Boolean,
    when_false: &Boolean,
) -> Result<Boolean, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let t = Boolean::and(cs.namespace(|| "mux_t"), cond, when_true)?;
    let f = Boolean::and(cs.namespace(|| "mux_f"), &cond.not(), when_false)?;
    Boolean::or(cs.namespace(|| "mux_or"), &t, &f)
}

fn mux_boolean_vectors<Scalar, CS>(
    mut cs: CS,
    cond: &Boolean,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .enumerate()
        .map(|(i, (x, y))| boolean_mux(cs.namespace(|| format!("mux_{i}")), cond, x, y))
        .collect()
}

/// Tie public `mlen` path bit to synthesis-time `circuit_mlen` until fully variable circuits land.
pub fn enforce_public_mlen_seed_path<Scalar, CS>(
    mut cs: CS,
    public: &InputizedVerifyPublic<Scalar>,
    circuit_mlen: usize,
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let is_short = public_mlen_is_short_path(cs.namespace(|| "path"), public)?;
    let expect_short = hash_message_seed_path(circuit_mlen) == HashMessageSeedPath::ShortFinalize;
    Boolean::enforce_equal(
        cs.namespace(|| "path_eq"),
        &is_short,
        &Boolean::constant(expect_short),
    )?;
    Ok(())
}

fn mgf1_bits_from_seed_hash<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    seed_hash_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let pk_seed_bits: Vec<Boolean> = bytes_to_bits_be(&pk[..SPX_N])
        .into_iter()
        .map(Boolean::constant)
        .collect();
    let mut seed_bits: Vec<Boolean> = bytes_to_bits_be(r).into_iter().map(Boolean::constant).collect();
    seed_bits.extend(pk_seed_bits);
    seed_bits.extend(seed_hash_bits.iter().cloned());
    mgf1_digest_bits(cs.namespace(|| "mgf1"), &seed_bits, SPX_DGST_BYTES)
}

/// `hash_message` seed SHA with **short/long path mux** from public `mlen`.
///
/// `circuit_mlen` still fixes short/long preimage sizes at synthesis; public `mlen` selects the
/// active PQClean branch via [`public_mlen_is_short_path`]. [`enforce_public_mlen_seed_path`]
/// ties public path to `circuit_mlen` on fixed-`mlen` instances.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit hash_message_variable_mlen_matches_native
/// ```
pub fn hash_message_bits_from_public_muxed<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    public: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    circuit_mlen: usize,
) -> Result<(Vec<Boolean>, HashMessageOutput), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(circuit_mlen <= MESSAGE_MAX_BYTES);
    enforce_public_mlen_seed_path(cs.namespace(|| "mlen_path"), public, circuit_mlen)?;

    let pk_bits = public_pk_sha_bits(cs.namespace(|| "pub_pk"), &public.pk_words, pk)?;
    let msg_bits = public_message_sha_bits(
        cs.namespace(|| "pub_msg"),
        &public.message_words,
        message,
    )?;

    let r_bits: Vec<Boolean> = bytes_to_bits_be(r).into_iter().map(Boolean::constant).collect();

    // Short path: SHA256(R ‖ PK ‖ M[0..circuit_mlen]).
    let mut short_preimage = r_bits.clone();
    short_preimage.extend(pk_bits.iter().cloned());
    short_preimage.extend(msg_bits.iter().take(circuit_mlen * 8).cloned());
    let short_seed = sha256(cs.namespace(|| "hm_seed_short"), &short_preimage)?;

    // Long path: SHA256( 64-byte block ‖ M[16..circuit_mlen] ).
    let first_block = HASH_MESSAGE_INBUF_BYTES - HASH_MESSAGE_PREFIX_BYTES;
    let mut block64 = r_bits;
    block64.extend(pk_bits.iter().cloned());
    block64.extend(msg_bits.iter().take(first_block * 8).cloned());
    assert_eq!(block64.len(), HASH_MESSAGE_INBUF_BYTES * 8);
    let tail_len = circuit_mlen.saturating_sub(first_block);
    let mut long_preimage = block64;
    long_preimage.extend(msg_bits.iter().skip(first_block * 8).take(tail_len * 8).cloned());
    let long_seed = sha256(cs.namespace(|| "hm_seed_long"), &long_preimage)?;

    let is_short = public_mlen_is_short_path(cs.namespace(|| "mlen_mux"), public)?;
    let seed_hash_bits = mux_boolean_vectors(
        cs.namespace(|| "seed_mux"),
        &is_short,
        &short_seed,
        &long_seed,
    )?;

    let mgf_bits = mgf1_bits_from_seed_hash(cs.namespace(|| "mgf"), r, pk, &seed_hash_bits)?;

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

/// In-circuit `hash_message` with `R ‖ PK ‖ M[0..mlen]` wired from **public Spartan columns**.
///
/// `pk` / `message` byte buffers supply synthesis-time assignments; R1CS ties
/// [`InputizedVerifyPublic`] words to those bytes. Used when `FoldVerifyCoreCircuit::public_io`.
///
/// `mlen` is still a synthesis-time constant for preimage length (variable public `mlen` is a later step).
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit hash_message_public_preimage_matches_native
/// ```
pub fn hash_message_bits_from_public<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    public: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
) -> Result<(Vec<Boolean>, HashMessageOutput), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    hash_message_bits_from_public_muxed(cs, r, public, pk, message, mlen)
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

/// Read big-endian bit vector back to bytes (uses witness `get_value()` at synthesis).
fn bits_to_bytes_be(bits: &[Boolean]) -> Vec<u8> {
    assert!(bits.len().is_multiple_of(8));
    bits.chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (j, bit) in chunk.iter().enumerate() {
                if bit.get_value().unwrap_or(false) {
                    byte |= 1 << (7 - j);
                }
            }
            byte
        })
        .collect()
}

/// Build [`HashMessageOutput`] from witness `mgf_bits` after `mgf_bits == expected_mgf` is enforced.
///
/// Applies the same PQClean mask as [`parse_mgf_output`] (`SPX_TREE_BITS`, `SPX_LEAF_BITS`).
/// Unused high bits in the tree/leaf byte fields may be non-zero in PQClean output — we do
/// **not** force them to zero in R1CS (masking happens here at synthesis / `get_value()` time).
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit hash_msg::tests::parsed_output_matches_native -- --nocapture
/// ```
pub fn hash_message_output_from_mgf_bits(mgf_bits: &[Boolean]) -> HashMessageOutput {
    let bytes = bits_to_bytes_be(mgf_bits);
    let mut buf = [0u8; SPX_DGST_BYTES];
    buf.copy_from_slice(&bytes[..SPX_DGST_BYTES]);
    parse_mgf_output(&buf)
}

/// Synthesize `hash_message`, enforce `expected_mgf`, and **parse** `mhash` / `tree` / `leaf_idx`
/// from the witness MGF1 bits (no separate trusted `hm_expected`).
///
/// Returns parsed [`HashMessageOutput`] for downstream gadgets (FORS addresses, hypertree indices).
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit parsed_output_matches_native
/// cargo test -p sphincs-circuit wrong_hm_mgf_unsatisfies_parsed_hash_message
/// ```
pub fn synthesize_hash_message_parsed<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8],
    mlen: usize,
    expected_mgf: &[u8; SPX_DGST_BYTES],
) -> Result<HashMessageOutput, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let (mgf_bits, _) = hash_message_bits(cs.namespace(|| "hm"), r, pk, message, mlen)?;
    enforce_bits_equal_bytes(cs.namespace(|| "mgf_out"), &mgf_bits, expected_mgf)?;
    Ok(hash_message_output_from_mgf_bits(&mgf_bits))
}

/// Like [`synthesize_hash_message_parsed`] but `PK` / `M` in the SHA preimage come from public IO.
pub fn synthesize_hash_message_parsed_public<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    public: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPX_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
    expected_mgf: &[u8; SPX_DGST_BYTES],
) -> Result<HashMessageOutput, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let (mgf_bits, _) =
        hash_message_bits_from_public(cs.namespace(|| "hm"), r, public, pk, message, mlen)?;
    enforce_bits_equal_bytes(cs.namespace(|| "mgf_out"), &mgf_bits, expected_mgf)?;
    Ok(hash_message_output_from_mgf_bits(&mgf_bits))
}

/// Synthesize `hash_message` and enforce MGF1 output matches `expected_mgf` (30 bytes).
///
/// Thin wrapper around [`synthesize_hash_message_parsed`] that discards the parsed
/// [`HashMessageOutput`]. Prefer `_parsed` when downstream gadgets need `mhash` / `tree` / `leaf_idx`.
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
    synthesize_hash_message_parsed(cs, r, pk, message, mlen, expected_mgf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use circuit_spec::VerifyPublic;
    use crate::verify_public_io::{inputize_verify_public, pack_verify_public};

    #[test]
    fn hash_message_seed_paths_match_native() {
        let r = [0x31u8; SPX_N];
        let pk = [0x32u8; SPX_PK_BYTES];
        for &mlen in &[5usize, 15, 16, 50, 100] {
            let msg = vec![0xabu8; mlen];
            let native = hash_message_seed_hash_native(&r, &pk, &msg, mlen);
            let branched = match hash_message_seed_path(mlen) {
                HashMessageSeedPath::ShortFinalize => {
                    hash_message_seed_hash_native(&r, &pk, &msg, mlen)
                }
                HashMessageSeedPath::LongBlockThenFinalize => {
                    hash_message_seed_hash_native_long(&r, &pk, &msg, mlen)
                }
            };
            assert_eq!(native, branched, "mlen={mlen}");
        }
    }

    #[test]
    fn hash_message_variable_mlen_matches_native() {
        let r = [0x77u8; SPX_N];
        let pk = [0x88u8; SPX_PK_BYTES];
        let cases: &[(usize, &[u8])] = &[
            (5, b"short"),
            (16, b"sixteen bytes!!!"),
            (100, &[0xcd; 100][..]),
        ];
        for &(mlen, msg) in cases {
            let mut padded = [0u8; MESSAGE_MAX_BYTES];
            padded[..mlen].copy_from_slice(msg);
            let stmt = VerifyPublic::from_message(pk, msg);
            let expected_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
            let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, mlen);

            let mut cs = TestConstraintSystem::<Fr>::new();
            let input = inputize_verify_public(&mut cs, &public).expect("inputize");
            synthesize_hash_message_parsed_public(
                &mut cs,
                &r,
                &input,
                &pk,
                &padded,
                mlen,
                &expected_mgf,
            )
            .expect("synth");
            assert!(cs.is_satisfied(), "mlen={mlen}");
        }
    }

    #[test]
    fn hash_message_public_preimage_matches_native() {
        let r = [0x77u8; 16];
        let msg = b"public preimage wiring";
        let pk = [0x88u8; 32];
        let stmt = VerifyPublic::from_message(pk, msg);
        let mlen = msg.len();
        let expected_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, mlen);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        synthesize_hash_message_parsed_public(
            &mut cs,
            &r,
            &input,
            &pk,
            &stmt.message,
            mlen,
            &expected_mgf,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

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

    /// Phase 2c: `synthesize_hash_message_parsed` agrees with native [`parse_mgf_output`] and PQClean.
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit parsed_output_matches_native -- --nocapture
    /// ```
    #[test]
    fn parsed_output_matches_native() {
        let r = [0x33u8; 16];
        let pk = [0x44u8; 32];
        let msg = b"parsed output from mgf witness";
        let mlen = msg.len();
        let mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
        let native = parse_mgf_output(&mgf);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let parsed =
            synthesize_hash_message_parsed(&mut cs, &r, &pk, msg, mlen, &mgf).expect("synth");
        assert!(cs.is_satisfied());
        assert_eq!(parsed, native);

        let oracle = sphincs_ref::hash_message_oracle(&r, &pk, msg, mlen);
        assert_eq!(parsed.mhash, oracle.mhash);
        assert_eq!(parsed.tree, oracle.tree);
        assert_eq!(parsed.leaf_idx, oracle.leaf_idx);
    }

    #[test]
    fn hash_message_seed_path_boundaries() {
        assert_eq!(hash_message_seed_path(15), HashMessageSeedPath::ShortFinalize);
        assert_eq!(hash_message_seed_path(16), HashMessageSeedPath::LongBlockThenFinalize);
        assert_eq!(hash_message_first_block_message_bytes(16), 16);
        assert_eq!(hash_message_tail_message_bytes(16), 0);
        assert_eq!(hash_message_first_block_message_bytes(100), 16);
        assert_eq!(hash_message_tail_message_bytes(100), 84);
    }

    #[test]
    fn hash_message_compression_budget_grows_with_mlen() {
        assert!(hash_message_compression_budget(0) < hash_message_compression_budget(128));
        assert!(hash_message_compression_budget(128) <= hash_message_compression_budget(512));
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
