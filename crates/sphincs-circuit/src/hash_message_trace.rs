//! PQClean trace ↔ `hash_message` compression span (variable-`mlen` step E).
//!
//! Locates the seed-SHA and MGF1 local chains in a verify trace and provides
//! exact compression counts from SHA-256 padding math (validated against PQClean).

use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circuit_spec::{Sha256Compression, SPHINCS_PK_BYTES};
use ff::PrimeField;

use crate::hash_msg::{
    hash_message_seed_path, hash_message_tail_message_bytes, mgf1_digest_bits, parse_mgf_output,
    HashMessageOutput, HashMessageSeedPath, HASH_MESSAGE_INBUF_BYTES, HASH_MESSAGE_PREFIX_BYTES,
    SPX_DGST_BYTES, SPX_PK_BYTES,
};
use crate::thash::enforce_bits_equal_bytes;
use crate::sha256_compress::sha256_state_words_to_bits_be;
use crate::shared_link::{enforce_words_eq_shared, link_shared_slice, DIGEST_WORDS};
use crate::step::StepInput;
use crate::thash::SPX_N;
use crate::witness::LocalChain;
use bellpepper::gadgets::sha256::sha256_compression_function;
use bellpepper::gadgets::uint32::UInt32;

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3), as eight big-endian state words.
///
/// Used to pin the first seed compression's `h_in` so the prover cannot start the seed hash
/// from an arbitrary chaining value. See [`seed_hash_words_bound`].
const SHA256_IV: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

/// Number of SHA-256 compressions for one-shot digest of `byte_len` bytes from the IV.
pub const fn sha256_compression_count_fresh(byte_len: usize) -> usize {
    let mut total = byte_len + 1 + 8;
    while total % 64 != 0 {
        total += 1;
    }
    total / 64
}

/// Compressions for `sha256_inc_finalize` after one full 64-byte `inc_blocks` absorb.
pub fn sha256_compression_count_after_full_block(tail_byte_len: usize) -> usize {
    let stream_len = HASH_MESSAGE_INBUF_BYTES + tail_byte_len;
    sha256_compression_count_fresh(stream_len).saturating_sub(1)
}

/// Seed-SHA compressions in PQClean `hash_message` for message length `mlen`.
pub fn hash_message_seed_compression_count(mlen: usize) -> usize {
    match hash_message_seed_path(mlen) {
        HashMessageSeedPath::ShortFinalize => {
            sha256_compression_count_fresh(HASH_MESSAGE_PREFIX_BYTES + mlen)
        }
        HashMessageSeedPath::LongBlockThenFinalize => {
            1 + sha256_compression_count_after_full_block(hash_message_tail_message_bytes(mlen))
        }
    }
}

/// MGF1 compressions for 128s (`SPX_DGST_BYTES` = 30 → one truncated SHA-256 on 52 bytes).
pub fn hash_message_mgf1_compression_count() -> usize {
    sha256_compression_count_fresh(48 + 4)
}

/// Exact `hash_message` compression count (seed + MGF1) for folding / trace alignment.
pub fn hash_message_compression_count_exact(mlen: usize) -> usize {
    hash_message_seed_compression_count(mlen) + hash_message_mgf1_compression_count()
}

/// Contiguous seed-SHA + MGF1 compression ranges inside a verify trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageTraceSpan {
    pub seed: LocalChain,
    pub mgf1: LocalChain,
}

/// PQClean compression rows for a located [`HashMessageTraceSpan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageTraceInputs {
    pub seed_rows: Vec<StepInput>,
    pub mgf1_rows: Vec<StepInput>,
}

impl HashMessageTraceInputs {
    pub fn from_span(rows: &[Sha256Compression], span: &HashMessageTraceSpan) -> Self {
        Self {
            seed_rows: rows[span.seed.start..=span.seed.end]
                .iter()
                .map(crate::witness::step_input_from_row)
                .collect(),
            mgf1_rows: rows[span.mgf1.start..=span.mgf1.end]
                .iter()
                .map(crate::witness::step_input_from_row)
                .collect(),
        }
    }

    pub fn total_compressions(&self) -> usize {
        self.seed_rows.len() + self.mgf1_rows.len()
    }
}

impl HashMessageTraceSpan {
    pub fn total_compressions(&self) -> usize {
        self.seed.len + self.mgf1.len
    }

    /// Contiguous trace indices covering seed-SHA and MGF1.
    pub fn full_chain(&self) -> LocalChain {
        LocalChain {
            start: self.seed.start,
            end: self.mgf1.end,
            len: self.total_compressions(),
        }
    }
}

fn pk_seed_bytes(pk: &[u8; SPHINCS_PK_BYTES]) -> [u8; SPX_N] {
    let mut out = [0u8; SPX_N];
    out.copy_from_slice(&pk[..SPX_N]);
    out
}

fn block_starts_with_hash_message_seed(
    block: &[u8; 64],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> bool {
    block[..SPX_N] == *r && block[SPX_N..SPX_N + SPX_PK_BYTES] == pk[..]
}

/// MGF1 preimage starts with `R ‖ pk_seed ‖ seed_hash[0..16]` (not `PK.root` at bytes 32–48).
fn block_starts_with_mgf1_seed(
    block: &[u8; 64],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> bool {
    let pk_seed = pk_seed_bytes(pk);
    block[..SPX_N] == *r
        && block[SPX_N..2 * SPX_N] == pk_seed
        && block[2 * SPX_N..SPX_N + SPX_PK_BYTES] != pk[SPX_N..]
}

fn extend_local_chain(compressions: &[Sha256Compression], start: usize) -> LocalChain {
    let mut end = start;
    while end + 1 < compressions.len() && compressions[end].h_out == compressions[end + 1].h_in {
        end += 1;
    }
    LocalChain {
        start,
        end,
        len: end - start + 1,
    }
}

/// Locate `hash_message` seed + MGF1 chains in a PQClean verify compression trace.
///
/// Returns the **first** span whose seed chain is immediately followed by an MGF1 round-0 block.
/// When `mlen` is known, prefer [`locate_hash_message_trace_span_for_mlen`] to disambiguate
/// rare collisions (e.g. all-zero 16-byte message on the long-path boundary).
pub fn locate_hash_message_trace_span(
    compressions: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> Option<HashMessageTraceSpan> {
    for (i, row) in compressions.iter().enumerate() {
        if !block_starts_with_hash_message_seed(&row.block, r, pk) {
            continue;
        }

        let seed = extend_local_chain(compressions, i);
        let mgf_start = seed.end + 1;
        if mgf_start >= compressions.len() {
            continue;
        }
        let mgf_row = &compressions[mgf_start];
        if !block_starts_with_mgf1_seed(&mgf_row.block, r, pk) {
            continue;
        }
        let mgf_len = hash_message_mgf1_compression_count();
        if mgf_start + mgf_len > compressions.len() {
            continue;
        }
        let mgf1 = LocalChain {
            start: mgf_start,
            end: mgf_start + mgf_len - 1,
            len: mgf_len,
        };
        return Some(HashMessageTraceSpan { seed, mgf1 });
    }
    None
}

/// Locate span and verify compression counts match [`hash_message_compression_count_exact`].
pub fn locate_hash_message_trace_span_for_mlen(
    compressions: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    mlen: usize,
) -> Option<HashMessageTraceSpan> {
    let span = locate_hash_message_trace_span(compressions, r, pk)?;
    if span.seed.len != hash_message_seed_compression_count(mlen) {
        return None;
    }
    if span.mgf1.len != hash_message_mgf1_compression_count() {
        return None;
    }
    Some(span)
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| Boolean::constant((byte >> i) & 1 == 1)))
        .collect()
}


/// Standard SHA-256 padded 64-byte blocks of the seed preimage `R ‖ PK ‖ M[0..mlen]`.
///
/// These blocks are a deterministic function of the **public statement** `(R, PK, M, mlen)`.
/// Binding the in-circuit seed compressions to them (rather than to prover-supplied trace
/// `block` witnesses) is what makes trace-linked `hash_message` sound — see the SOUNDNESS note
/// on [`seed_hash_words_bound`].
///
/// PQClean's incremental hash (`inc_blocks` over the first 64 bytes for `mlen >= 16`, then
/// `inc_finalize` over the tail) absorbs exactly `R ‖ PK ‖ M[0..mlen]`, so the concatenation of
/// all seed compression blocks equals the standard SHA-256 padding of that buffer. The 64-byte
/// chunk boundaries therefore match the PQClean trace's seed compression rows one-for-one.
fn hash_message_seed_blocks(
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> Vec<[u8; 64]> {
    let mut p: Vec<u8> = Vec::with_capacity(HASH_MESSAGE_PREFIX_BYTES + mlen);
    p.extend_from_slice(r);
    p.extend_from_slice(&pk[..SPX_PK_BYTES]);
    p.extend_from_slice(&message[..mlen]);

    let bitlen = (p.len() as u64) * 8;
    p.push(0x80);
    while p.len() % 64 != 56 {
        p.push(0);
    }
    p.extend_from_slice(&bitlen.to_be_bytes());

    p.chunks(64)
        .map(|c| {
            let mut b = [0u8; 64];
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// Compute the seed hash `SHA256(R ‖ PK ‖ M[0..mlen])` in-circuit, bound to the public statement.
///
/// # SOUNDNESS (why this exists)
///
/// The earlier implementation fed the SHA compression **prover-supplied trace `block` and `h_in`
/// witnesses** (`StepInput`) directly. Those witnesses were never constrained to equal
/// `R ‖ PK ‖ M` or the SHA-256 IV, so a malicious prover could hash an entirely different
/// message, satisfy `mgf_bits == hm_mgf` with a matching forged `hm_mgf`, and still produce an
/// accepting proof for an unrelated public `M`. That broke the verify relation for the message.
///
/// This function instead:
/// 1. Reconstructs the seed preimage blocks **from `(R, PK, M, mlen)`** ([`hash_message_seed_blocks`]).
/// 2. Pins the first compression's `h_in` to the SHA-256 [`SHA256_IV`].
/// 3. Feeds each compression a **constant** block derived from the statement (not trace witnesses).
/// 4. Optionally links internal boundaries to the folded `C_step` instances via `shared`
///    (an optimization; soundness no longer depends on it because the core self-computes the hash).
///
/// `M` is bound to the public columns transitively: the caller (`FoldVerifyCoreCircuit`) also runs
/// `enforce_public_matches_statement` / `enforce_public_matches_pk_message`, which tie the public
/// `PK` / `M` columns to the same `self.message` / `self.pk` constants used here.
fn seed_hash_words_bound<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    seed_rows_len: usize,
    shared: &[AllocatedNum<Scalar>],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let blocks = hash_message_seed_blocks(r, pk, message, mlen);

    // The seed compression count is fully determined by `mlen`. Reject any trace whose seed-row
    // count disagrees so a prover cannot inject or drop compressions.
    if blocks.is_empty() || blocks.len() != seed_rows_len {
        return Err(SynthesisError::Unsatisfiable);
    }

    let links_available = shared.len() >= blocks.len().saturating_sub(1) * DIGEST_WORDS;

    let mut h_words: Vec<UInt32> = SHA256_IV.iter().map(|&w| UInt32::constant(w)).collect();
    let mut out_words = h_words.clone();
    for (i, block) in blocks.iter().enumerate() {
        let block_bits = constant_bits(block);
        out_words = sha256_compression_function(
            cs.namespace(|| format!("seed_compress_{i}")),
            &block_bits,
            &h_words,
        )?;
        if i + 1 < blocks.len() {
            if links_available {
                enforce_words_eq_shared(
                    cs.namespace(|| format!("seed_link_{i}")),
                    "h_out",
                    &out_words,
                    link_shared_slice(shared, i),
                )?;
            }
            h_words = out_words.clone();
        }
    }
    Ok(out_words)
}

/// Full `hash_message` bound to the statement `(R, PK, M, mlen)`, with seed compressions optionally
/// linked to folded `C_step` instances.
///
/// - Seed-SHA is reconstructed from `(R, PK, M)` ([`seed_hash_words_bound`]) — **sound**.
/// - `seed_rows.len()` must equal the statement-derived seed compression count, else synthesis fails.
/// - When `shared` carries link columns, internal seed boundaries are tied to folded steps.
/// - MGF1 is computed one-shot over `R ‖ pk_seed ‖ seed_hash`; `trace.mgf1_rows` is metadata the
///   prover uses to *select* folded `C_step` instances and is intentionally unused here.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_hash_message_with_trace<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    trace: &HashMessageTraceInputs,
    expected_mgf: &[u8; SPX_DGST_BYTES],
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let seed_words = seed_hash_words_bound(
        cs.namespace(|| "seed"),
        r,
        pk,
        message,
        mlen,
        trace.seed_rows.len(),
        shared,
    )?;
    let seed_hash_bits = sha256_state_words_to_bits_be(&seed_words);

    let mut seed_bits = constant_bits(r);
    seed_bits.extend(constant_bits(&pk[..SPX_N]));
    seed_bits.extend(seed_hash_bits);
    let mgf_bits = mgf1_digest_bits(cs.namespace(|| "mgf1"), &seed_bits, SPX_DGST_BYTES)?;
    enforce_bits_equal_bytes(cs.namespace(|| "mgf_out"), &mgf_bits, expected_mgf)?;
    Ok(())
}

/// Like [`synthesize_hash_message_with_trace`] but returns parsed [`HashMessageOutput`] for verify core.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_hash_message_parsed_with_trace<Scalar, CS>(
    cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    trace: &HashMessageTraceInputs,
    expected_mgf: &[u8; SPX_DGST_BYTES],
    shared: &[AllocatedNum<Scalar>],
) -> Result<HashMessageOutput, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    synthesize_hash_message_with_trace(cs, r, pk, message, mlen, trace, expected_mgf, shared)?;
    // `expected_mgf` is enforced equal to MGF1(seed); since the seed is bound to (R, PK, M),
    // `expected_mgf` is forced to be the genuine digest and the parsed fields are trustworthy.
    Ok(parse_mgf_output(expected_mgf))
}

/// `hash_message` with seed-SHA reconstructed from `(R, PK, M)` and linked to folded seed rows.
///
/// Thin wrapper around [`synthesize_hash_message_with_trace`] with empty `mgf1_rows`.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_hash_message_with_seed_trace<Scalar, CS>(
    cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    seed_rows: &[StepInput],
    expected_mgf: &[u8; SPX_DGST_BYTES],
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let trace = HashMessageTraceInputs {
        seed_rows: seed_rows.to_vec(),
        mgf1_rows: Vec::new(),
    };
    synthesize_hash_message_with_trace(cs, r, pk, message, mlen, &trace, expected_mgf, shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

    fn trace_rows(msg: &[u8]) -> ([u8; SPHINCS_PK_BYTES], [u8; SPX_N], Vec<Sha256Compression>) {
        let seed = [0x2au8; CRYPTO_SEEDBYTES];
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let r: [u8; SPX_N] = sig[..SPX_N].try_into().expect("R");
        let rows: Vec<Sha256Compression> = trace
            .compressions
            .into_iter()
            .map(|r| Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();
        (pk, r, rows)
    }

    #[test]
    fn sha256_compression_count_fresh_known_values() {
        assert_eq!(sha256_compression_count_fresh(0), 1);
        assert_eq!(sha256_compression_count_fresh(55), 1);
        assert_eq!(sha256_compression_count_fresh(56), 2);
        assert_eq!(sha256_compression_count_fresh(64), 2);
    }

    #[test]
    fn hash_message_seed_count_short_long_boundary() {
        assert_eq!(hash_message_seed_compression_count(15), 2);
        assert_eq!(hash_message_seed_compression_count(16), 2);
        assert_eq!(
            crate::hash_msg::hash_message_first_block_message_bytes(16),
            HASH_MESSAGE_INBUF_BYTES - HASH_MESSAGE_PREFIX_BYTES
        );
    }

    #[test]
    fn hash_message_compression_count_exact_matches_pqclean_trace() {
        for (msg, mlen) in [
            (b"short".as_slice(), 5usize),
            (vec![0u8; 15].as_slice(), 15usize),
            (vec![0u8; 33].as_slice(), 33usize),
            (vec![0xabu8; 512].as_slice(), 512usize),
        ] {
            let (pk, r, rows) = trace_rows(msg);
            let span =
                locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, mlen).expect("locate");
            assert_eq!(
                span.total_compressions(),
                hash_message_compression_count_exact(mlen),
                "mlen={mlen}"
            );
            assert_eq!(span.mgf1.len, hash_message_mgf1_compression_count());
        }
    }

    #[test]
    fn hash_message_compression_count_grows_with_mlen() {
        assert!(
            hash_message_compression_count_exact(0) < hash_message_compression_count_exact(128)
        );
        assert!(
            hash_message_compression_count_exact(128) <= hash_message_compression_count_exact(512)
        );
    }

    #[test]
    fn hash_message_full_trace_linked_satisfies_short_and_long_seed() {
        use bellpepper_core::test_cs::TestConstraintSystem;
        use blstrs::Scalar as Fr;
        use crate::hash_msg::hash_message_mgf_buf;
        use crate::shared_link::alloc_digest_shared;

        for (msg, mlen) in [(b"short".as_slice(), 5usize), (vec![0u8; 15].as_slice(), 15usize)] {
            let (pk, r, rows) = trace_rows(msg);
            let span = locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, mlen).expect("span");
            let trace = HashMessageTraceInputs::from_span(&rows, &span);
            let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);

            let mut cs = TestConstraintSystem::<Fr>::new();
            let shared = if trace.seed_rows.len() >= 2 {
                let link = rows[span.seed.start].h_out;
                alloc_digest_shared(&mut cs, "link0", link).expect("shared")
            } else {
                Vec::new()
            };
            let mut padded = vec![0u8; mlen];
            padded[..msg.len().min(mlen)].copy_from_slice(&msg[..msg.len().min(mlen)]);
            synthesize_hash_message_with_trace(
                &mut cs, &r, &pk, &padded, mlen, &trace, &hm_mgf, &shared,
            )
            .expect("synth");
            assert!(cs.is_satisfied(), "mlen={mlen}");
        }
    }

    /// SOUNDNESS regression: a seed hash bound to the wrong message must NOT satisfy.
    ///
    /// The trace is honest for `msg`, but we synthesize against a different message buffer while
    /// keeping the original `hm_mgf`. Because the seed compressions are reconstructed from the
    /// supplied message (not the trace blocks), the MGF1 output no longer matches `hm_mgf`.
    #[test]
    fn hash_message_trace_rejects_message_mismatch() {
        use bellpepper_core::test_cs::TestConstraintSystem;
        use blstrs::Scalar as Fr;
        use crate::hash_msg::hash_message_mgf_buf;

        let msg = b"short";
        let mlen = msg.len();
        let (pk, r, rows) = trace_rows(msg);
        let span = locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, mlen).expect("span");
        let trace = HashMessageTraceInputs::from_span(&rows, &span);
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);

        // Same length, different content.
        let mut wrong = msg.to_vec();
        wrong[0] ^= 0x01;

        let mut cs = TestConstraintSystem::<Fr>::new();
        // The seed hash is reconstructed from the (constant) message, so a mismatch is rejected
        // either as a synthesis `Unsatisfiable` (constant-folded bits differ) or as an unsatisfied
        // constraint system. Both count as rejection.
        let res = synthesize_hash_message_with_trace(
            &mut cs, &r, &pk, &wrong, mlen, &trace, &hm_mgf, &[],
        );
        assert!(
            res.is_err() || !cs.is_satisfied(),
            "seed hash must be bound to the message, not the trace block"
        );
    }

    #[test]
    fn hash_message_seed_trace_linked_satisfies() {
        use bellpepper_core::test_cs::TestConstraintSystem;
        use blstrs::Scalar as Fr;
        use crate::hash_msg::hash_message_mgf_buf;
        use crate::shared_link::alloc_digest_shared;
        use crate::witness::step_input_from_row;

        let msg = vec![0u8; 15];
        let (pk, r, rows) = trace_rows(&msg);
        let span = locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, 15).expect("span");
        let seed_inputs: Vec<StepInput> = rows[span.seed.start..=span.seed.end]
            .iter()
            .map(step_input_from_row)
            .collect();
        assert_eq!(seed_inputs.len(), 2);

        let hm_mgf = hash_message_mgf_buf(&r, &pk, &msg, 15);
        let link = rows[span.seed.start].h_out;

        let mut cs = TestConstraintSystem::<Fr>::new();
        let shared = alloc_digest_shared(&mut cs, "link0", link).expect("shared");
        synthesize_hash_message_with_seed_trace(
            &mut cs,
            &r,
            &pk,
            &msg,
            15,
            &seed_inputs,
            &hm_mgf,
            &shared,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn hash_message_exact_within_rough_budget() {
        use crate::hash_msg::hash_message_compression_budget;
        for mlen in [0usize, 15, 16, 33, 128, 512] {
            let exact = hash_message_compression_count_exact(mlen);
            let budget = hash_message_compression_budget(mlen);
            assert!(
                exact <= budget + 1,
                "mlen={mlen} exact={exact} budget={budget}"
            );
        }
    }
}
