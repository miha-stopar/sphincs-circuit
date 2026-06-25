//! Top-level SPHINCS+ verify core — composes all M2 gadgets into the PQClean
//! `crypto_sign_verify` pipeline:
//!
//! ```text
//! hash_message(R, PK, M) → mhash, tree, idx_leaf
//! fors_pk_from_sig(sig_fors, mhash) → root
//! for layer in 0..7:
//!     wots_pk_from_sig → thash(leaf) → compute_root → root
//! root == PK.root
//! ```
//!
//! # NeutronNova integration
//!
//! Wrapped by [`sphincs_prover::FoldVerifyCoreCircuit`] (`VerifyCorePhase::Full`) as `C_core`.
//! See **`docs/VERIFY_CORE.md`** for the prover adapter, tests, and staged rollout.
//!
//! # Phase 2c — `hm_mgf` only (no `hm_expected`)
//!
//! [`synthesize_verify_core`] takes a single 30-byte **`hm_mgf`** witness. [`synthesize_hash_message_parsed`]
//! enforces `mgf_bits == hm_mgf` and returns `mhash` / `tree` / `leaf_idx` by reading those witness
//! bits at synthesis time ([`hash_message_output_from_mgf_bits`]). There is no separate trusted
//! `hm_expected` parameter.
//!
//! **WOTS topology:** `chain_lengths` follow witness root bits via [`crate::thash::witness_bytes_from_bits`]
//! in [`crate::hypertree::hypertree_layer_from_root_bits`] — no `intermediate_roots` oracle.

use crate::fors::{fors_pk_from_sig_bits, SPX_FORS_BYTES};
use crate::hash_message_trace::{synthesize_hash_message_parsed_with_trace, HashMessageTraceInputs};
use crate::hash_msg::{
    synthesize_hash_message_parsed, synthesize_hash_message_parsed_public, HashMessageOutput,
    SPX_DGST_BYTES, SPX_PK_BYTES,
};
use crate::hypertree::{hypertree_layer_from_root_bits, SPX_TREE_AUTH_BYTES, SPX_TREE_HEIGHT};
use crate::thash::{enforce_bits_equal_bytes, ADDR_BYTES, SPX_N};
use crate::verify_public_io::InputizedVerifyPublic;
use crate::wots::SPX_WOTS_BYTES;
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
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

/// Enforce the inactive message suffix `message[mlen..]` is all zero **at synthesis time**.
///
/// `hash_message_bits` only allocates witness for `message[0..mlen]`; tail bytes are not part of
/// the R1CS witness. When the circuit is built from a PQClean trace (or any honest setup), the
/// buffer tail must already be zero — this function checks that without adding ~`(M_MAX - mlen)`
/// boolean constraints (which breaks NeutronNova `C_core` witness layout when `M_MAX` is large).
///
/// Soundness: with public `mlen`, the relation only hashes `message[0..mlen]`; inactive bytes are
/// not witness and cannot be chosen by a malicious prover.
pub fn enforce_message_padding<Scalar, CS>(
    _cs: CS,
    message: &[u8],
    mlen: usize,
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(message.len() >= mlen);
    for i in mlen..message.len().min(MESSAGE_MAX_BYTES) {
        if message[i] != 0 {
            return Err(SynthesisError::AssignmentMissing);
        }
    }
    Ok(())
}

/// Per-byte R1CS padding: `(pad_bit[i] == 0)` for each inactive byte witness.
///
/// Only use when inactive message bytes are allocated as witness (not the default `hash_message`
/// path). Avoid on NeutronNova `C_core` at `M_MAX` scale — use [`enforce_message_padding`] instead.
pub fn enforce_message_padding_witness<Scalar, CS>(
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

/// In-circuit verify core when all constraints are satisfied.
///
/// `mhash` / `tree` / `leaf_idx` come from witness `mgf_bits` via [`synthesize_hash_message_parsed`].
/// Hypertree layers chain `root_bits` from FORS through WOTS/Merkle; WOTS topology uses
/// [`witness_bytes_from_bits`] on those roots (no `intermediate_roots` oracle).
#[allow(clippy::too_many_arguments)]
pub fn synthesize_verify_core<Scalar, CS>(
    mut cs: CS,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm_mgf: &[u8; SPX_DGST_BYTES],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= message.len());
    enforce_message_padding(&mut cs, message, mlen)?;

    let r = {
        let mut a = [0u8; SPX_N];
        a.copy_from_slice(&signature[..SIG_R_BYTES]);
        a
    };
    let mut pk32 = [0u8; SPX_PK_BYTES];
    pk32.copy_from_slice(pk);

    let hm = synthesize_hash_message_parsed(
        cs.namespace(|| "hash_message"),
        &r,
        &pk32,
        message,
        mlen,
        hm_mgf,
    )?;

    synthesize_verify_core_tail(cs.namespace(|| "verify_tail"), pk, signature, &hm)
}

/// Full verify core with `hash_message` preimage wired from public Spartan `PK` / `M` columns.
///
/// Used when [`sphincs_prover::FoldVerifyCoreCircuit::public_io`] and [`VerifyCorePhase::Full`].
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit valid_signature_satisfies_core_public --release -- --ignored
/// ```
#[allow(clippy::too_many_arguments)]
pub fn synthesize_verify_core_public<Scalar, CS>(
    mut cs: CS,
    public: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm_mgf: &[u8; SPX_DGST_BYTES],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    enforce_message_padding(&mut cs, message, mlen)?;

    let r = {
        let mut a = [0u8; SPX_N];
        a.copy_from_slice(&signature[..SIG_R_BYTES]);
        a
    };

    let hm = synthesize_hash_message_parsed_public(
        cs.namespace(|| "hash_message"),
        &r,
        public,
        pk,
        message,
        mlen,
        hm_mgf,
    )?;

    synthesize_verify_core_tail(cs.namespace(|| "verify_tail"), pk, signature, &hm)
}

/// Full verify core with trace-linked `hash_message` seed-SHA (FORS / hypertree unchanged).
#[allow(clippy::too_many_arguments)]
pub fn synthesize_verify_core_with_trace<Scalar, CS>(
    mut cs: CS,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm_mgf: &[u8; SPX_DGST_BYTES],
    trace: &HashMessageTraceInputs,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= message.len());
    enforce_message_padding(&mut cs, message, mlen)?;

    let r = {
        let mut a = [0u8; SPX_N];
        a.copy_from_slice(&signature[..SIG_R_BYTES]);
        a
    };

    let hm = synthesize_hash_message_parsed_with_trace(
        cs.namespace(|| "hash_message"),
        &r,
        pk,
        message,
        mlen,
        trace,
        hm_mgf,
        shared,
    )?;

    synthesize_verify_core_tail(cs.namespace(|| "verify_tail"), pk, signature, &hm)
}

/// Full verify core with public IO statement + trace-linked `hash_message`.
///
/// The `public` columns are tied to `pk` / `message` by the caller via
/// [`crate::verify_public_io::enforce_public_matches_statement`] (or `_pk_message`); the seed hash
/// here is reconstructed from `message` so the hashed preimage is bound to the public statement.
#[allow(clippy::too_many_arguments)]
pub fn synthesize_verify_core_public_with_trace<Scalar, CS>(
    mut cs: CS,
    _public: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm_mgf: &[u8; SPX_DGST_BYTES],
    trace: &HashMessageTraceInputs,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    enforce_message_padding(&mut cs, message, mlen)?;

    let r = {
        let mut a = [0u8; SPX_N];
        a.copy_from_slice(&signature[..SIG_R_BYTES]);
        a
    };

    let hm = synthesize_hash_message_parsed_with_trace(
        cs.namespace(|| "hash_message"),
        &r,
        pk,
        message,
        mlen,
        trace,
        hm_mgf,
        shared,
    )?;

    synthesize_verify_core_tail(cs.namespace(|| "verify_tail"), pk, signature, &hm)
}

fn synthesize_verify_core_tail<Scalar, CS>(
    mut cs: CS,
    pk: &[u8; SPHINCS_PK_BYTES],
    signature: &[u8; SPHINCS_SIG_BYTES],
    hm: &HashMessageOutput,
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
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

    let mut tree = hm.tree;
    let mut idx_leaf = hm.leaf_idx;

    // 2. fors_pk_from_sig
    let mut fors_addr = [0u8; ADDR_BYTES];
    fors_addr = set_type(&fors_addr, SPX_ADDR_TYPE_WOTS);
    fors_addr = set_tree_addr(&fors_addr, tree);
    fors_addr = set_keypair_addr(&fors_addr, idx_leaf);

    let mut fors_sig = [0u8; SPX_FORS_BYTES];
    fors_sig.copy_from_slice(&signature[SIG_R_BYTES..SIG_AFTER_FORS]);

    let mhash = hm.mhash;

    let fors_pk_bits = fors_pk_from_sig_bits(
        cs.namespace(|| "fors"),
        &pub_seed,
        &fors_addr,
        &fors_sig,
        &mhash,
    )?;
    let mut root_bits = fors_pk_bits;
    let mut sig_off = SIG_AFTER_FORS;

    // 3. Seven hypertree layers — root_bits chains layer to layer.
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

        root_bits = hypertree_layer_from_root_bits(
            cs.namespace(|| format!("layer_{layer}")),
            &pub_seed,
            &wots_addr,
            &wots_pk_addr,
            &tree_addr,
            &sig_wots,
            &root_bits,
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
    use crate::hash_msg::hash_message_mgf_buf;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use sphincs_ref::{sign_deterministic, CRYPTO_SEEDBYTES};

    /// Phase 2c regression: corrupt `hm_mgf` must fail `mgf_bits == hm_mgf` (fast — hash_message only).
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit wrong_hm_mgf_unsatisfies_parsed_hash_message
    /// ```
    #[test]
    fn wrong_hm_mgf_unsatisfies_parsed_hash_message() {
        let seed = [7u8; CRYPTO_SEEDBYTES];
        let msg = b"wrong mgf must fail";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let r = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&sig[..16]);
            a
        };
        let mut hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());
        hm_mgf[0] ^= 0xff;

        let mut padded = vec![0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);

        let mut cs = TestConstraintSystem::<Fr>::new();
        enforce_message_padding(&mut cs, &padded, msg.len()).expect("pad");
        synthesize_hash_message_parsed(&mut cs, &r, &pk, &padded, msg.len(), &hm_mgf)
            .expect("synth");
        assert!(!cs.is_satisfied(), "corrupt hm_mgf must break mgf_bits == hm_mgf");
    }

    /// Full M2 verify core R1CS on a PQClean KAT signature (slow).
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit valid_signature_satisfies_core --release -- --ignored --nocapture
    /// ```
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
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());

        let mut padded = vec![0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);

        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_verify_core(
            &mut cs,
            &pk,
            &padded,
            msg.len(),
            &sig,
            &hm_mgf,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

    /// Full verify core with public-wired `hash_message` preimage (slow).
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit valid_signature_satisfies_core_public --release -- --ignored
    /// ```
    #[test]
    #[ignore = "full verify core public_io is slow; run with --release --ignored"]
    fn valid_signature_satisfies_core_public() {
        use circuit_spec::VerifyPublic;
        use crate::verify_public_io::{inputize_verify_public, pack_verify_public};

        let seed = [0xabu8; CRYPTO_SEEDBYTES];
        let msg = b"sphincs verify core public io test";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

        let r = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&sig[..16]);
            a
        };
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());

        let mut padded = [0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);
        let stmt = VerifyPublic::from_message(pk, msg);
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        synthesize_verify_core_public(
            &mut cs,
            &input,
            &pk,
            &padded,
            msg.len(),
            &sig,
            &hm_mgf,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

    /// Full verify core with trace-linked `hash_message` (slow).
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit valid_signature_satisfies_core_trace --release -- --ignored
    /// ```
    #[test]
    #[ignore = "full verify core trace hash_message is slow; run with --release --ignored"]
    fn valid_signature_satisfies_core_trace() {
        use crate::hash_message_trace::{
            locate_hash_message_trace_span_for_mlen, HashMessageTraceInputs,
        };
        use sphincs_ref::verify_with_trace;

        let seed = [0xadu8; CRYPTO_SEEDBYTES];
        let msg = b"verify core trace hash_message";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let rows: Vec<circuit_spec::Sha256Compression> = trace
            .compressions
            .iter()
            .map(|r| circuit_spec::Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();

        let r = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&sig[..16]);
            a
        };
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());
        let span =
            locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, msg.len()).expect("span");
        let trace_inputs = HashMessageTraceInputs::from_span(&rows, &span);

        let mut padded = vec![0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);

        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_verify_core_with_trace(
            &mut cs,
            &pk,
            &padded,
            msg.len(),
            &sig,
            &hm_mgf,
            &trace_inputs,
            &[],
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

    /// SOUNDNESS regression at the full-core level: trace-linked `hash_message` must be bound to
    /// the message, so a one-byte change in the message buffer breaks satisfaction.
    #[test]
    #[ignore = "full verify core trace hash_message is slow; run with --release --ignored"]
    fn verify_core_trace_rejects_message_mismatch() {
        use crate::hash_message_trace::{
            locate_hash_message_trace_span_for_mlen, HashMessageTraceInputs,
        };
        use sphincs_ref::verify_with_trace;

        let seed = [0xaeu8; CRYPTO_SEEDBYTES];
        let msg = b"verify core trace mismatch";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let rows: Vec<circuit_spec::Sha256Compression> = trace
            .compressions
            .iter()
            .map(|r| circuit_spec::Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();

        let r = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&sig[..16]);
            a
        };
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, msg.len());
        let span =
            locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, msg.len()).expect("span");
        let trace_inputs = HashMessageTraceInputs::from_span(&rows, &span);

        // Corrupt the message buffer (same length); seed hash now differs from `hm_mgf`.
        let mut padded = vec![0u8; MESSAGE_MAX_BYTES];
        padded[..msg.len()].copy_from_slice(msg);
        padded[0] ^= 0x01;

        let mut cs = TestConstraintSystem::<Fr>::new();
        let res = synthesize_verify_core_with_trace(
            &mut cs,
            &pk,
            &padded,
            msg.len(),
            &sig,
            &hm_mgf,
            &trace_inputs,
            &[],
        );
        assert!(res.is_err() || !cs.is_satisfied());
    }

    /// Full verify core + public IO + muxed `hash_message` at multiple `mlen` values (slow).
    ///
    /// Step D: exercises [`synthesize_verify_core_public`] with short and long PQClean branches.
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit valid_signature_satisfies_core_variable_mlen --release -- --ignored
    /// ```
    #[test]
    #[ignore = "full verify core variable mlen public_io is slow; run with --release --ignored"]
    fn valid_signature_satisfies_core_variable_mlen() {
        use circuit_spec::VerifyPublic;
        use crate::verify_public_io::{
            enforce_public_inactive_chunks_zero, enforce_public_mlen_in_range,
            inputize_verify_public, pack_verify_public,
        };

        let cases: &[(usize, &[u8])] = &[
            (5, b"short"),
            (16, b"sixteen bytes!!!"),
            (100, &[0xcd; 100][..]),
        ];

        for &(mlen, msg) in cases {
            let seed = [0xacu8; CRYPTO_SEEDBYTES];
            let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
            let r = {
                let mut a = [0u8; 16];
                a.copy_from_slice(&sig[..16]);
                a
            };
            let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
            let mut padded = [0u8; MESSAGE_MAX_BYTES];
            padded[..mlen].copy_from_slice(msg);
            let stmt = VerifyPublic::from_message(pk, msg);
            let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, mlen);

            let mut cs = TestConstraintSystem::<Fr>::new();
            let input = inputize_verify_public(&mut cs, &public).expect("inputize");
            enforce_public_mlen_in_range(&mut cs, &input).expect("range");
            enforce_public_inactive_chunks_zero(&mut cs, &input, mlen).expect("tail");
            synthesize_verify_core_public(
                &mut cs,
                &input,
                &pk,
                &padded,
                mlen,
                &sig,
                &hm_mgf,
            )
            .expect("synth");
            assert!(cs.is_satisfied(), "mlen={mlen}");
        }
    }

    #[test]
    fn message_padding_rejects_nonzero_tail_at_synthesis() {
        let mut padded = [0u8; MESSAGE_MAX_BYTES];
        padded[0] = 1;
        padded[10] = 2; // nonzero in inactive region when mlen=5
        let mut cs = TestConstraintSystem::<Fr>::new();
        let err = enforce_message_padding(&mut cs, &padded, 5).unwrap_err();
        assert!(matches!(err, SynthesisError::AssignmentMissing));
    }

    #[test]
    fn message_padding_mgf_padded_buffer_satisfies() {
        let r = [0x11u8; 16];
        let pk = [0x22u8; 32];
        let msg = b"padded buffer hash_message";
        let mlen = msg.len();
        let (padded, _) = {
            let mut buf = [0u8; MESSAGE_MAX_BYTES];
            buf[..mlen].copy_from_slice(msg);
            (buf, mlen)
        };
        let hm_mgf = hash_message_mgf_buf(&r, &pk, msg, mlen);
        let mut cs = TestConstraintSystem::<Fr>::new();
        enforce_message_padding(&mut cs, &padded, mlen).expect("pad");
        synthesize_hash_message_parsed(&mut cs, &r, &pk, &padded, mlen, &hm_mgf).expect("hm");
        assert!(cs.is_satisfied());
    }
}
