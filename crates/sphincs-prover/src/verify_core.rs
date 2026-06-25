//! Real SPHINCS+ verify glue as NeutronNova **`C_core`** (Phase 2).
//!
//! # Why this module exists
//!
//! M2 arithmetized PQClean `crypto_sign_verify` in `sphincs-circuit` as
//! [`synthesize_verify_core`]. NeutronNova requires a separate [`SpartanCircuit`] for the
//! **core** relation (`C_core`). This module is that adapter: it runs the M2 gadgets inside
//! `precommitted()` so they share the same witness layout conventions as
//! [`super::FoldStepBoundCircuit`] (shared link digests + precommitted gadget aux).
//!
//! Full design write-up: **`docs/VERIFY_CORE.md`**.
//!
//! # Incremental rollout (`VerifyCorePhase`)
//!
//! | Phase | Constructor | `precommitted()` synthesizes | Test |
//! |-------|-------------|------------------------------|------|
//! | **2a** | [`FoldVerifyCoreCircuit::hash_message`] | `hash_message` + link checks only | `fold_verify_core_hash_message` (CI) |
//! | **2b** | [`FoldVerifyCoreCircuit::full`] | Full [`synthesize_verify_core`] | `fold_verify_core_full_*` (`#[ignore]`, release) |
//! | **2c** | [`FoldVerifyCoreCircuit::with_public_io`] | `public_values` = `(mlen, PK, M)` — 1033 scalars; fixed `mlen` per instance | `fold_verify_core_hash_message_public_io` (CI) |
//!
//! # SpartanCircuit layout
//!
//! ```text
//! shared()       → link_digests[k] as field elements (must match FoldStepBoundCircuit)
//! precommitted() → phase gadget + enforce_bytes_eq_shared per link + inputize core_x
//! synthesize()   → (empty — constraints live in precommitted, like FoldStepCircuit)
//! public_values()→ [0] placeholder, or 1033 scalars when [`FoldVerifyCoreCircuit::public_io`]
//! ```
//!
//! # Message / padding
//!
//! - `message` is `[u8; MESSAGE_MAX_BYTES]` with zero tail; only `message[0..mlen]` is hashed.
//! - [`enforce_message_padding`] is a **synthesis-time** zero-tail check (no ~4k orphan
//!   `AllocatedBit`s — that broke NeutronNova `C_core` layout; see `SHARED_WITNESS_DEBUG.md`).
//! - `mlen` is a **synthesis-time constant** on the struct (fixed per proof instance). Variable
//!   public `mlen` is Phase 2c — see `docs/HACKMD_NEUTRONNOVA_PLAN.md` §Phase 2.
//!
//! # Phase Full — witness hints
//!
//! No `hm_expected` or `intermediate_roots` fields. WOTS topology follows chained `root_bits`.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_message_padding, link_shared_slice,
    inputize_verify_public, pack_verify_public, enforce_public_matches_statement,
    synthesize_hash_message, synthesize_verify_core, hash_msg::SPX_DGST_BYTES, thash::SPX_N,
};

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// Which slice of the verify core is synthesized in [`FoldVerifyCoreCircuit::precommitted`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyCorePhase {
    /// Phase 2a: `hash_message(R, PK, M)` + shared link digest checks on the shared bus.
    ///
    /// Smaller than [`Self::Full`] — use to debug NeutronNova `C_core` layout before enabling
    /// the full FORS / hypertree / root pipeline.
    HashMessage,
    /// Phase 2b: entire [`synthesize_verify_core`] (hash_message → FORS → 7× hypertree → root).
    Full,
}

/// Pin each `link_digests[k]` (trace bytes) to the corresponding shared link variables.
///
/// Shared layout: `8` field words per link digest (`DIGEST_WORDS`), same as
/// [`super::FoldStepBoundCircuit`]. When `link_digests` is empty (plain-step tests), this is a no-op.
fn enforce_core_shared_links<Scalar, CS>(
    cs: &mut CS,
    shared: &[AllocatedNum<Scalar>],
    link_digests: &[[u8; 32]],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    for (k, digest) in link_digests.iter().enumerate() {
        enforce_bytes_eq_shared(
            cs.namespace(|| format!("core_link_{k}")),
            "trace",
            digest,
            link_shared_slice(shared, k),
        )?;
    }
    Ok(())
}

/// NeutronNova **core** carrying real SPHINCS+ verify constraints.
///
/// # Shared witness
///
/// `shared()` allocates `link_digests.len() × DIGEST_WORDS` field elements. Every folded step
/// instance and this core **must** use the same shared commitment (`comm_W_shared`) with
/// identical column indices — see `docs/SHARED_WITNESS_DEBUG.md`.
///
/// # Constructors
///
/// - [`Self::hash_message`] — Phase 2a smoke (hash only).
/// - [`Self::full`] — Phase 2b (full verify). Prefer
///   [`super::verify_witness::fold_verify_core_from_pqclean`] for PQClean KATs.
#[derive(Clone, Debug)]
pub struct FoldVerifyCoreCircuit {
    pub phase: VerifyCorePhase,
    pub pk: [u8; SPHINCS_PK_BYTES],
    /// Padded message buffer (`MESSAGE_MAX_BYTES`); only `message[0..mlen]` is hashed.
    pub message: [u8; MESSAGE_MAX_BYTES],
    /// Active message length (synthesis-time constant until Phase 2c public IO).
    pub mlen: usize,
    /// Signature prefix `R` (`SPX_N` bytes) — used by `hash_message`.
    pub r: [u8; SPX_N],
    /// Expected raw MGF1 output (30 B) — enforced in R1CS; parsed fields derived in-circuit.
    pub hm_mgf: [u8; SPX_DGST_BYTES],
    /// Full verify only: complete signature.
    pub signature: Option<[u8; SPHINCS_SIG_BYTES]>,
    /// `link_digests[k]` = expected bytes at boundary between step `k` and `k+1` on the trace.
    pub link_digests: Vec<[u8; 32]>,
    /// When true, expose `(mlen, PK, M_padded)` via Spartan `public_values` + `inputize`.
    /// See `sphincs_circuit::verify_public_io` and `docs/VERIFY_CORE.md` §Public Spartan IO.
    pub public_io: bool,
    _p: PhantomData<Scalar>,
}

impl FoldVerifyCoreCircuit {
    /// Phase 2a: `hash_message` + optional shared link checks (no FORS / hypertree).
    pub fn hash_message(
        pk: [u8; SPHINCS_PK_BYTES],
        message: [u8; MESSAGE_MAX_BYTES],
        mlen: usize,
        r: [u8; SPX_N],
        hm_mgf: [u8; SPX_DGST_BYTES],
        link_digests: Vec<[u8; 32]>,
    ) -> Self {
        assert!(mlen <= MESSAGE_MAX_BYTES);
        Self {
            phase: VerifyCorePhase::HashMessage,
            pk,
            message,
            mlen,
            r,
            hm_mgf,
            signature: None,
            link_digests,
            public_io: false,
            _p: PhantomData,
        }
    }

    /// Enable public Spartan IO: verifier sees `(mlen, PK, M_padded)` per [DECISIONS.md](../../docs/DECISIONS.md).
    ///
    /// `mlen` is still fixed at circuit-build time for `hash_message` SHA length; the public scalar
    /// is constrained to match. Variable public `mlen` in one universal circuit is a later step.
    ///
    /// # Testing
    ///
    /// ```bash
    /// cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
    /// ```
    pub fn with_public_io(mut self) -> Self {
        self.public_io = true;
        self
    }

    /// Phase 2b/2c: full [`synthesize_verify_core`] inside `C_core`.
    ///
    /// **Phase 2c:** no `hm_expected`; WOTS topology from chained witness roots (no `intermediate_roots`).
    ///
    /// Prefer [`super::verify_witness::fold_verify_core_from_pqclean`] for PQClean KATs.
    ///
    /// # Testing
    ///
    /// ```bash
    /// cargo test -p sphincs-prover --features pqclean --release \
    ///   --test fold_verify_core_full fold_verify_core_full_setup -- --ignored --nocapture
    /// ```
    pub fn full(
        pk: [u8; SPHINCS_PK_BYTES],
        message: [u8; MESSAGE_MAX_BYTES],
        mlen: usize,
        signature: [u8; SPHINCS_SIG_BYTES],
        r: [u8; SPX_N],
        hm_mgf: [u8; SPX_DGST_BYTES],
        link_digests: Vec<[u8; 32]>,
    ) -> Self {
        assert!(mlen <= MESSAGE_MAX_BYTES);
        Self {
            phase: VerifyCorePhase::Full,
            pk,
            message,
            mlen,
            r,
            hm_mgf,
            signature: Some(signature),
            link_digests,
            public_io: false,
            _p: PhantomData,
        }
    }

    /// Number of step↔step link digests (= `link_digests.len()` = shared columns / 8).
    pub fn num_links(&self) -> usize {
        self.link_digests.len()
    }
}

fn alloc_all_link_digests<Scalar, CS>(
    mut cs: CS,
    link_digests: &[[u8; 32]],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut nums = Vec::with_capacity(link_digests.len() * sphincs_circuit::DIGEST_WORDS);
    for (k, digest) in link_digests.iter().enumerate() {
        nums.extend(alloc_digest_shared(
            cs.namespace(|| format!("link_{k}")),
            "link",
            *digest,
        )?);
    }
    Ok(nums)
}

impl SpartanCircuit<E> for FoldVerifyCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        if self.public_io {
            Ok(pack_verify_public(&self.pk, &self.message, self.mlen))
        } else {
            // Placeholder matching FoldStepBoundCircuit / FoldCoreBoundCircuit
            // (Spartan2 requires ≥1 inputized column via dummy `core_x`).
            Ok(vec![Scalar::ZERO])
        }
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_link_digests(cs.namespace(|| "core_shared_links"), &self.link_digests)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        match self.phase {
            VerifyCorePhase::HashMessage => {
                enforce_message_padding(
                    cs.namespace(|| "msg_pad"),
                    &self.message,
                    self.mlen,
                )?;
                synthesize_hash_message(
                    cs.namespace(|| "hash_message"),
                    &self.r,
                    &self.pk,
                    &self.message,
                    self.mlen,
                    &self.hm_mgf,
                )?;

                enforce_core_shared_links(
                    &mut cs.namespace(|| "links"),
                    shared,
                    &self.link_digests,
                )?;
            }
            VerifyCorePhase::Full => {
                let signature = self
                    .signature
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?;

                synthesize_verify_core(
                    cs.namespace(|| "verify_core"),
                    &self.pk,
                    &self.message,
                    self.mlen,
                    signature,
                    &self.hm_mgf,
                )?;

                enforce_core_shared_links(
                    &mut cs.namespace(|| "links"),
                    shared,
                    &self.link_digests,
                )?;
            }
        }

        if self.public_io {
            let public = self.public_values()?;
            let input = inputize_verify_public(cs.namespace(|| "public_io"), &public)?;
            enforce_public_matches_statement(
                cs.namespace(|| "public_stmt"),
                &input,
                &self.pk,
                &self.message,
                self.mlen,
            )?;
        } else {
            // Spartan2 requires at least one inputized witness column in precommitted.
            let x = AllocatedNum::alloc(cs.namespace(|| "core_x"), || Ok(Scalar::ZERO))?;
            x.inputize(cs.namespace(|| "inputize core_x"))?;
        }
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        // All constraints are allocated in precommitted() — same pattern as FoldStepCircuit.
        Ok(())
    }
}

/// Build `MESSAGE_MAX_BYTES` buffer with zero tail (v1 padded-message policy).
pub fn padded_message(msg: &[u8]) -> ([u8; MESSAGE_MAX_BYTES], usize) {
    assert!(msg.len() <= MESSAGE_MAX_BYTES);
    let mut padded = [0u8; MESSAGE_MAX_BYTES];
    padded[..msg.len()].copy_from_slice(msg);
    (padded, msg.len())
}

/// Exact-length message (no tail buffer). Prefer [`padded_message`] for verify-core circuits.
pub fn message_bytes(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() <= MESSAGE_MAX_BYTES);
    msg.to_vec()
}

/// Extract `R` (first `SPX_N` bytes) from a SPHINCS+ signature.
pub fn sig_r(sig: &[u8; SPHINCS_SIG_BYTES]) -> [u8; SPX_N] {
    let mut r = [0u8; SPX_N];
    r.copy_from_slice(&sig[..SPX_N]);
    r
}
