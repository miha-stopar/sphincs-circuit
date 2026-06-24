//! Real SPHINCS+ verify glue as NeutronNova **`C_core`** (Phase 2).
//!
//! Incremental rollout:
//! - [`VerifyCorePhase::HashMessage`] — `hash_message` + shared link digests (`fold_verify_core_hash_message`)
//! - [`VerifyCorePhase::Full`] — full `synthesize_verify_core` (future)
//!
//! **Public `mlen` rollout:** Phase 2 smoke keeps `mlen` as a **synthesis-time constant**
//! on the circuit struct (fixed per proof instance). The final v1 statement still has public
//! `mlen` ([`circuit_spec::VerifyPublic`]); wiring variable public `mlen` into
//! `hash_message_bits` (muxed preimage / trace alignment) is deferred to
//! [`VerifyCorePhase::Full`] + Spartan public IO — see `docs/HACKMD_NEUTRONNOVA_PLAN.md` §Phase 2.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_message_padding, link_shared_slice,
    synthesize_hash_message, hash_msg::SPX_DGST_BYTES, thash::SPX_N,
};

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// Which slice of the verify core is synthesized in this circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyCorePhase {
    /// `hash_message(R, PK, M)` + trace link digest checks on shared bus.
    HashMessage,
    /// Full `synthesize_verify_core` (not wired yet).
    Full,
}

/// NeutronNova core carrying real SPHINCS+ verify constraints.
///
/// Shares the same `shared()` layout as [`super::FoldStepBoundCircuit`] (`8 × num_links`
/// field elements) so step compressions and core glue reference identical link variables.
#[derive(Clone, Debug)]
pub struct FoldVerifyCoreCircuit {
    pub phase: VerifyCorePhase,
    pub pk: [u8; SPHINCS_PK_BYTES],
    /// Padded message buffer (`MESSAGE_MAX_BYTES`); only `message[0..mlen]` is hashed.
    pub message: [u8; MESSAGE_MAX_BYTES],
    pub mlen: usize,
    /// Signature prefix `R` (`SPX_N` bytes).
    pub r: [u8; SPX_N],
    /// Expected MGF1 output from `hash_message` (30 bytes).
    pub hm_mgf: [u8; SPX_DGST_BYTES],
    /// `link_digests[k]` = shared witness for boundary between step `k` and `k+1`.
    pub link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl FoldVerifyCoreCircuit {
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
            link_digests,
            _p: PhantomData,
        }
    }

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
        // Match [`FoldCoreBoundCircuit`] / [`FoldStepBoundCircuit`] segment layout (one public IO).
        Ok(vec![Scalar::ZERO])
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

                for (k, digest) in self.link_digests.iter().enumerate() {
                    enforce_bytes_eq_shared(
                        cs.namespace(|| format!("core_link_{k}")),
                        "trace",
                        digest,
                        link_shared_slice(shared, k),
                    )?;
                }
            }
            VerifyCorePhase::Full => {
                return Err(SynthesisError::AssignmentMissing);
            }
        }

        let x = AllocatedNum::alloc(cs.namespace(|| "core_x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize core_x"))?;
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

/// Extract `R` from a SPHINCS+ signature.
pub fn sig_r(sig: &[u8; SPHINCS_SIG_BYTES]) -> [u8; SPX_N] {
    let mut r = [0u8; SPX_N];
    r.copy_from_slice(&sig[..SPX_N]);
    r
}
