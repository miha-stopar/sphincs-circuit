//! Relation for zero-knowledge proof of SPHINCS+ signature verification.
//!
//! Locked v1: ZK variant A, padded message — see `docs/DECISIONS.md`.
//! Trace / chaining: `docs/TRACE.md`. Proof system: `docs/PROOF_SYSTEM.md`.

/// SPHINCS+-SHA2-128s simple public key size.
pub const SPHINCS_PK_BYTES: usize = 32;

/// SPHINCS+-SHA2-128s simple signature size.
pub const SPHINCS_SIG_BYTES: usize = 7856;

/// Maximum message length supported by the padded-message circuit (TBD at M2).
pub const MESSAGE_MAX_BYTES: usize = 4096;

/// Public inputs for `R_verify` (variant A: hide signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPublic {
    pub pk: [u8; SPHINCS_PK_BYTES],
    /// Message padded to `MESSAGE_MAX_BYTES`; only first `mlen` bytes are active.
    pub message: [u8; MESSAGE_MAX_BYTES],
    pub mlen: usize,
}

/// Spartan public-input layout for [`VerifyPublic`].
///
/// Scalar order (see `docs/VERIFY_CORE.md` §Public Spartan IO):
///
/// ```text
/// [ mlen | pk[8 SHA-state u32 words] | message[128 × 8 words] ]
/// ```
///
/// `pk` and each 32-byte message chunk use big-endian SHA-256 state word packing
/// ([`sphincs_circuit::sha256_compress::state_bytes_to_words`]).
pub const VERIFY_PUBLIC_MLEN_SCALARS: usize = 1;
/// `SPHINCS_PK_BYTES` / 32 × 8 words — one 32-byte block.
pub const VERIFY_PUBLIC_PK_SCALARS: usize = 8;
/// `MESSAGE_MAX_BYTES` / 32 chunks × 8 words per chunk.
pub const VERIFY_PUBLIC_MSG_SCALARS: usize = (MESSAGE_MAX_BYTES / 32) * 8;
/// Total `public_values().len()` for `FoldVerifyCoreCircuit` with `public_io = true`.
pub const VERIFY_PUBLIC_NUM_SCALARS: usize =
    VERIFY_PUBLIC_MLEN_SCALARS + VERIFY_PUBLIC_PK_SCALARS + VERIFY_PUBLIC_MSG_SCALARS;

impl VerifyPublic {
    /// Build from a short message (zero-padded tail per v1 policy).
    pub fn from_message(pk: [u8; SPHINCS_PK_BYTES], msg: &[u8]) -> Self {
        assert!(msg.len() <= MESSAGE_MAX_BYTES);
        let mut message = [0u8; MESSAGE_MAX_BYTES];
        message[..msg.len()].copy_from_slice(msg);
        Self {
            pk,
            message,
            mlen: msg.len(),
        }
    }
}

/// Private witness for the verifier relation.
#[derive(Debug, Clone)]
pub struct VerifyWitness {
    pub signature: [u8; SPHINCS_SIG_BYTES],
    /// Per-compression trace: (H_in, block, H_out) for step circuit + core chaining.
    pub sha256_compressions: Vec<Sha256Compression>,
    /// Optional PQClean-derived aux (FORS indices, WOTS lengths, etc.).
    pub sphincs_aux: SphincsAuxWitness,
}

#[derive(Debug, Clone)]
pub struct Sha256Compression {
    pub index: usize,
    pub h_in: [u8; 32],
    pub block: [u8; 64],
    pub h_out: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct SphincsAuxWitness {
    pub r_sig: [u8; 16],
    pub mhash: Vec<u8>,
    pub tree: u64,
    pub idx_leaf: u32,
}

/// Sub-circuits composed by `C_core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifySubcircuit {
    HashMessage,
    ForsPkFromSig,
    WotsPkFromSig,
    ThashLeaf,
    ComputeRoot,
    RootEquality,
}

impl VerifyWitness {
    pub fn subcircuits() -> &'static [VerifySubcircuit] {
        &[
            VerifySubcircuit::HashMessage,
            VerifySubcircuit::ForsPkFromSig,
            VerifySubcircuit::WotsPkFromSig,
            VerifySubcircuit::ThashLeaf,
            VerifySubcircuit::ComputeRoot,
            VerifySubcircuit::RootEquality,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_public_scalar_layout() {
        assert_eq!(VERIFY_PUBLIC_PK_SCALARS, 8);
        assert_eq!(VERIFY_PUBLIC_MSG_SCALARS, 1024);
        assert_eq!(VERIFY_PUBLIC_NUM_SCALARS, 1033);
    }

    #[test]
    fn signature_size_matches_pqclean_meta() {
        assert_eq!(SPHINCS_SIG_BYTES, 7856);
        assert_eq!(SPHINCS_PK_BYTES, 32);
    }
}
