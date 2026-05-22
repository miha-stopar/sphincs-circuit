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
    pub message: Vec<u8>,
    pub mlen: usize,
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
    fn signature_size_matches_pqclean_meta() {
        assert_eq!(SPHINCS_SIG_BYTES, 7856);
        assert_eq!(SPHINCS_PK_BYTES, 32);
    }
}
