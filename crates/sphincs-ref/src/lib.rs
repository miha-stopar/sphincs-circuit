//! Native SPHINCS+-SHA2-128s (simple) via PQClean (`third_party/PQClean`).
//!
//! Code map: [docs/CODEMAP.md](../../docs/CODEMAP.md)

mod trace;

pub use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotLinked,
    InvalidPublicKey,
    InvalidSignature,
    VerifyFailed,
    TraceBufferFull,
}

/// PQClean seed length for deterministic keygen (`crypto_sign_seed_keypair`).
pub const CRYPTO_SEEDBYTES: usize = 48;

// PQClean: `third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c`
#[cfg(pqclean_linked)]
extern "C" {
    fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;

    fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_seed_keypair(
        pk: *mut u8,
        sk: *mut u8,
        seed: *const u8,
    ) -> i32;

    fn PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> i32;
}

/// Verify detached signature — [`sign.c` `crypto_sign_verify`](../../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c).
pub fn verify(pk: &[u8; SPHINCS_PK_BYTES], msg: &[u8], sig: &[u8; SPHINCS_SIG_BYTES]) -> Result<(), Error> {
    #[cfg(pqclean_linked)]
    {
        let rc = unsafe {
            PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(
                sig.as_ptr(),
                sig.len(),
                msg.as_ptr(),
                msg.len(),
                pk.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::VerifyFailed)
        }
    }
    #[cfg(not(pqclean_linked))]
    {
        let _ = (pk, msg, sig);
        Err(Error::NotLinked)
    }
}

/// Every SHA-256 compression during verify (witness for `C_step`).
#[derive(Debug, Clone)]
pub struct Sha256Trace {
    pub compressions: Vec<Sha256Compression>,
}

impl Sha256Trace {
    pub fn len(&self) -> usize {
        self.compressions.len()
    }

    /// Consecutive compressions within one logical hash should satisfy `h_out[i] == h_in[i+1]`.
    pub fn check_step_chains(&self) -> bool {
        self.compressions
            .windows(2)
            .all(|w| w[0].h_out == w[1].h_in)
    }
}

#[derive(Debug, Clone)]
pub struct Sha256Compression {
    pub index: usize,
    pub h_in: [u8; 32],
    pub block: [u8; 64],
    pub h_out: [u8; 32],
}

/// Run verify and record every compression via hook in [`sha2.c`](../../third_party/PQClean/common/sha2.c).
pub fn verify_with_trace(
    pk: &[u8; SPHINCS_PK_BYTES],
    msg: &[u8],
    sig: &[u8; SPHINCS_SIG_BYTES],
) -> Result<Sha256Trace, Error> {
    #[cfg(pqclean_linked)]
    {
        trace::trace_reset();
        verify(pk, msg, sig)?;
        Ok(trace::trace_collect())
    }
    #[cfg(not(pqclean_linked))]
    {
        let _ = (pk, msg, sig);
        Err(Error::NotLinked)
    }
}

/// Deterministic keypair + signature for tests (NIST KAT–style seed).
/// Reset the deterministic PRNG used by PQClean signing ([`randombytes_stub.c`](c/randombytes_stub.c)).
#[cfg(pqclean_linked)]
pub fn reset_signing_rng(seed: u64) {
    extern "C" {
        fn randombytes_seed(seed: u64);
    }
    unsafe { randombytes_seed(seed) }
}

/// Keypair + detached signature using deterministic RNG (reproducible tests).
#[cfg(pqclean_linked)]
pub fn sign_deterministic(
    seed: &[u8; CRYPTO_SEEDBYTES],
    msg: &[u8],
) -> Result<([u8; SPHINCS_PK_BYTES], [u8; SPHINCS_SIG_BYTES]), Error> {
    reset_signing_rng(u64::from_le_bytes([
        seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7],
    ]));
    let mut pk = [0u8; SPHINCS_PK_BYTES];
    let mut sk = [0u8; 64];
    let rc = unsafe {
        PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_seed_keypair(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(Error::InvalidPublicKey);
    }

    let mut sig = [0u8; SPHINCS_SIG_BYTES];
    let mut siglen = SPHINCS_SIG_BYTES;
    let rc = unsafe {
        PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut siglen,
            msg.as_ptr(),
            msg.len(),
            sk.as_ptr(),
        )
    };
    if rc != 0 || siglen != SPHINCS_SIG_BYTES {
        return Err(Error::InvalidSignature);
    }
    Ok((pk, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_pqclean_meta() {
        assert_eq!(SPHINCS_SIG_BYTES, 7856);
        assert_eq!(SPHINCS_PK_BYTES, 32);
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn pqclean_is_linked() {
        let pk = [0u8; SPHINCS_PK_BYTES];
        let sig = [0u8; SPHINCS_SIG_BYTES];
        let msg = b"test";
        assert!(matches!(verify(&pk, msg, &sig), Err(Error::VerifyFailed)));
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn verify_trace_on_valid_signature() {
        let seed = [0u8; CRYPTO_SEEDBYTES];
        let msg = b"sphincs-circuit trace test message";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");

        let trace = verify_with_trace(&pk, msg, &sig).expect("verify+trace");
        assert!(trace.len() > 1000, "expected thousands of compressions, got {}", trace.len());
        assert!(trace.len() < 10_000, "unexpected trace length {}", trace.len());

        // Spot-check: global chain is NOT contiguous (separate hash calls reset state).
        assert!(!trace.check_step_chains());

        // Most `thash` calls reset from `state_seeded` (single-block finalize), so the
        // global trace is not one long chain — only multi-block hashes link locally.
        let local = trace
            .compressions
            .windows(2)
            .filter(|w| w[0].h_out == w[1].h_in)
            .count();
        assert!(local > 0, "expected some within-hash links, got {local}");
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn trace_count_scales_with_message_length() {
        let seed = [1u8; CRYPTO_SEEDBYTES];
        let short = b"short";
        let long = vec![0xabu8; 512];

        reset_signing_rng(1);
        let (pk_s, sig_s) = sign_deterministic(&seed, short).unwrap();
        reset_signing_rng(2);
        let (pk_l, sig_l) = sign_deterministic(&seed, &long).unwrap();

        let t_short = verify_with_trace(&pk_s, short, &sig_s).unwrap();
        let t_long = verify_with_trace(&pk_l, &long, &sig_l).unwrap();

        // Trace length depends on WOTS paths (from `hash_message`) too, not only |M|.
        assert!(t_short.len() > 1500 && t_long.len() > 1500);
        assert_ne!(t_short.len(), t_long.len(), "traces: {} vs {}", t_short.len(), t_long.len());
    }
}
