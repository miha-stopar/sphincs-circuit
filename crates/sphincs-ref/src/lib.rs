//! Native SPHINCS+-SHA2-128s (simple) via PQClean (`third_party/PQClean`).
//!
//! Code map: [docs/CODEMAP.md](../../docs/CODEMAP.md)

pub use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotLinked,
    VerifyFailed,
}

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
}
