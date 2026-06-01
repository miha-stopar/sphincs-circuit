//! Native SPHINCS+-SHA2-128s (simple) via PQClean (`third_party/PQClean`).
//!
//! Code map: [docs/CODEMAP.md](../../docs/CODEMAP.md)

mod trace;

pub use circuit_spec::{MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES};

use std::sync::Mutex;

/// PQClean uses process-global mutable state: the SHA-256 compression trace
/// buffer (written by the instrumented `common/sha2.c`) and the deterministic
/// RNG stub. Tests run multi-threaded, so every entry point that touches that
/// state must hold this lock to avoid data races. Poison is ignored because the
/// only invariant the lock protects is "one PQClean call at a time".
static PQCLEAN_LOCK: Mutex<()> = Mutex::new(());

#[cfg(pqclean_linked)]
fn pqclean_guard() -> std::sync::MutexGuard<'static, ()> {
    PQCLEAN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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

/// FFI verify with no locking; callers must hold [`pqclean_guard`].
#[cfg(pqclean_linked)]
fn verify_inner(
    pk: &[u8; SPHINCS_PK_BYTES],
    msg: &[u8],
    sig: &[u8; SPHINCS_SIG_BYTES],
) -> Result<(), Error> {
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

/// Verify detached signature — [`sign.c` `crypto_sign_verify`](../../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c).
pub fn verify(pk: &[u8; SPHINCS_PK_BYTES], msg: &[u8], sig: &[u8; SPHINCS_SIG_BYTES]) -> Result<(), Error> {
    #[cfg(pqclean_linked)]
    {
        let _guard = pqclean_guard();
        verify_inner(pk, msg, sig)
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

/// Export compression trace as JSON for the circuit witness generator.
pub fn trace_to_json(trace: &Sha256Trace) -> Result<String, serde_json::Error> {
    #[derive(serde::Serialize)]
    struct RowJson {
        index: usize,
        h_in: String,
        block: String,
        h_out: String,
    }
    #[derive(serde::Serialize)]
    struct TraceJson {
        compressions: Vec<RowJson>,
    }

    let rows = trace
        .compressions
        .iter()
        .map(|c| RowJson {
            index: c.index,
            h_in: hex_bytes(&c.h_in),
            block: hex_bytes(&c.block),
            h_out: hex_bytes(&c.h_out),
        })
        .collect();

    serde_json::to_string_pretty(&TraceJson {
        compressions: rows,
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run verify and record every compression via hook in [`sha2.c`](../../third_party/PQClean/common/sha2.c).
pub fn verify_with_trace(
    pk: &[u8; SPHINCS_PK_BYTES],
    msg: &[u8],
    sig: &[u8; SPHINCS_SIG_BYTES],
) -> Result<Sha256Trace, Error> {
    #[cfg(pqclean_linked)]
    {
        let _guard = pqclean_guard();
        trace::trace_reset();
        verify_inner(pk, msg, sig)?;
        Ok(trace::trace_collect())
    }
    #[cfg(not(pqclean_linked))]
    {
        let _ = (pk, msg, sig);
        Err(Error::NotLinked)
    }
}

/// Ground-truth `thash` output (16 bytes) for circuit validation.
///
/// Mirrors PQClean `thash_sha2_simple.c`: seeds a context with `pub_seed`,
/// then hashes `addr ‖ in` under the seeded state. Equivalent to
/// `SHA256(pub_seed ‖ zeros(48) ‖ addr ‖ in)[0..16]` (see the alignment test).
///
/// `input` must be a whole number of `SPX_N` (16-byte) blocks; `inblocks >= 1`.
#[cfg(pqclean_linked)]
pub fn thash_oracle(pub_seed: &[u8; 16], addr: &[u8; 22], input: &[u8]) -> [u8; 16] {
    assert_eq!(input.len() % 16, 0, "input must be whole SPX_N blocks");
    let inblocks = input.len() / 16;
    assert!(inblocks >= 1, "thash needs at least one block");

    extern "C" {
        fn spx_thash_oracle(
            out: *mut u8,
            pub_seed: *const u8,
            addr_bytes: *const u8,
            input: *const u8,
            inblocks: u32,
        );
    }

    let _guard = pqclean_guard();
    let mut out = [0u8; 16];
    unsafe {
        spx_thash_oracle(
            out.as_mut_ptr(),
            pub_seed.as_ptr(),
            addr.as_ptr(),
            input.as_ptr(),
            inblocks as u32,
        );
    }
    out
}

/// Ground-truth `compute_root` output (16 bytes) for circuit validation.
///
/// Mirrors PQClean `utils.c:compute_root`: reconstructs a Merkle root from a
/// `leaf` and an `auth_path` of `tree_height` sibling nodes, using `leaf_idx`
/// (and `idx_offset`) to decide left/right placement and tree-index addresses.
/// `addr` is the 22-byte base address with type/layer/tree/keypair already set.
///
/// `auth_path.len()` must equal `tree_height as usize * 16`.
#[cfg(pqclean_linked)]
#[allow(clippy::too_many_arguments)]
pub fn compute_root_oracle(
    pub_seed: &[u8; 16],
    addr: &[u8; 22],
    leaf: &[u8; 16],
    leaf_idx: u32,
    idx_offset: u32,
    auth_path: &[u8],
    tree_height: u32,
) -> [u8; 16] {
    assert_eq!(
        auth_path.len(),
        tree_height as usize * 16,
        "auth_path must be tree_height SPX_N-blocks"
    );

    extern "C" {
        fn spx_compute_root_oracle(
            out: *mut u8,
            pub_seed: *const u8,
            addr_bytes: *const u8,
            leaf: *const u8,
            leaf_idx: u32,
            idx_offset: u32,
            auth_path: *const u8,
            tree_height: u32,
        );
    }

    let _guard = pqclean_guard();
    let mut out = [0u8; 16];
    unsafe {
        spx_compute_root_oracle(
            out.as_mut_ptr(),
            pub_seed.as_ptr(),
            addr.as_ptr(),
            leaf.as_ptr(),
            leaf_idx,
            idx_offset,
            auth_path.as_ptr(),
            tree_height,
        );
    }
    out
}

/// SPHINCS+-SHA2-128s WOTS+ signature length in bytes (`SPX_WOTS_LEN * SPX_N`).
pub const WOTS_BYTES: usize = 560;

/// Ground-truth `wots_pk_from_sig` output (560 bytes) for circuit validation.
///
/// Mirrors PQClean `wots.c:wots_pk_from_sig`: derives the per-chain lengths from
/// `msg` (base-w digits + checksum) and walks each of the 35 Winternitz chains
/// from the signature value up to the top, returning the recovered WOTS+ public
/// key. `addr` is the 22-byte base address with type=WOTS and layer/tree/keypair
/// already set.
#[cfg(pqclean_linked)]
pub fn wots_pk_from_sig_oracle(
    pub_seed: &[u8; 16],
    addr: &[u8; 22],
    sig: &[u8; WOTS_BYTES],
    msg: &[u8; 16],
) -> [u8; WOTS_BYTES] {
    extern "C" {
        fn spx_wots_pk_from_sig_oracle(
            pk: *mut u8,
            pub_seed: *const u8,
            addr_bytes: *const u8,
            sig: *const u8,
            msg: *const u8,
        );
    }

    let _guard = pqclean_guard();
    let mut pk = [0u8; WOTS_BYTES];
    unsafe {
        spx_wots_pk_from_sig_oracle(
            pk.as_mut_ptr(),
            pub_seed.as_ptr(),
            addr.as_ptr(),
            sig.as_ptr(),
            msg.as_ptr(),
        );
    }
    pk
}

/// FORS signature byte length (`SPX_FORS_BYTES`).
pub const FORS_BYTES: usize = 2912;
/// FORS message hash bytes (`SPX_FORS_MSG_BYTES`).
pub const FORS_MSG_BYTES: usize = 21;

/// Ground-truth `hash_message` for circuit validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageOracleOutput {
    pub mhash: [u8; FORS_MSG_BYTES],
    pub tree: u64,
    pub leaf_idx: u32,
}

/// Ground-truth `hash_message` output. Mirrors PQClean `hash_sha2.c:hash_message`.
#[cfg(pqclean_linked)]
pub fn hash_message_oracle(
    r: &[u8; 16],
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8],
    mlen: usize,
) -> HashMessageOracleOutput {
    extern "C" {
        fn spx_hash_message_oracle(
            mhash: *mut u8,
            tree: *mut u64,
            leaf_idx: *mut u32,
            r: *const u8,
            pk: *const u8,
            m: *const u8,
            mlen: usize,
        );
    }

    let _guard = pqclean_guard();
    let mut mhash = [0u8; FORS_MSG_BYTES];
    let mut tree = 0u64;
    let mut leaf_idx = 0u32;
    unsafe {
        spx_hash_message_oracle(
            mhash.as_mut_ptr(),
            &mut tree,
            &mut leaf_idx,
            r.as_ptr(),
            pk.as_ptr(),
            message.as_ptr(),
            mlen,
        );
    }
    HashMessageOracleOutput {
        mhash,
        tree,
        leaf_idx,
    }
}

/// Ground-truth `fors_pk_from_sig` output (16 bytes) for circuit validation.
///
/// Mirrors PQClean `fors.c:fors_pk_from_sig`: for each of 14 height-12 trees,
/// hashes the secret-key part to a leaf, walks the auth path to a tree root,
/// then horizontally hashes all tree roots into the FORS public key.
#[cfg(pqclean_linked)]
pub fn fors_pk_from_sig_oracle(
    pub_seed: &[u8; 16],
    addr: &[u8; 22],
    sig: &[u8; FORS_BYTES],
    mhash: &[u8; FORS_MSG_BYTES],
) -> [u8; 16] {
    extern "C" {
        fn spx_fors_pk_from_sig_oracle(
            pk: *mut u8,
            pub_seed: *const u8,
            addr_bytes: *const u8,
            sig: *const u8,
            mhash: *const u8,
        );
    }

    let _guard = pqclean_guard();
    let mut pk = [0u8; 16];
    unsafe {
        spx_fors_pk_from_sig_oracle(
            pk.as_mut_ptr(),
            pub_seed.as_ptr(),
            addr.as_ptr(),
            sig.as_ptr(),
            mhash.as_ptr(),
        );
    }
    pk
}

/// Seed the deterministic PRNG with no locking; callers must hold the guard.
#[cfg(pqclean_linked)]
fn reset_signing_rng_inner(seed: u64) {
    extern "C" {
        fn randombytes_seed(seed: u64);
    }
    unsafe { randombytes_seed(seed) }
}

/// Deterministic keypair + signature for tests (NIST KAT–style seed).
/// Reset the deterministic PRNG used by PQClean signing ([`randombytes_stub.c`](c/randombytes_stub.c)).
#[cfg(pqclean_linked)]
pub fn reset_signing_rng(seed: u64) {
    let _guard = pqclean_guard();
    reset_signing_rng_inner(seed);
}

/// Keypair + detached signature using deterministic RNG (reproducible tests).
#[cfg(pqclean_linked)]
pub fn sign_deterministic(
    seed: &[u8; CRYPTO_SEEDBYTES],
    msg: &[u8],
) -> Result<([u8; SPHINCS_PK_BYTES], [u8; SPHINCS_SIG_BYTES]), Error> {
    let _guard = pqclean_guard();
    reset_signing_rng_inner(u64::from_le_bytes([
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
    fn trace_to_json_roundtrip_shape() {
        let seed = [2u8; CRYPTO_SEEDBYTES];
        let msg = b"json export";
        let (pk, sig) = sign_deterministic(&seed, msg).unwrap();
        let trace = verify_with_trace(&pk, msg, &sig).unwrap();
        let json = trace_to_json(&trace).unwrap();
        assert!(json.contains("\"h_in\""));
        assert!(json.contains("\"compressions\""));
        assert!(trace.len() > 0);
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn thash_oracle_is_deterministic_and_input_sensitive() {
        let pub_seed = [0x11u8; 16];
        let addr = [0x22u8; 22];
        let input = [0x33u8; 16];

        let a = thash_oracle(&pub_seed, &addr, &input);
        let b = thash_oracle(&pub_seed, &addr, &input);
        assert_eq!(a, b, "thash must be deterministic");
        assert_ne!(a, [0u8; 16], "output should not be all-zero");

        // Changing the address changes the output (domain separation).
        let mut addr2 = addr;
        addr2[0] ^= 1;
        assert_ne!(thash_oracle(&pub_seed, &addr2, &input), a);

        // Changing the input changes the output.
        let mut input2 = input;
        input2[3] ^= 1;
        assert_ne!(thash_oracle(&pub_seed, &addr, &input2), a);

        // Changing the seed changes the output.
        let mut seed2 = pub_seed;
        seed2[7] ^= 1;
        assert_ne!(thash_oracle(&seed2, &addr, &input), a);
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn thash_oracle_supports_multiblock_inputs() {
        let pub_seed = [5u8; 16];
        let addr = [9u8; 22];
        // inblocks used in SPHINCS+ verify: 1 (chain/leaf), 2 (Merkle), 14 (FORS root), 35 (WOTS leaf).
        for inblocks in [1usize, 2, 14, 35] {
            let input = vec![0x5au8; inblocks * 16];
            let out = thash_oracle(&pub_seed, &addr, &input);
            assert_ne!(out, [0u8; 16], "inblocks={inblocks} produced zero output");
        }
    }

    #[cfg(pqclean_linked)]
    #[test]
    fn compute_root_oracle_is_deterministic_and_parity_sensitive() {
        let pub_seed = [0x44u8; 16];
        let addr = [0x55u8; 22];
        let leaf = [0x66u8; 16];
        let tree_height = 9u32;
        let auth: Vec<u8> = (0..tree_height as usize * 16).map(|i| i as u8).collect();

        let a = compute_root_oracle(&pub_seed, &addr, &leaf, 0, 0, &auth, tree_height);
        let b = compute_root_oracle(&pub_seed, &addr, &leaf, 0, 0, &auth, tree_height);
        assert_eq!(a, b, "compute_root must be deterministic");
        assert_ne!(a, [0u8; 16]);

        // Flipping leaf_idx parity changes left/right placement → different root.
        let odd = compute_root_oracle(&pub_seed, &addr, &leaf, 1, 0, &auth, tree_height);
        assert_ne!(odd, a, "parity of leaf_idx must affect the root");
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
