//! WOTS+ public-key recovery gadget — `wots_pk_from_sig`, mirroring PQClean
//! `wots.c`. Used once per hypertree layer to turn a WOTS+ signature over a
//! node into the leaf-defining public key.
//!
//! Structure (SPHINCS+-SHA2-128s-simple parameters):
//!   - `SPX_WOTS_W = 16`, `LOGW = 4` → message splits into base-16 digits.
//!   - `LEN1 = 32` message digits + `LEN2 = 3` checksum digits = `LEN = 35` chains.
//!   - Each chain is `gen_chain`: start at the signature value (position
//!     `lengths[i]`) and apply `15 - lengths[i]` iterated `thash(.., 1)` calls,
//!     each at hash address `j`, walking up to the top of the Winternitz chain.
//!
//! As in [`crate::merkle`], the per-chain `lengths` (hence the number of hash
//! steps and the addresses) are known at synthesis time — the circuit follows
//! the same data-dependent structure as the C reference. The 16-byte chain
//! values are circuit wires: each `thash` output feeds the next via
//! [`crate::thash::thash_digest_bits`].

use crate::thash::{alloc_input_bits, enforce_digest_equals, thash_digest_bits, witness_bytes_from_bits, ADDR_BYTES, SPX_N};
use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// Winternitz parameter `w`.
pub const SPX_WOTS_W: u32 = 16;
/// `log2(w)`.
pub const SPX_WOTS_LOGW: usize = 4;
/// Number of base-w message digits (`8 * SPX_N / LOGW`).
pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;
/// Number of base-w checksum digits.
pub const SPX_WOTS_LEN2: usize = 3;
/// Total number of Winternitz chains.
pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
/// WOTS+ public key / signature byte length.
pub const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;

/// `base_w`: read `out_len` base-`w` digits (big-endian within each byte) from
/// `input`. Matches PQClean `wots.c:base_w` (only valid because `LOGW | 8`).
fn base_w(out_len: usize, input: &[u8]) -> Vec<u32> {
    let mut output = Vec::with_capacity(out_len);
    let mut in_idx = 0usize;
    let mut total = 0u8;
    let mut bits = 0usize;
    for _ in 0..out_len {
        if bits == 0 {
            total = input[in_idx];
            in_idx += 1;
            bits = 8;
        }
        bits -= SPX_WOTS_LOGW;
        output.push(((total >> bits) as u32) & (SPX_WOTS_W - 1));
    }
    output
}

/// Derive all `SPX_WOTS_LEN` chain lengths from the 16-byte message:
/// `LEN1` message digits followed by `LEN2` checksum digits.
/// Mirrors PQClean `wots.c:chain_lengths` + `wots_checksum`.
pub fn chain_lengths(msg: &[u8; SPX_N]) -> [u32; SPX_WOTS_LEN] {
    let mut lengths = [0u32; SPX_WOTS_LEN];

    let msg_digits = base_w(SPX_WOTS_LEN1, msg);
    lengths[..SPX_WOTS_LEN1].copy_from_slice(&msg_digits);

    // checksum = Σ (w-1 - digit)
    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += SPX_WOTS_W - 1 - d;
    }
    // Left-align so the empty bits are least significant.
    let shift = (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8;
    csum <<= shift;
    // ull_to_bytes(csum_bytes, 2, csum): big-endian, 2 bytes.
    let csum_bytes = [(csum >> 8) as u8, csum as u8];
    let csum_digits = base_w(SPX_WOTS_LEN2, &csum_bytes);
    lengths[SPX_WOTS_LEN1..].copy_from_slice(&csum_digits);

    lengths
}

/// Overlay `chain` address (offset 17) onto a copy of the base address —
/// mirrors `set_chain_addr`.
fn addr_with_chain(base: &[u8; ADDR_BYTES], chain: u32) -> [u8; ADDR_BYTES] {
    let mut a = *base;
    a[17] = chain as u8;
    a
}

/// In-circuit `gen_chain`: starting from `in_bits` (position `start`), apply
/// `steps` iterated `thash(.., 1)` calls, each at hash address `start + k`,
/// returning the 128-bit chain value. `addr_base` must already carry the chain
/// address; this sets the hash address (offset 21) per step.
pub fn gen_chain<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    in_bits: &[Boolean],
    start: u32,
    steps: u32,
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut out = in_bits.to_vec();
    // C loop: for (i = start; i < start + steps && i < SPX_WOTS_W; i++)
    let mut j = start;
    while j < start + steps && j < SPX_WOTS_W {
        let mut addr = *addr_base;
        addr[21] = j as u8; // set_hash_addr
        out = thash_digest_bits(
            cs.namespace(|| format!("step_{j}")),
            pub_seed,
            &addr,
            &out,
        )?;
        j += 1;
    }
    Ok(out)
}

/// In-circuit `wots_pk_from_sig` using witness root **bits** (FORS pk or prior layer root).
///
/// `chain_lengths` are derived from witness assignments via [`witness_bytes_from_bits`]
/// at synthesis time — no separate `root_in_bytes` oracle parameter.
pub fn wots_pk_from_sig_root_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    sig: &[u8; SPX_WOTS_BYTES],
    root_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(root_bits.len(), SPX_N * 8);
    let msg = witness_bytes_from_bits::<SPX_N>(root_bits);
    wots_pk_from_sig_bits(cs, pub_seed, addr_base, sig, &msg)
}

/// In-circuit `wots_pk_from_sig`: recover the WOTS+ public key wires (the 35
/// chain tops concatenated) from a signature and the signed message.
pub fn wots_pk_from_sig_bits<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    sig: &[u8; SPX_WOTS_BYTES],
    msg: &[u8; SPX_N],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let lengths = chain_lengths(msg);
    let mut pk_bits = Vec::with_capacity(SPX_WOTS_BYTES * 8);

    for (i, &len) in lengths.iter().enumerate() {
        let chain_in = alloc_input_bits(
            &mut cs.namespace(|| format!("sig_{i}")),
            "v",
            &sig[i * SPX_N..(i + 1) * SPX_N],
        )?;
        let addr = addr_with_chain(addr_base, i as u32);
        let top = gen_chain(
            cs.namespace(|| format!("chain_{i}")),
            pub_seed,
            &addr,
            &chain_in,
            len,
            SPX_WOTS_W - 1 - len,
        )?;
        pk_bits.extend(top);
    }
    Ok(pk_bits)
}

/// Synthesize `wots_pk_from_sig` and enforce the recovered key equals
/// `expected_pk` (used for bit-exact validation against PQClean).
pub fn synthesize_wots_pk_from_sig<Scalar, CS>(
    mut cs: CS,
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    sig: &[u8; SPX_WOTS_BYTES],
    msg: &[u8; SPX_N],
    expected_pk: &[u8; SPX_WOTS_BYTES],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let pk_bits = wots_pk_from_sig_bits(
        cs.namespace(|| "wots_pk"),
        pub_seed,
        addr_base,
        sig,
        msg,
    )?;

    for chunk in 0..SPX_WOTS_LEN {
        let mut expected = [0u8; SPX_N];
        expected.copy_from_slice(&expected_pk[chunk * SPX_N..(chunk + 1) * SPX_N]);
        let bits = &pk_bits[chunk * SPX_N * 8..(chunk + 1) * SPX_N * 8];
        enforce_digest_equals(cs.namespace(|| format!("pk_eq_{chunk}")), bits, &expected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    fn run(
        pub_seed: &[u8; 16],
        addr: &[u8; 22],
        sig: &[u8; SPX_WOTS_BYTES],
        msg: &[u8; 16],
        expected_pk: &[u8; SPX_WOTS_BYTES],
    ) -> bool {
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_wots_pk_from_sig(&mut cs, pub_seed, addr, sig, msg, expected_pk).expect("synth");
        cs.is_satisfied()
    }

    #[test]
    fn chain_lengths_matches_known_shape() {
        // All-0xff message → every base-w digit is 15, checksum is 0.
        let lengths = chain_lengths(&[0xffu8; 16]);
        assert_eq!(&lengths[..SPX_WOTS_LEN1], &[15u32; SPX_WOTS_LEN1]);
        assert_eq!(&lengths[SPX_WOTS_LEN1..], &[0u32; SPX_WOTS_LEN2]);
    }

    // Fast path: all-0xff message → the 32 message chains are no-ops (start at
    // the top), and the 3 checksum chains each run 15 thash steps. Exercises
    // gen_chain hashing + full pk assembly + oracle equality at ~45 SHA-256s.
    #[test]
    fn matches_pqclean_high_message() {
        let pub_seed = [0x21u8; 16];
        let mut addr = [0u8; 22];
        addr[9] = 0; // SPX_ADDR_TYPE_WOTS
        addr[13] = 7; // a keypair address, for realism
        let sig: Vec<u8> = (0..SPX_WOTS_BYTES).map(|i| (i % 251) as u8).collect();
        let sig: [u8; SPX_WOTS_BYTES] = sig.try_into().unwrap();
        let msg = [0xffu8; 16];

        let expected = sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &addr, &sig, &msg);
        assert!(run(&pub_seed, &addr, &sig, &msg, &expected));
    }

    /// `wots_pk_from_sig_root_bits` agrees with byte-message path when root witness matches.
    ///
    /// ```bash
    /// cargo test -p sphincs-circuit root_bits_path_matches_byte_message --release -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "WOTS recover is slow in debug (~2 min); run --release --ignored"]
    fn root_bits_path_matches_byte_message() {
        use bellpepper_core::test_cs::TestConstraintSystem;
        use blstrs::Scalar as Fr;
        use crate::thash::alloc_input_bits;

        let pub_seed = [0x77u8; 16];
        let addr = [0u8; 22];
        let sig: Vec<u8> = (0..SPX_WOTS_BYTES).map(|i| (i % 200) as u8).collect();
        let sig: [u8; SPX_WOTS_BYTES] = sig.try_into().unwrap();
        let msg = [0xabu8; 16];
        let expected = sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &addr, &sig, &msg);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let root_bits = alloc_input_bits(&mut cs, "root", &msg).unwrap();
        let pk_bits =
            wots_pk_from_sig_root_bits(&mut cs, &pub_seed, &addr, &sig, &root_bits).unwrap();
        for chunk in 0..SPX_WOTS_LEN {
            let mut expected_chunk = [0u8; SPX_N];
            expected_chunk.copy_from_slice(&expected[chunk * SPX_N..(chunk + 1) * SPX_N]);
            let bits = &pk_bits[chunk * SPX_N * 8..(chunk + 1) * SPX_N * 8];
            enforce_digest_equals(
                cs.namespace(|| format!("pk_eq_{chunk}")),
                bits,
                &expected_chunk,
            )
            .unwrap();
        }
        assert!(cs.is_satisfied());
    }

    #[test]
    fn wrong_pk_is_unsatisfiable() {
        let pub_seed = [0x55u8; 16];
        let addr = [0u8; 22];
        let sig: Vec<u8> = (0..SPX_WOTS_BYTES).map(|i| (i * 3 % 256) as u8).collect();
        let sig: [u8; SPX_WOTS_BYTES] = sig.try_into().unwrap();
        let msg = [0xffu8; 16];

        let mut expected = sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &addr, &sig, &msg);
        expected[SPX_WOTS_LEN1 * SPX_N] ^= 1; // corrupt the first checksum-chain output byte
        assert!(!run(&pub_seed, &addr, &sig, &msg, &expected));
    }

    // Full message-chain hashing (random msg → ~250 SHA-256s). Slow in debug;
    // run with `cargo test -- --ignored` (or release) for thorough validation.
    #[test]
    #[ignore]
    fn matches_pqclean_random_message() {
        let pub_seed = [0x9au8; 16];
        let mut addr = [0u8; 22];
        addr[13] = 42;
        let sig: Vec<u8> = (0..SPX_WOTS_BYTES).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let sig: [u8; SPX_WOTS_BYTES] = sig.try_into().unwrap();
        let msg: [u8; 16] = core::array::from_fn(|i| ((i * 17 + 5) % 256) as u8);

        let expected = sphincs_ref::wots_pk_from_sig_oracle(&pub_seed, &addr, &sig, &msg);
        assert!(run(&pub_seed, &addr, &sig, &msg, &expected));
    }
}
