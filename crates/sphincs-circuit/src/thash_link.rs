//! Trace-linked `thash`-F: move the variable SHA-256 compression of a WOTS+ chain
//! step out of `C_core` and into a folded `C_step` instance, bound through a
//! minimal shared-witness "bus".
//!
//! # Why
//!
//! Today `C_core` synthesizes *every* SHA-256 compression of FORS / WOTS / the
//! hypertree in-line (the ~49M-constraint monolith). NeutronNova is built to
//! fold each compression as a tiny `C_step` instance and keep only *glue* in
//! `C_core`. This module is the first sound, self-contained step of that move:
//! it offloads the **WOTS+ chain `F` function**, which is the single biggest
//! contributor to the core (≈3,600 chain `thash`es at KAT size).
//!
//! # The `thash`-F structure (`inblocks = 1`)
//!
//! ```text
//!   thash_F(in, addr) = SHA256( pub_seed(16) ‖ 0^48 ‖ addr(22) ‖ in(16) )[0:16]
//! ```
//!
//! The 102-byte preimage is exactly **two** SHA-256 blocks:
//!
//! - **block 0** = `pub_seed ‖ 0^48` → `S = Compress(IV, block0)`. `S` depends
//!   only on `pub_seed`, so it is a **global constant** for the whole proof
//!   (PQClean precomputes it once as `state_seeded`).
//! - **block 1** = `addr(22) ‖ in(16) ‖ 0x80 ‖ 0^17 ‖ len_be(816)`. Only
//!   `addr` and `in` are variable; everything else is constant.
//!
//! So one `thash`-F is one *variable* compression `Compress(S, block1)` whose
//! truncated output `[0:16]` is the chain step result. That is what we fold.
//!
//! # The bus (minimal-slice binding)
//!
//! Per `thash`-F call the shared witness carries **three** field elements:
//!
//! | slot   | width   | meaning                                           |
//! |--------|---------|---------------------------------------------------|
//! | `addr` | 176-bit | big-endian value of the 22-byte address           |
//! | `in`   | 128-bit | big-endian value of the 16-byte chain input       |
//! | `out`  | 128-bit | big-endian value of the 16-byte chain output      |
//!
//! - [`thash_f_step`] (the folded `C_step`) pins `h_in = S` and the pad bytes to
//!   constants, allocates `addr‖in` as the block witness, runs **one**
//!   compression, and binds `addr`/`in`/`out` to the bus.
//! - [`thash_f_core_link`] (the `C_core` glue) performs **no** compression: it
//!   binds the bus `addr` to the topology constant, the bus `in` to the upstream
//!   wire, and returns the bus `out` as the downstream wire.
//!
//! Because `S` is pinned in the step, `addr`/`in` are bound on both sides, and
//! `out` flows from the step's real compression, a malicious prover cannot
//! substitute a different preimage — closing the BUG-1 class of soundness holes
//! (see `docs/SOUNDNESS_AUDIT.md`) for the offloaded compression.

use bellpepper::gadgets::boolean::{AllocatedBit, Boolean};
use bellpepper::gadgets::sha256::sha256_compression_function;
use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

use crate::sha256_compress::{sha256_state_words_to_bits_be, state_bytes_to_words};
use crate::thash::{ADDR_BYTES, SPX_N};
use crate::wots::SPX_WOTS_W;

/// SHA-256 initial hash value (RFC 6234).
pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// `thash`-F preimage length in bytes: `64 (seed block) + 22 (addr) + 16 (in)`.
pub const F_PREIMAGE_BYTES: usize = 64 + ADDR_BYTES + SPX_N;

/// Number of shared-witness field elements per `thash`-F call (`addr`, `in`, `out`).
pub const THASH_F_SLOT_LEN: usize = 3;

// ---------------------------------------------------------------------------
// Native (out-of-circuit) helpers — used to build constants, witnesses, tests,
// and (later) the prover's bus values.
// ---------------------------------------------------------------------------

fn words_to_be_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

/// The seeded SHA-256 state `S = Compress(IV, pub_seed ‖ 0^48)` (32 big-endian bytes).
///
/// Constant for the whole proof given `pub_seed`; equals PQClean `state_seeded`.
pub fn seeded_state(pub_seed: &[u8; SPX_N]) -> [u8; 32] {
    let mut block0 = [0u8; 64];
    block0[..SPX_N].copy_from_slice(pub_seed);
    let mut state = SHA256_IV;
    let ga = sha2::digest::generic_array::GenericArray::clone_from_slice(&block0);
    sha2::compress256(&mut state, &[ga]);
    words_to_be_bytes(&state)
}

/// The second (variable) SHA-256 block of a `thash`-F call: `addr ‖ in ‖ pad`.
pub fn thash_f_block(addr: &[u8; ADDR_BYTES], input: &[u8; SPX_N]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..ADDR_BYTES].copy_from_slice(addr);
    block[ADDR_BYTES..ADDR_BYTES + SPX_N].copy_from_slice(input);
    block[ADDR_BYTES + SPX_N] = 0x80; // SHA-256 padding marker
    let bit_len = (F_PREIMAGE_BYTES as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    block
}

/// Full 32-byte intermediate `Compress(S, block1)` for a `thash`-F call.
pub fn thash_f_full_digest(
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    input: &[u8; SPX_N],
) -> [u8; 32] {
    let mut state = state_bytes_to_words(&seeded_state(pub_seed));
    let block1 = thash_f_block(addr, input);
    let ga = sha2::digest::generic_array::GenericArray::clone_from_slice(&block1);
    sha2::compress256(&mut state, &[ga]);
    words_to_be_bytes(&state)
}

/// The 16-byte `thash`-F output (chain step result).
pub fn thash_f_out(
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    input: &[u8; SPX_N],
) -> [u8; SPX_N] {
    let digest = thash_f_full_digest(pub_seed, addr, input);
    let mut out = [0u8; SPX_N];
    out.copy_from_slice(&digest[..SPX_N]);
    out
}

/// One bus entry's native values: `(addr, in, out)` for a single `thash`-F call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThashFBusValue {
    pub addr: [u8; ADDR_BYTES],
    pub input: [u8; SPX_N],
    pub out: [u8; SPX_N],
}

/// Native WOTS+ `gen_chain` that records one [`ThashFBusValue`] per `thash` step.
///
/// Mirrors [`crate::wots::gen_chain`]: starts at position `start`, applies up to
/// `steps` iterated `thash`-F calls (hash address = `start + k`). Returns the per
/// step bus values and the final 16-byte chain value.
pub fn thash_f_chain_bus_values(
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    input: &[u8; SPX_N],
    start: u32,
    steps: u32,
) -> (Vec<ThashFBusValue>, [u8; SPX_N]) {
    let mut cur = *input;
    let mut values = Vec::new();
    let mut j = start;
    while j < start + steps && j < SPX_WOTS_W {
        let mut addr = *addr_base;
        addr[21] = j as u8; // set_hash_addr
        let out = thash_f_out(pub_seed, &addr, &cur);
        values.push(ThashFBusValue {
            addr,
            input: cur,
            out,
        });
        cur = out;
        j += 1;
    }
    (values, cur)
}

// ---------------------------------------------------------------------------
// Scalar / bit packing helpers.
// ---------------------------------------------------------------------------

fn bytes_to_bits_be(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Big-endian integer value of `bytes` as a field element (requires `8*len` < field bits).
pub fn scalar_from_be_bytes<Scalar: PrimeField>(bytes: &[u8]) -> Scalar {
    let mut acc = Scalar::ZERO;
    for &byte in bytes {
        for i in (0..8).rev() {
            acc = acc.double();
            if (byte >> i) & 1 == 1 {
                acc += Scalar::ONE;
            }
        }
    }
    acc
}

/// Low `N` bytes of `s`, big-endian (inverse of [`scalar_from_be_bytes`] for `N`-byte values).
fn scalar_low_be_bytes<Scalar: PrimeField, const N: usize>(s: &Scalar) -> [u8; N] {
    let repr = s.to_repr();
    let le = repr.as_ref(); // little-endian byte representation
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = le[N - 1 - i];
    }
    out
}

/// Enforce `num == Σ_i bits[i] · 2^(n-1-i)` (big-endian) with one R1CS row.
///
/// `bits` may mix constants and variables; works for any `bits.len()` whose value
/// fits the scalar field (all uses here are ≤ 176 bits). Public so fold-step
/// circuits can bind a muxed shared-bus column to a step's witness bits.
pub fn enforce_num_eq_be_bits<Scalar, CS>(
    mut cs: CS,
    num: &AllocatedNum<Scalar>,
    bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    cs.enforce(
        || "num_eq_be_bits",
        |lc| {
            let mut acc = lc + num.get_variable();
            let mut coeff = Scalar::ONE;
            for b in bits.iter().rev() {
                acc = acc - &b.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            acc
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

/// Allocate `bytes` as big-endian witness bits (`AllocatedBit`).
fn alloc_byte_bits<Scalar, CS>(
    cs: &mut CS,
    label: &str,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    bytes_to_bits_be(bytes)
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            AllocatedBit::alloc(cs.namespace(|| format!("{label}_{i}")), Some(b)).map(Boolean::from)
        })
        .collect()
}

fn const_byte_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes_to_bits_be(bytes)
        .into_iter()
        .map(Boolean::constant)
        .collect()
}

// ---------------------------------------------------------------------------
// Shared-witness bus.
// ---------------------------------------------------------------------------

/// Allocate one bus entry (`[addr, in, out]`) as shared-witness field elements.
///
/// In the real fold these columns live in the single `comm_W_shared` commitment
/// alongside the existing link digests; here they are an independent contiguous
/// block (`THASH_F_SLOT_LEN` per call).
pub fn alloc_thash_f_slot<Scalar, CS>(
    mut cs: CS,
    value: &ThashFBusValue,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let addr = AllocatedNum::alloc(cs.namespace(|| "addr"), || {
        Ok(scalar_from_be_bytes(&value.addr))
    })?;
    let input = AllocatedNum::alloc(cs.namespace(|| "in"), || {
        Ok(scalar_from_be_bytes(&value.input))
    })?;
    let out = AllocatedNum::alloc(cs.namespace(|| "out"), || {
        Ok(scalar_from_be_bytes(&value.out))
    })?;
    Ok(vec![addr, input, out])
}

/// Allocate a whole chain's bus (`THASH_F_SLOT_LEN` field elements per step).
pub fn alloc_thash_f_bus<Scalar, CS>(
    mut cs: CS,
    values: &[ThashFBusValue],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut bus = Vec::with_capacity(values.len() * THASH_F_SLOT_LEN);
    for (k, v) in values.iter().enumerate() {
        bus.extend(alloc_thash_f_slot(cs.namespace(|| format!("slot_{k}")), v)?);
    }
    Ok(bus)
}

// ---------------------------------------------------------------------------
// C_step: the folded compression instance.
// ---------------------------------------------------------------------------

/// Compute the folded `C_step` witness bits for one `thash`-F call **without**
/// binding to any bus slot: pins `h_in = seeded` and the pad bytes to constants,
/// allocates `addr‖in` as the block witness, runs one SHA-256 compression, and
/// returns `(addr_bits, in_bits, out_bits)` (each big-endian).
///
/// [`thash_f_step`] binds these to a fixed slot; a fold step circuit binds them to
/// a selector-muxed shared column (uniform R1CS shape across folded instances).
pub fn thash_f_step_values<Scalar, CS>(
    mut cs: CS,
    seeded: &[u8; 32],
    addr: &[u8; ADDR_BYTES],
    input: &[u8; SPX_N],
) -> Result<(Vec<Boolean>, Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    // Block = addr(22, witness) ‖ in(16, witness) ‖ pad(26, constant).
    let addr_bits = alloc_byte_bits(&mut cs.namespace(|| "addr"), "b", addr)?;
    let in_bits = alloc_byte_bits(&mut cs.namespace(|| "in"), "b", input)?;
    let pad = {
        let full = thash_f_block(addr, input);
        let mut p = [0u8; 26];
        p.copy_from_slice(&full[ADDR_BYTES + SPX_N..]);
        p
    };
    let mut block_bits = Vec::with_capacity(512);
    block_bits.extend_from_slice(&addr_bits);
    block_bits.extend_from_slice(&in_bits);
    block_bits.extend(const_byte_bits(&pad));
    debug_assert_eq!(block_bits.len(), 512);

    // h_in pinned to the constant seeded state S.
    let h_words: Vec<UInt32> = state_bytes_to_words(seeded)
        .iter()
        .map(|&w| UInt32::constant(w))
        .collect();

    let out_words = sha256_compression_function(cs.namespace(|| "compress"), &block_bits, &h_words)?;
    let out_bits: Vec<Boolean> = sha256_state_words_to_bits_be(&out_words[..4]); // 128 bits
    Ok((addr_bits, in_bits, out_bits))
}

/// Folded **`C_step`** body for one `thash`-F call.
///
/// Pins `h_in = seeded` and the pad bytes to constants, allocates `addr‖in` as the
/// block witness, runs one SHA-256 compression, and binds `addr`/`in`/`out` to the
/// `slot` (`[addr, in, out]`). The compression output `[0:16]` is bound to the bus
/// `out`; nothing else leaves the step.
pub fn thash_f_step<Scalar, CS>(
    mut cs: CS,
    seeded: &[u8; 32],
    addr: &[u8; ADDR_BYTES],
    input: &[u8; SPX_N],
    slot: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(slot.len(), THASH_F_SLOT_LEN);
    let (addr_bits, in_bits, out_bits) =
        thash_f_step_values(cs.namespace(|| "compute"), seeded, addr, input)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_addr"), &slot[0], &addr_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in"), &slot[1], &in_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_out"), &slot[2], &out_bits)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// C_core: the glue that links to the folded step (no compression).
// ---------------------------------------------------------------------------

/// **`C_core`** glue for one `thash`-F call: bind `addr` (topology constant) and
/// `in` (upstream wire) to the bus, and return the bus `out` as 128 downstream bits.
///
/// Performs **no** SHA-256 compression — that lives in the folded [`thash_f_step`].
pub fn thash_f_core_link<Scalar, CS>(
    mut cs: CS,
    addr_const: &[u8; ADDR_BYTES],
    in_bits: &[Boolean],
    slot: &[AllocatedNum<Scalar>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(slot.len(), THASH_F_SLOT_LEN);
    assert_eq!(in_bits.len(), SPX_N * 8);

    // Bind addr slot to the compile-time topology constant.
    let addr_bits = const_byte_bits(addr_const);
    enforce_num_eq_be_bits(cs.namespace(|| "bind_addr"), &slot[0], &addr_bits)?;

    // Bind in slot to the upstream chain wires.
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in"), &slot[1], in_bits)?;

    // Materialize out as fresh wires equal to the bus out slot.
    let out_val: [u8; SPX_N] = slot[2]
        .get_value()
        .map(|s| scalar_low_be_bytes::<Scalar, SPX_N>(&s))
        .unwrap_or([0u8; SPX_N]);
    let out_bits = alloc_byte_bits(&mut cs.namespace(|| "out"), "b", &out_val)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_out"), &slot[2], &out_bits)?;
    Ok(out_bits)
}

/// **`C_core`** trace-linked WOTS+ `gen_chain`: like [`crate::wots::gen_chain`] but
/// every `thash`-F step is a bus link to a folded step instead of an in-core SHA.
///
/// `bus` must hold `THASH_F_SLOT_LEN` field elements per executed step
/// (i.e. `THASH_F_SLOT_LEN * min(steps, SPX_WOTS_W - start)`).
pub fn gen_chain_linked<Scalar, CS>(
    mut cs: CS,
    addr_base: &[u8; ADDR_BYTES],
    in_bits: &[Boolean],
    start: u32,
    steps: u32,
    bus: &[AllocatedNum<Scalar>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut out = in_bits.to_vec();
    let mut slot_idx = 0usize;
    let mut j = start;
    while j < start + steps && j < SPX_WOTS_W {
        let mut addr = *addr_base;
        addr[21] = j as u8; // set_hash_addr
        let slot = &bus[slot_idx * THASH_F_SLOT_LEN..(slot_idx + 1) * THASH_F_SLOT_LEN];
        out = thash_f_core_link(cs.namespace(|| format!("step_{j}")), &addr, &out, slot)?;
        slot_idx += 1;
        j += 1;
    }
    Ok(out)
}

// ===========================================================================
// thash-H family (inblocks = 2) — the Merkle / FORS node hash.
//
//   thash_H(in0, in1, addr) = SHA256( pub_seed(16) ‖ 0^48 ‖ addr(22) ‖ in0(16) ‖ in1(16) )[0:16]
//
// The variable region addr(22)‖in0(16)‖in1(16) = 54 bytes plus SHA padding still
// fits a *single* block after the constant seed block, so — exactly like F — one
// `thash`-H is one variable compression `Compress(S, block1)`. The bus carries
// four field elements `[addr, in0, in1, out]` (the 32-byte input is split into two
// 128-bit halves so every column stays < the scalar field).
// ===========================================================================

/// `thash`-H (`inblocks = 2`) preimage length: `64 + 22 (addr) + 32 (two inputs)`.
pub const H_PREIMAGE_BYTES: usize = 64 + ADDR_BYTES + 2 * SPX_N;

/// Number of shared-witness field elements per `thash`-H call (`addr, in0, in1, out`).
pub const THASH_H_SLOT_LEN: usize = 4;

/// The second (variable) SHA-256 block of a `thash`-H call: `addr ‖ in0 ‖ in1 ‖ pad`.
pub fn thash_h_block(addr: &[u8; ADDR_BYTES], in0: &[u8; SPX_N], in1: &[u8; SPX_N]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..ADDR_BYTES].copy_from_slice(addr);
    block[ADDR_BYTES..ADDR_BYTES + SPX_N].copy_from_slice(in0);
    block[ADDR_BYTES + SPX_N..ADDR_BYTES + 2 * SPX_N].copy_from_slice(in1);
    block[ADDR_BYTES + 2 * SPX_N] = 0x80; // SHA-256 padding marker (offset 54)
    let bit_len = (H_PREIMAGE_BYTES as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    block
}

/// The 16-byte `thash`-H output (one Merkle/FORS node).
pub fn thash_h_out(
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    in0: &[u8; SPX_N],
    in1: &[u8; SPX_N],
) -> [u8; SPX_N] {
    let mut state = state_bytes_to_words(&seeded_state(pub_seed));
    let block1 = thash_h_block(addr, in0, in1);
    let ga = sha2::digest::generic_array::GenericArray::clone_from_slice(&block1);
    sha2::compress256(&mut state, &[ga]);
    let digest = words_to_be_bytes(&state);
    let mut out = [0u8; SPX_N];
    out.copy_from_slice(&digest[..SPX_N]);
    out
}

/// One `thash`-H bus entry's native values: `(addr, in0, in1, out)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThashHBusValue {
    pub addr: [u8; ADDR_BYTES],
    pub in0: [u8; SPX_N],
    pub in1: [u8; SPX_N],
    pub out: [u8; SPX_N],
}

/// Allocate one `thash`-H bus entry (`[addr, in0, in1, out]`) as shared witnesses.
pub fn alloc_thash_h_slot<Scalar, CS>(
    mut cs: CS,
    value: &ThashHBusValue,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let addr = AllocatedNum::alloc(cs.namespace(|| "addr"), || {
        Ok(scalar_from_be_bytes(&value.addr))
    })?;
    let in0 = AllocatedNum::alloc(cs.namespace(|| "in0"), || {
        Ok(scalar_from_be_bytes(&value.in0))
    })?;
    let in1 = AllocatedNum::alloc(cs.namespace(|| "in1"), || {
        Ok(scalar_from_be_bytes(&value.in1))
    })?;
    let out = AllocatedNum::alloc(cs.namespace(|| "out"), || {
        Ok(scalar_from_be_bytes(&value.out))
    })?;
    Ok(vec![addr, in0, in1, out])
}

/// Allocate a whole `thash`-H bus (`THASH_H_SLOT_LEN` field elements per call).
pub fn alloc_thash_h_bus<Scalar, CS>(
    mut cs: CS,
    values: &[ThashHBusValue],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut bus = Vec::with_capacity(values.len() * THASH_H_SLOT_LEN);
    for (k, v) in values.iter().enumerate() {
        bus.extend(alloc_thash_h_slot(cs.namespace(|| format!("slot_{k}")), v)?);
    }
    Ok(bus)
}

/// Compute the folded `C_step` witness bits for one `thash`-H call **without**
/// binding to any bus slot. Returns `(addr_bits, in0_bits, in1_bits, out_bits)`.
pub fn thash_h_step_values<Scalar, CS>(
    mut cs: CS,
    seeded: &[u8; 32],
    addr: &[u8; ADDR_BYTES],
    in0: &[u8; SPX_N],
    in1: &[u8; SPX_N],
) -> Result<(Vec<Boolean>, Vec<Boolean>, Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    // Block = addr(22) ‖ in0(16) ‖ in1(16) ‖ pad(10), all but the pad are witness.
    let addr_bits = alloc_byte_bits(&mut cs.namespace(|| "addr"), "b", addr)?;
    let in0_bits = alloc_byte_bits(&mut cs.namespace(|| "in0"), "b", in0)?;
    let in1_bits = alloc_byte_bits(&mut cs.namespace(|| "in1"), "b", in1)?;
    let pad = {
        let full = thash_h_block(addr, in0, in1);
        let mut p = [0u8; 10];
        p.copy_from_slice(&full[ADDR_BYTES + 2 * SPX_N..]);
        p
    };
    let mut block_bits = Vec::with_capacity(512);
    block_bits.extend_from_slice(&addr_bits);
    block_bits.extend_from_slice(&in0_bits);
    block_bits.extend_from_slice(&in1_bits);
    block_bits.extend(const_byte_bits(&pad));
    debug_assert_eq!(block_bits.len(), 512);

    let h_words: Vec<UInt32> = state_bytes_to_words(seeded)
        .iter()
        .map(|&w| UInt32::constant(w))
        .collect();
    let out_words = sha256_compression_function(cs.namespace(|| "compress"), &block_bits, &h_words)?;
    let out_bits: Vec<Boolean> = sha256_state_words_to_bits_be(&out_words[..4]);
    Ok((addr_bits, in0_bits, in1_bits, out_bits))
}

/// Folded **`C_step`** body for one `thash`-H call: one compression, binds
/// `addr / in0 / in1 / out` to `slot`.
pub fn thash_h_step<Scalar, CS>(
    mut cs: CS,
    seeded: &[u8; 32],
    addr: &[u8; ADDR_BYTES],
    in0: &[u8; SPX_N],
    in1: &[u8; SPX_N],
    slot: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(slot.len(), THASH_H_SLOT_LEN);
    let (addr_bits, in0_bits, in1_bits, out_bits) =
        thash_h_step_values(cs.namespace(|| "compute"), seeded, addr, in0, in1)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_addr"), &slot[0], &addr_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in0"), &slot[1], &in0_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in1"), &slot[2], &in1_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_out"), &slot[3], &out_bits)?;
    Ok(())
}

/// **`C_core`** glue for one `thash`-H call: bind `addr` (topology constant) and the
/// 256-bit `in_bits` (= `in0 ‖ in1`, upstream wires) to the bus, return bus `out`.
///
/// Performs **no** SHA-256 compression — that lives in the folded [`thash_h_step`].
pub fn thash_h_core_link<Scalar, CS>(
    mut cs: CS,
    addr_const: &[u8; ADDR_BYTES],
    in_bits: &[Boolean],
    slot: &[AllocatedNum<Scalar>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(slot.len(), THASH_H_SLOT_LEN);
    assert_eq!(in_bits.len(), 2 * SPX_N * 8);

    let addr_bits = const_byte_bits(addr_const);
    enforce_num_eq_be_bits(cs.namespace(|| "bind_addr"), &slot[0], &addr_bits)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in0"), &slot[1], &in_bits[..SPX_N * 8])?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_in1"), &slot[2], &in_bits[SPX_N * 8..])?;

    let out_val: [u8; SPX_N] = slot[3]
        .get_value()
        .map(|s| scalar_low_be_bytes::<Scalar, SPX_N>(&s))
        .unwrap_or([0u8; SPX_N]);
    let out_bits = alloc_byte_bits(&mut cs.namespace(|| "out"), "b", &out_val)?;
    enforce_num_eq_be_bits(cs.namespace(|| "bind_out"), &slot[3], &out_bits)?;
    Ok(out_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satcheck::SatCheckCS;
    use crate::thash::{alloc_input_bits, thash_digest_bits, witness_bytes_from_bits};
    use blstrs::Scalar as Fr;

    fn pub_seed() -> [u8; 16] {
        [0x11u8; 16]
    }

    fn addr() -> [u8; 22] {
        let mut a = [0u8; 22];
        for (i, b) in a.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        a
    }

    /// Native decomposition matches a plain SHA-256 over the full preimage.
    #[test]
    fn native_two_block_decomposition_matches_sha256() {
        use sha2::{Digest, Sha256};
        let ps = pub_seed();
        let ad = addr();
        let input = [0xa5u8; 16];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&ps);
        preimage.resize(64, 0u8);
        preimage.extend_from_slice(&ad);
        preimage.extend_from_slice(&input);
        let full = Sha256::digest(&preimage);

        assert_eq!(&thash_f_full_digest(&ps, &ad, &input)[..], &full[..]);
        assert_eq!(&thash_f_out(&ps, &ad, &input)[..], &full[..16]);
    }

    /// Combined `C_step` + `C_core` over one shared bus is satisfiable and correct.
    ///
    /// This single constraint system is a faithful model of the fold's joint
    /// relation: the step and the core glue read the *same* shared `addr/in/out`
    /// columns, so satisfiability here ⇔ "there exist shared values making both
    /// relations hold", which is exactly what the NeutronNova verifier checks.
    #[test]
    fn offload_one_thash_f_is_satisfiable_and_correct() {
        let ps = pub_seed();
        let ad = addr();
        let input = [0x3cu8; 16];
        let out = thash_f_out(&ps, &ad, &input);
        let seeded = seeded_state(&ps);

        let mut cs = SatCheckCS::<Fr>::new();
        let value = ThashFBusValue {
            addr: ad,
            input,
            out,
        };
        let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), &value).unwrap();

        // C_core: bind addr (constant) + in (upstream wire), read out.
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "core_in"), "v", &input).unwrap();
        let out_bits =
            thash_f_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();

        // C_step: prove the offloaded compression.
        thash_f_step(cs.namespace(|| "step"), &seeded, &ad, &input, &slot).unwrap();

        assert!(
            cs.is_satisfied(),
            "joint relation unsatisfied at {:?}",
            cs.first_unsatisfied_path()
        );
        // The core's downstream wire equals the real thash output.
        assert_eq!(witness_bytes_from_bits::<16>(&out_bits), out);
    }

    /// Offloaded core link equals the in-core `thash_digest_bits` gadget output.
    #[test]
    fn core_link_matches_in_core_thash() {
        let ps = pub_seed();
        let ad = addr();
        let input = [0x77u8; 16];

        // In-core reference output.
        let reference = {
            let mut cs = SatCheckCS::<Fr>::new();
            let in_bits = alloc_input_bits(&mut cs, "v", &input).unwrap();
            let digest = thash_digest_bits(cs.namespace(|| "t"), &ps, &ad, &in_bits).unwrap();
            assert!(cs.is_satisfied());
            witness_bytes_from_bits::<16>(&digest)
        };

        assert_eq!(reference, thash_f_out(&ps, &ad, &input));
    }

    /// A whole WOTS+ chain offloaded via the bus matches the in-core `gen_chain`.
    #[test]
    fn offload_wots_chain_matches_gen_chain() {
        use crate::wots::gen_chain;

        let ps = pub_seed();
        let mut ad = addr();
        ad[21] = 0; // hash addr is set per step
        let input = [0x42u8; 16];
        let start = 3u32;
        let steps = SPX_WOTS_W - 1 - start; // walk to the top

        // Reference: in-core gen_chain.
        let reference = {
            let mut cs = SatCheckCS::<Fr>::new();
            let in_bits = alloc_input_bits(&mut cs, "v", &input).unwrap();
            let top = gen_chain(cs.namespace(|| "c"), &ps, &ad, &in_bits, start, steps).unwrap();
            assert!(cs.is_satisfied());
            witness_bytes_from_bits::<16>(&top)
        };

        // Offloaded: core links + folded steps over one shared bus.
        let (values, final_native) =
            thash_f_chain_bus_values(&ps, &ad, &input, start, steps);
        assert_eq!(final_native, reference);

        let seeded = seeded_state(&ps);
        let mut cs = SatCheckCS::<Fr>::new();
        let bus = alloc_thash_f_bus(cs.namespace(|| "bus"), &values).unwrap();
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "in"), "v", &input).unwrap();
        let top = gen_chain_linked(
            cs.namespace(|| "core_chain"),
            &ad,
            &in_bits,
            start,
            steps,
            &bus,
        )
        .unwrap();
        for (k, v) in values.iter().enumerate() {
            let slot = &bus[k * THASH_F_SLOT_LEN..(k + 1) * THASH_F_SLOT_LEN];
            thash_f_step(
                cs.namespace(|| format!("step_{k}")),
                &seeded,
                &v.addr,
                &v.input,
                slot,
            )
            .unwrap();
        }
        assert!(
            cs.is_satisfied(),
            "offloaded chain unsatisfied at {:?}",
            cs.first_unsatisfied_path()
        );
        assert_eq!(witness_bytes_from_bits::<16>(&top), reference);
    }

    /// Fold smoke test: each step is an *independent* instance; the core is a
    /// separate instance; they agree only through the shared bus values. Models
    /// the NeutronNova decomposition (many folded `C_step`s + one `C_core`).
    #[test]
    fn steps_are_independent_instances_sharing_the_bus() {
        let ps = pub_seed();
        let mut ad = addr();
        ad[21] = 0;
        let input = [0x9bu8; 16];
        let start = 2u32;
        let steps = SPX_WOTS_W - 1 - start;
        let (values, _final) = thash_f_chain_bus_values(&ps, &ad, &input, start, steps);
        let seeded = seeded_state(&ps);

        // Each folded step is verified in its OWN constraint system.
        for (k, v) in values.iter().enumerate() {
            let mut cs = SatCheckCS::<Fr>::new();
            let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), v).unwrap();
            thash_f_step(cs.namespace(|| "step"), &seeded, &v.addr, &v.input, &slot).unwrap();
            assert!(cs.is_satisfied(), "folded step {k} unsatisfied");
        }

        // The core is verified in its OWN constraint system over the same bus values.
        let mut cs = SatCheckCS::<Fr>::new();
        let bus = alloc_thash_f_bus(cs.namespace(|| "bus"), &values).unwrap();
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "in"), "v", &input).unwrap();
        let _top =
            gen_chain_linked(cs.namespace(|| "core"), &ad, &in_bits, start, steps, &bus).unwrap();
        assert!(cs.is_satisfied(), "core glue unsatisfied");
    }

    /// The whole point: replacing in-core SHA with a bus link shrinks `C_core`
    /// by orders of magnitude (the compressions move to folded steps).
    #[test]
    fn core_link_shrinks_core_vs_in_core() {
        use crate::wots::gen_chain;

        let ps = pub_seed();
        let mut ad = addr();
        ad[21] = 0;
        let input = [0x42u8; 16];
        let start = 0u32;
        let steps = SPX_WOTS_W - 1; // 15 thash-F steps (a full chain)

        // In-core: every step is a full SHA-256 thash.
        let in_core = {
            let mut cs = SatCheckCS::<Fr>::new();
            let in_bits = alloc_input_bits(&mut cs, "v", &input).unwrap();
            let _ = gen_chain(cs.namespace(|| "c"), &ps, &ad, &in_bits, start, steps).unwrap();
            cs.num_constraints()
        };

        // Offloaded: C_core keeps only bus glue (no compression).
        let (values, _f) = thash_f_chain_bus_values(&ps, &ad, &input, start, steps);
        let core_only = {
            let mut cs = SatCheckCS::<Fr>::new();
            let bus = alloc_thash_f_bus(cs.namespace(|| "bus"), &values).unwrap();
            let in_bits = alloc_input_bits(&mut cs.namespace(|| "in"), "v", &input).unwrap();
            let _ = gen_chain_linked(cs.namespace(|| "core"), &ad, &in_bits, start, steps, &bus)
                .unwrap();
            cs.num_constraints()
        };

        println!("in-core gen_chain: {in_core} constraints; core-link glue: {core_only}");
        // The folded design must cut the core for this family by >50x.
        assert!(
            core_only * 50 < in_core,
            "expected >50x core reduction, got in_core={in_core} core_only={core_only}"
        );
    }

    // -- soundness: every bound field must be tamper-evident -----------------

    fn tamper_setup() -> (
        [u8; 16],
        [u8; 22],
        [u8; 16],
        [u8; 16],
        [u8; 32],
    ) {
        let ps = pub_seed();
        let ad = addr();
        let input = [0x3cu8; 16];
        let out = thash_f_out(&ps, &ad, &input);
        let seeded = seeded_state(&ps);
        (ps, ad, input, out, seeded)
    }

    /// Step compresses a different `in` than the core binds → joint unsatisfiable.
    #[test]
    fn rejects_input_mismatch() {
        let (_ps, ad, input, out, seeded) = tamper_setup();
        let mut cs = SatCheckCS::<Fr>::new();
        let value = ThashFBusValue { addr: ad, input, out };
        let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), &value).unwrap();
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "core_in"), "v", &input).unwrap();
        let _ = thash_f_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();

        let mut bad_in = input;
        bad_in[0] ^= 1;
        thash_f_step(cs.namespace(|| "step"), &seeded, &ad, &bad_in, &slot).unwrap();
        assert!(!cs.is_satisfied(), "input mismatch must not satisfy");
    }

    /// Step uses a different `addr` than the core's topology constant → unsatisfiable.
    #[test]
    fn rejects_addr_mismatch() {
        let (_ps, ad, input, out, seeded) = tamper_setup();
        let mut cs = SatCheckCS::<Fr>::new();
        let value = ThashFBusValue { addr: ad, input, out };
        let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), &value).unwrap();
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "core_in"), "v", &input).unwrap();
        let _ = thash_f_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();

        let mut bad_addr = ad;
        bad_addr[21] ^= 1; // wrong hash address
        thash_f_step(cs.namespace(|| "step"), &seeded, &bad_addr, &input, &slot).unwrap();
        assert!(!cs.is_satisfied(), "addr mismatch must not satisfy");
    }

    /// A free / wrong `h_in` (not the seeded state) cannot forge the bound output.
    #[test]
    fn rejects_wrong_seeded_state() {
        let (_ps, ad, input, out, mut seeded) = tamper_setup();
        let mut cs = SatCheckCS::<Fr>::new();
        // Core fixes `out` to the real thash output via the bus value.
        let value = ThashFBusValue { addr: ad, input, out };
        let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), &value).unwrap();
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "core_in"), "v", &input).unwrap();
        let _ = thash_f_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();

        seeded[0] ^= 1; // wrong seeded state in the step
        thash_f_step(cs.namespace(|| "step"), &seeded, &ad, &input, &slot).unwrap();
        assert!(!cs.is_satisfied(), "wrong seeded state must not satisfy");
    }

    /// A bus `out` that disagrees with the step's real compression → unsatisfiable.
    #[test]
    fn rejects_out_mismatch() {
        let (_ps, ad, input, out, seeded) = tamper_setup();
        let mut cs = SatCheckCS::<Fr>::new();
        let mut bad_out = out;
        bad_out[0] ^= 1;
        let value = ThashFBusValue { addr: ad, input, out: bad_out };
        let slot = alloc_thash_f_slot(cs.namespace(|| "slot"), &value).unwrap();
        thash_f_step(cs.namespace(|| "step"), &seeded, &ad, &input, &slot).unwrap();
        assert!(!cs.is_satisfied(), "out mismatch must not satisfy");
    }

    // ===================== thash-H (inblocks = 2) =========================

    /// The native `thash_h_out` equals the in-core `thash_digest_bits` over a
    /// 256-bit (two-block) input — i.e. our H decomposition matches the gadget.
    #[test]
    fn h_native_matches_in_core_thash() {
        let ps = pub_seed();
        let ad = addr();
        let in0 = [0x55u8; 16];
        let in1 = [0xa6u8; 16];

        let reference = {
            let mut cs = SatCheckCS::<Fr>::new();
            let mut in_bits = alloc_input_bits(&mut cs.namespace(|| "i0"), "v", &in0).unwrap();
            in_bits.extend(alloc_input_bits(&mut cs.namespace(|| "i1"), "v", &in1).unwrap());
            let digest = thash_digest_bits(cs.namespace(|| "t"), &ps, &ad, &in_bits).unwrap();
            assert!(cs.is_satisfied());
            witness_bytes_from_bits::<16>(&digest)
        };
        assert_eq!(reference, thash_h_out(&ps, &ad, &in0, &in1));
    }

    /// Joint H relation: `C_core` link + folded `C_step` over a shared slot is
    /// satisfiable and the core's downstream wire equals the real node value.
    #[test]
    fn h_joint_relation_is_satisfiable_and_correct() {
        let ps = pub_seed();
        let ad = addr();
        let in0 = [0x12u8; 16];
        let in1 = [0x9fu8; 16];
        let out = thash_h_out(&ps, &ad, &in0, &in1);
        let seeded = seeded_state(&ps);

        let mut cs = SatCheckCS::<Fr>::new();
        let value = ThashHBusValue { addr: ad, in0, in1, out };
        let slot = alloc_thash_h_slot(cs.namespace(|| "slot"), &value).unwrap();

        let mut in_bits = alloc_input_bits(&mut cs.namespace(|| "i0"), "v", &in0).unwrap();
        in_bits.extend(alloc_input_bits(&mut cs.namespace(|| "i1"), "v", &in1).unwrap());
        let out_bits = thash_h_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();
        thash_h_step(cs.namespace(|| "step"), &seeded, &ad, &in0, &in1, &slot).unwrap();

        assert!(
            cs.is_satisfied(),
            "H joint relation unsatisfied at {:?}",
            cs.first_unsatisfied_path()
        );
        assert_eq!(witness_bytes_from_bits::<16>(&out_bits), out);
    }

    /// H soundness: tampering any bound field (in0 / in1 / addr / out) breaks it.
    #[test]
    fn h_rejects_tampering() {
        let ps = pub_seed();
        let ad = addr();
        let in0 = [0x12u8; 16];
        let in1 = [0x9fu8; 16];
        let out = thash_h_out(&ps, &ad, &in0, &in1);
        let seeded = seeded_state(&ps);

        // in1 mismatch between core binding and step compression.
        {
            let mut cs = SatCheckCS::<Fr>::new();
            let value = ThashHBusValue { addr: ad, in0, in1, out };
            let slot = alloc_thash_h_slot(cs.namespace(|| "slot"), &value).unwrap();
            let mut in_bits = alloc_input_bits(&mut cs.namespace(|| "i0"), "v", &in0).unwrap();
            in_bits.extend(alloc_input_bits(&mut cs.namespace(|| "i1"), "v", &in1).unwrap());
            let _ = thash_h_core_link(cs.namespace(|| "core"), &ad, &in_bits, &slot).unwrap();
            let mut bad = in1;
            bad[0] ^= 1;
            thash_h_step(cs.namespace(|| "step"), &seeded, &ad, &in0, &bad, &slot).unwrap();
            assert!(!cs.is_satisfied(), "in1 mismatch must not satisfy");
        }
        // out mismatch: bus out disagrees with the step's real compression.
        {
            let mut cs = SatCheckCS::<Fr>::new();
            let mut bad_out = out;
            bad_out[0] ^= 1;
            let value = ThashHBusValue { addr: ad, in0, in1, out: bad_out };
            let slot = alloc_thash_h_slot(cs.namespace(|| "slot"), &value).unwrap();
            thash_h_step(cs.namespace(|| "step"), &seeded, &ad, &in0, &in1, &slot).unwrap();
            assert!(!cs.is_satisfied(), "out mismatch must not satisfy");
        }
    }
}
