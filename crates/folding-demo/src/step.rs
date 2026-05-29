//! The uniform STEP relation — the thing we fold N times.
//!
//! In the real Track A circuit one step is a SHA-256 compression
//! `h_out = Compress(h_in, block)` (~25k constraints). Here we use a tiny
//! arithmetic stand-in with the SAME structural role:
//!
//! ```text
//!     out = in^2 + block
//! ```
//!
//! What matters for the folding lesson is not the function itself but that:
//!   * every step has the *same* R1CS shape (so instances are foldable), and
//!   * each step has a private `block` and links `in -> out`.
//!
//! Witness (z) layout, with z[0] = 1 (constant wire):
//!
//! | index | wire    | meaning                  |
//! |-------|---------|--------------------------|
//! |   0   | one     | constant 1               |
//! |   1   | `in`    | input state of this step |
//! |   2   | `block` | private per-step input   |
//! |   3   | `out`   | output state of this step|
//! |   4   | `t`     | aux: t = in*in           |
//!
//! Constraints:
//!   C1:  in  * in  = t            (square)
//!   C2: (t + block) * 1 = out     (add block)

use crate::r1cs::R1cs;
use crate::Scalar;
use ff::Field;

pub const ONE: usize = 0;
pub const IN: usize = 1;
pub const BLOCK: usize = 2;
pub const OUT: usize = 3;
pub const T: usize = 4;
pub const NUM_VARS: usize = 5;
pub const NUM_CONSTRAINTS: usize = 2;

/// Build the (constant) R1CS shape shared by every step instance.
pub fn step_shape() -> R1cs {
    let mut r = R1cs::zeros(NUM_CONSTRAINTS, NUM_VARS);

    // C1: in * in = t
    r.a[0][IN] = Scalar::ONE;
    r.b[0][IN] = Scalar::ONE;
    r.c[0][T] = Scalar::ONE;

    // C2: (t + block) * one = out
    r.a[1][T] = Scalar::ONE;
    r.a[1][BLOCK] = Scalar::ONE;
    r.b[1][ONE] = Scalar::ONE;
    r.c[1][OUT] = Scalar::ONE;

    r
}

/// Native evaluation of one step: `out = in^2 + block`.
pub fn step_native(input: Scalar, block: Scalar) -> Scalar {
    input * input + block
}

/// Build a satisfying witness vector for one step.
pub fn step_witness(input: Scalar, block: Scalar) -> Vec<Scalar> {
    let t = input * input;
    let out = t + block;
    let mut z = vec![Scalar::ZERO; NUM_VARS];
    z[ONE] = Scalar::ONE;
    z[IN] = input;
    z[BLOCK] = block;
    z[OUT] = out;
    z[T] = t;
    z
}
