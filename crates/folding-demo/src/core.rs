//! The CORE relation — the non-folded "glue", proven ONCE.
//!
//! Folding proves each step is individually correct (`out = in^2 + block` for
//! every instance). It does NOT, by itself, prove the steps form a chain, nor
//! that the chain matches the public endpoints, nor any non-hash predicate.
//! Those checks live here, in a single R1CS instance that is proven once
//! (not folded).
//!
//! This mirrors SPHINCS+ `C_core`: it does no bulk hashing; it wires endpoints
//! (`h_out_i == h_in_{i+1}`), binds to public values (`root == PK.root`), and
//! enforces non-hash logic (FORS index selection, WOTS+ checksum, ...).
//!
//! Here the core enforces, over the per-step boundary values:
//!   1. boundary:  in_0   == start         (public)
//!   2. linking:   out_i  == in_{i+1}       (the chain glue, for all i)
//!   3. root:      out_{N-1} == root        (public)
//!   4. checksum:  Σ out_i == checksum      (a stand-in for WOTS+ checksum;
//!                                           a non-hash arithmetic predicate)
//!
//! Public values (`start`, `root`, `checksum`) are baked into the matrices as
//! constants, exactly like Spartan2 bakes Fiat-Shamir/public inputs into the
//! R1CS coefficients to keep the witness minimal.

use crate::r1cs::R1cs;
use crate::Scalar;
use ff::Field;

/// Indices into the core witness vector for a chain of `n` steps.
pub struct CoreLayout {
    pub n: usize,
}

impl CoreLayout {
    pub fn new(n: usize) -> Self {
        assert!(n >= 1, "need at least one step");
        Self { n }
    }
    pub const fn one(&self) -> usize {
        0
    }
    /// Witness index of `in_i`.
    pub fn in_idx(&self, i: usize) -> usize {
        1 + i
    }
    /// Witness index of `out_i`.
    pub fn out_idx(&self, i: usize) -> usize {
        1 + self.n + i
    }
    pub fn num_vars(&self) -> usize {
        1 + 2 * self.n
    }
    /// start(1) + linking(n-1) + root(1) + checksum(1)
    pub fn num_constraints(&self) -> usize {
        self.n + 2
    }
}

/// Build the core R1CS shape, baking the public `start`, `root`, `checksum`.
pub fn core_shape(layout: &CoreLayout, start: Scalar, root: Scalar, checksum: Scalar) -> R1cs {
    let n = layout.n;
    let mut r = R1cs::zeros(layout.num_constraints(), layout.num_vars());
    let one = layout.one();
    let mut row = 0;

    // 1. in_0 * one = start    (=> in_0 == start)
    r.a[row][layout.in_idx(0)] = Scalar::ONE;
    r.b[row][one] = Scalar::ONE;
    r.c[row][one] = start;
    row += 1;

    // 2. out_i * one = in_{i+1}   for i in 0..n-1   (chain linking)
    for i in 0..n - 1 {
        r.a[row][layout.out_idx(i)] = Scalar::ONE;
        r.b[row][one] = Scalar::ONE;
        r.c[row][layout.in_idx(i + 1)] = Scalar::ONE;
        row += 1;
    }

    // 3. out_{n-1} * one = root   (=> out_{n-1} == root)
    r.a[row][layout.out_idx(n - 1)] = Scalar::ONE;
    r.b[row][one] = Scalar::ONE;
    r.c[row][one] = root;
    row += 1;

    // 4. (Σ out_i) * one = checksum   (non-hash predicate, e.g. WOTS+ checksum)
    for i in 0..n {
        r.a[row][layout.out_idx(i)] = Scalar::ONE;
    }
    r.b[row][one] = Scalar::ONE;
    r.c[row][one] = checksum;

    r
}

/// Build the core witness from the per-step boundary values.
///
/// `ins[i]`, `outs[i]` are the input/output of step `i`. In a real system these
/// would be opened from the *same commitments* that were folded; here we pass
/// them explicitly and separately assert they match the step witnesses
/// (see `link_matches_steps` in `lib.rs`).
pub fn core_witness(layout: &CoreLayout, ins: &[Scalar], outs: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(ins.len(), layout.n);
    assert_eq!(outs.len(), layout.n);
    let mut z = vec![Scalar::ZERO; layout.num_vars()];
    z[layout.one()] = Scalar::ONE;
    for i in 0..layout.n {
        z[layout.in_idx(i)] = ins[i];
        z[layout.out_idx(i)] = outs[i];
    }
    z
}
