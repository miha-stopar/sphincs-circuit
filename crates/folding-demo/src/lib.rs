//! # folding-demo
//!
//! A small, from-scratch, fully tested demonstration of **how folding integrates
//! with non-folded checks** — the exact pattern Track A uses for SPHINCS+:
//!
//! * a uniform **step** relation, folded `N` times (stand-in for one SHA-256
//!   compression), and
//! * a separate **core** relation, proven once, that wires the steps together
//!   and binds them to public values (stand-in for `C_core`).
//!
//! The point this code makes concrete:
//!
//! > Folding proves *each step is individually correct*. It does **not** prove
//! > the steps form a chain, match the public endpoints, or satisfy any
//! > non-hash predicate. The **core** circuit does that — and it is proven once,
//! > not folded.
//!
//! See `src/bin/walkthrough.rs` for a narrated run, and the tests at the bottom
//! of this file for the load-bearing assertions (especially
//! `broken_link_passes_fold_but_fails_core`).

pub mod core;
pub mod r1cs;
pub mod step;

/// Concrete prime field used throughout (BLS12-381 scalar field).
pub type Scalar = blstrs::Scalar;

use crate::core::{core_shape, core_witness, CoreLayout};
use crate::r1cs::{fold, R1cs, RelaxedInstance};
use crate::step::{step_native, step_shape, step_witness, IN, OUT};
use ff::Field;

/// A chain of `N` steps: `in_0 = start`, `out_i = in_i^2 + block_i`,
/// `in_{i+1} = out_i`. The public `root` is `out_{N-1}`.
#[derive(Debug, Clone)]
pub struct Chain {
    pub start: Scalar,
    pub blocks: Vec<Scalar>,
    pub ins: Vec<Scalar>,
    pub outs: Vec<Scalar>,
}

impl Chain {
    /// Build the honest chain for a given start and per-step blocks.
    pub fn new(start: Scalar, blocks: Vec<Scalar>) -> Self {
        let mut ins = Vec::with_capacity(blocks.len());
        let mut outs = Vec::with_capacity(blocks.len());
        let mut cur = start;
        for &b in &blocks {
            let out = step_native(cur, b);
            ins.push(cur);
            outs.push(out);
            cur = out;
        }
        Self {
            start,
            blocks,
            ins,
            outs,
        }
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Public root = last output of the chain.
    pub fn root(&self) -> Scalar {
        *self.outs.last().expect("non-empty chain")
    }

    /// WOTS+-style non-hash predicate value: sum of all outputs.
    pub fn checksum(&self) -> Scalar {
        self.outs.iter().fold(Scalar::ZERO, |acc, x| acc + *x)
    }

    /// Honest per-step witnesses (one R1CS assignment per step).
    pub fn step_witnesses(&self) -> Vec<Vec<Scalar>> {
        self.ins
            .iter()
            .zip(&self.blocks)
            .map(|(&i, &b)| step_witness(i, b))
            .collect()
    }
}

/// Fiat–Shamir stand-in: a deterministic, nonzero folding challenge per fold.
///
/// Real systems derive `r` by hashing the transcript (commitments so far). The
/// folding *identity* holds for any `r`; a *random* `r` is what makes folding
/// sound. We use a fixed schedule here so tests are deterministic.
fn challenge(i: usize) -> Scalar {
    Scalar::from((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(7))
}

/// Fold a list of step witnesses (each a strict R1CS assignment) into a single
/// relaxed accumulator. Returns the accumulator and the step shape.
pub fn fold_steps(step_witnesses: &[Vec<Scalar>]) -> (R1cs, RelaxedInstance) {
    assert!(!step_witnesses.is_empty(), "need at least one step");
    let shape = step_shape();
    let mut acc = shape.relax(step_witnesses[0].clone());
    for (i, w) in step_witnesses.iter().enumerate().skip(1) {
        let inst = shape.relax(w.clone());
        acc = fold(&shape, &acc, &inst, challenge(i));
    }
    (shape, acc)
}

/// Outcome of running the full pipeline.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub num_steps: usize,
    /// Each step witness satisfies the step R1CS on its own (informational).
    pub all_steps_individually_ok: bool,
    /// The single folded accumulator satisfies the relaxed R1CS
    /// (⇒ all steps were individually correct).
    pub folded_ok: bool,
    /// The core R1CS (linking + boundary + checksum) is satisfied.
    pub core_ok: bool,
    /// The boundary values used by the core equal the step witnesses' in/out
    /// wires (in real systems this is enforced by shared commitments).
    pub link_ok: bool,
    /// Final `u` of the folded accumulator (1 for a single step, grows as you fold).
    pub folded_u: Scalar,
}

impl VerifyResult {
    /// The verifier accepts iff folding *and* core *and* linking all hold.
    pub fn accept(&self) -> bool {
        self.folded_ok && self.core_ok && self.link_ok
    }
}

/// The full pipeline, with every input exposed so tests can tamper with each
/// piece independently:
///
/// * `step_witnesses` — one assignment per folded step,
/// * `core_ins` / `core_outs` — the boundary values the core circuit consumes,
/// * `start` / `root` / `checksum` — public values baked into the core.
pub fn verify(
    step_witnesses: &[Vec<Scalar>],
    core_ins: &[Scalar],
    core_outs: &[Scalar],
    start: Scalar,
    root: Scalar,
    checksum: Scalar,
) -> VerifyResult {
    let n = step_witnesses.len();

    // (a) Sanity: does each step satisfy the step relation on its own?
    let step = step_shape();
    let all_steps_individually_ok = step_witnesses.iter().all(|w| step.is_satisfied(w));

    // (b) Fold everything into one accumulator and check the relaxed equation.
    let (shape, acc) = fold_steps(step_witnesses);
    let folded_ok = acc.is_satisfied(&shape);

    // (c) Core: the non-folded glue, proven once.
    let layout = CoreLayout::new(n);
    let core = core_shape(&layout, start, root, checksum);
    let core_z = core_witness(&layout, core_ins, core_outs);
    let core_ok = core.is_satisfied(&core_z);

    // (d) Linking: the values the core used must be the SAME values that were
    //     folded. Production systems get this for free via commitments; here we
    //     check it explicitly.
    let link_ok = (0..n).all(|i| {
        step_witnesses[i][IN] == core_ins[i] && step_witnesses[i][OUT] == core_outs[i]
    });

    VerifyResult {
        num_steps: n,
        all_steps_individually_ok,
        folded_ok,
        core_ok,
        link_ok,
        folded_u: acc.u,
    }
}

/// Convenience: run the honest pipeline for a chain.
pub fn verify_chain(chain: &Chain) -> VerifyResult {
    let witnesses = chain.step_witnesses();
    verify(
        &witnesses,
        &chain.ins,
        &chain.outs,
        chain.start,
        chain.root(),
        chain.checksum(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chain(n: usize) -> Chain {
        let blocks = (0..n).map(|i| Scalar::from(i as u64 + 1)).collect();
        Chain::new(Scalar::from(3u64), blocks)
    }

    #[test]
    fn fold_identity_two_satisfied_instances() {
        // Two unrelated but individually-valid step instances fold to a
        // satisfied relaxed instance.
        let shape = step_shape();
        let w1 = step_witness(Scalar::from(3u64), Scalar::from(5u64));
        let w2 = step_witness(Scalar::from(9u64), Scalar::from(2u64));
        assert!(shape.is_satisfied(&w1));
        assert!(shape.is_satisfied(&w2));

        let i1 = shape.relax(w1);
        let i2 = shape.relax(w2);
        let acc = fold(&shape, &i1, &i2, challenge(1));
        assert!(acc.is_satisfied(&shape), "folded instance must satisfy relaxed R1CS");
        // After folding two strict (u=1) instances, u = 1 + r != 1.
        assert_ne!(acc.u, Scalar::ONE);
    }

    #[test]
    fn fold_detects_an_unsatisfied_instance() {
        // If one instance is NOT satisfied, the folded instance is (almost surely) not satisfied.
        let shape = step_shape();
        let good = shape.relax(step_witness(Scalar::from(3u64), Scalar::from(5u64)));
        let mut bad_w = step_witness(Scalar::from(4u64), Scalar::from(6u64));
        bad_w[OUT] += Scalar::ONE; // break out = in^2 + block
        let bad = shape.relax(bad_w);
        assert!(!shape.is_satisfied(&bad.z));
        let acc = fold(&shape, &good, &bad, challenge(1));
        assert!(!acc.is_satisfied(&shape));
    }

    #[test]
    fn honest_chain_is_accepted() {
        let chain = sample_chain(6);
        let r = verify_chain(&chain);
        assert!(r.all_steps_individually_ok);
        assert!(r.folded_ok);
        assert!(r.core_ok);
        assert!(r.link_ok);
        assert!(r.accept());
        assert_ne!(r.folded_u, Scalar::ONE, "u should grow after folding many steps");
    }

    #[test]
    fn tampered_step_breaks_the_fold() {
        // Corrupt one step's output so that step's "compression" is wrong.
        // Folding must catch it; the verifier rejects.
        let chain = sample_chain(6);
        let mut witnesses = chain.step_witnesses();
        witnesses[3][OUT] += Scalar::ONE; // wrong "hash output"

        // Keep the core consistent with the (now corrupted) boundary so we
        // isolate the fold's job.
        let mut outs = chain.outs.clone();
        outs[3] += Scalar::ONE;

        let r = verify(
            &witnesses,
            &chain.ins,
            &outs,
            chain.start,
            *outs.last().unwrap(),
            outs.iter().fold(Scalar::ZERO, |a, x| a + *x),
        );
        assert!(!r.folded_ok, "folding must reject a bad step");
        assert!(!r.accept());
    }

    #[test]
    fn broken_link_passes_fold_but_fails_core() {
        // THE key demonstration. Build N steps that are each individually valid
        // (out_i = in_i^2 + block_i) but DO NOT chain: in_3 is chosen freely,
        // not equal to out_2. Folding happily accepts (every step is correct on
        // its own); only the CORE catches the broken chain.
        let n = 5;
        let mut ins = vec![Scalar::from(3u64)];
        let blocks: Vec<Scalar> = (0..n).map(|i| Scalar::from(i as u64 + 1)).collect();

        // Honest chain would set in_{i+1} = out_i. We deliberately break it at i=2.
        let mut outs = Vec::new();
        for i in 0..n {
            let out = step_native(ins[i], blocks[i]);
            outs.push(out);
            if i + 1 < n {
                if i == 2 {
                    // BROKEN LINK: pick an arbitrary next input != out_i.
                    ins.push(Scalar::from(999u64));
                } else {
                    ins.push(out);
                }
            }
        }

        let witnesses: Vec<Vec<Scalar>> = (0..n)
            .map(|i| step_witness(ins[i], blocks[i]))
            .collect();

        // Each step is individually valid → folding accepts.
        let shape = step_shape();
        assert!(witnesses.iter().all(|w| shape.is_satisfied(w)));

        let root = *outs.last().unwrap();
        let checksum = outs.iter().fold(Scalar::ZERO, |a, x| a + *x);
        let r = verify(&witnesses, &ins, &outs, ins[0], root, checksum);

        assert!(r.all_steps_individually_ok);
        assert!(r.folded_ok, "folding does NOT see the broken chain");
        assert!(!r.core_ok, "core MUST catch the broken link (out_2 != in_3)");
        assert!(!r.accept());
    }

    #[test]
    fn wrong_public_root_fails_core() {
        let chain = sample_chain(4);
        let witnesses = chain.step_witnesses();
        let wrong_root = chain.root() + Scalar::ONE;
        let r = verify(
            &witnesses,
            &chain.ins,
            &chain.outs,
            chain.start,
            wrong_root, // verifier-supplied public root is wrong
            chain.checksum(),
        );
        assert!(r.folded_ok);
        assert!(!r.core_ok, "root binding must fail");
        assert!(!r.accept());
    }

    #[test]
    fn link_mismatch_between_core_and_steps_is_caught() {
        // The core uses boundary values that differ from what was folded.
        let chain = sample_chain(4);
        let witnesses = chain.step_witnesses();
        let mut core_ins = chain.ins.clone();
        core_ins[1] += Scalar::ONE; // core lies about a boundary value
        let r = verify(
            &witnesses,
            &core_ins,
            &chain.outs,
            chain.start,
            chain.root(),
            chain.checksum(),
        );
        assert!(!r.link_ok, "link check must catch core/step value mismatch");
        assert!(!r.accept());
    }
}
