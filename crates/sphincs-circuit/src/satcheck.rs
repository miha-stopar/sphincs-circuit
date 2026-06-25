//! Memory-light satisfaction-checking constraint system.
//!
//! # Why this exists
//!
//! [`bellpepper_core::test_cs::TestConstraintSystem`] stores, for **every** constraint, the three
//! linear combinations plus a `String` path used for diagnostics. For the full SPHINCS+ verify
//! core (millions of constraints) that needs tens of GB and swap-thrashes — the
//! `valid_signature_satisfies_core*` tests can run for hours and never finish on a normal machine
//! (see `docs/VERIFY_CORE_TESTS.md`).
//!
//! [`SatCheckCS`] instead evaluates each `A · B = C` against the running witness **immediately**
//! and drops the linear combinations, so peak memory is `O(num_variables)` (a couple of `Vec`s of
//! field elements) rather than `O(num_constraints × lc_size)`. It cannot pretty-print which named
//! constraint failed, but it reports the first failing constraint **index**, which is enough to
//! assert satisfiability for the large cores.
//!
//! It is a drop-in `ConstraintSystem` for satisfiability checks only — it does not build an R1CS
//! shape and is not a witness generator.

use bellpepper_core::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use ff::PrimeField;

/// A constraint system that only checks `A · B = C` against the witness as constraints arrive.
#[derive(Debug)]
pub struct SatCheckCS<Scalar: PrimeField> {
    input_assignment: Vec<Scalar>,
    aux_assignment: Vec<Scalar>,
    num_constraints: usize,
    first_unsatisfied: Option<usize>,
    namespace_stack: Vec<String>,
    first_unsatisfied_path: Option<String>,
}

impl<Scalar: PrimeField> SatCheckCS<Scalar> {
    /// New system with the constant-one input (`CS::one()` → `Index::Input(0)`).
    pub fn new() -> Self {
        Self {
            input_assignment: vec![Scalar::ONE],
            aux_assignment: Vec::new(),
            num_constraints: 0,
            first_unsatisfied: None,
            namespace_stack: Vec::new(),
            first_unsatisfied_path: None,
        }
    }

    /// `true` iff every constraint enforced so far holds for the assigned witness.
    pub fn is_satisfied(&self) -> bool {
        self.first_unsatisfied.is_none()
    }

    /// Index of the first unsatisfied constraint, if any (in enforcement order).
    pub fn which_is_unsatisfied(&self) -> Option<usize> {
        self.first_unsatisfied
    }

    /// Full namespace path (`a/b/c/annotation`) of the first unsatisfied constraint, if any.
    pub fn first_unsatisfied_path(&self) -> Option<&str> {
        self.first_unsatisfied_path.as_deref()
    }

    /// Total number of enforced constraints.
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    /// Number of public inputs (including the constant-one wire).
    pub fn num_inputs(&self) -> usize {
        self.input_assignment.len()
    }

    /// Number of auxiliary (witness) variables.
    pub fn num_aux(&self) -> usize {
        self.aux_assignment.len()
    }
}

impl<Scalar: PrimeField> Default for SatCheckCS<Scalar> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Scalar: PrimeField> ConstraintSystem<Scalar> for SatCheckCS<Scalar> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.aux_assignment.len();
        let value = f()?;
        self.aux_assignment.push(value);
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(&mut self, _annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.input_assignment.len();
        let value = f()?;
        self.input_assignment.push(value);
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let index = self.num_constraints;
        self.num_constraints += 1;

        // Once a violation is found we keep counting but skip evaluation to save work.
        if self.first_unsatisfied.is_some() {
            return;
        }

        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());

        let av = a.eval(&self.input_assignment, &self.aux_assignment);
        let bv = b.eval(&self.input_assignment, &self.aux_assignment);
        let cv = c.eval(&self.input_assignment, &self.aux_assignment);

        if av * bv != cv {
            self.first_unsatisfied = Some(index);
            // Only build the (allocating) path on the failure path to keep the hot loop cheap.
            let mut path = self.namespace_stack.join("/");
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&annotation().into());
            self.first_unsatisfied_path = Some(path);
        }
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Track names only until we have located the first failure (keeps the common path light).
        if self.first_unsatisfied.is_none() {
            self.namespace_stack.push(name_fn().into());
        } else {
            self.namespace_stack.push(String::new());
        }
    }

    fn pop_namespace(&mut self) {
        self.namespace_stack.pop();
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    /// `SatCheckCS` must agree with `TestConstraintSystem` on a small SHA-256 message hash.
    #[test]
    fn agrees_with_test_cs_on_hash_message() {
        use crate::hash_msg::hash_message_bits;

        let r = [0x11u8; crate::thash::SPX_N];
        let pk = [0x22u8; crate::hash_msg::SPX_PK_BYTES];
        let msg = b"satcheck agreement";

        let mut test_cs = TestConstraintSystem::<Fr>::new();
        hash_message_bits(&mut test_cs, &r, &pk, msg, msg.len()).expect("test_cs");

        let mut sat = SatCheckCS::<Fr>::new();
        hash_message_bits(&mut sat, &r, &pk, msg, msg.len()).expect("satcheck");

        assert!(test_cs.is_satisfied());
        assert!(sat.is_satisfied());
        assert_eq!(test_cs.num_constraints(), sat.num_constraints());
    }

    /// A deliberately broken constraint is detected.
    #[test]
    fn detects_unsatisfiable_constraint() {
        let mut sat = SatCheckCS::<Fr>::new();
        let a = sat
            .alloc(|| "a", || Ok(Fr::from(3u64)))
            .expect("alloc a");
        // Enforce a * 1 = 4, which is false for a = 3.
        sat.enforce(
            || "bad",
            |lc| lc + a,
            |lc| lc + SatCheckCS::<Fr>::one(),
            |lc| lc + (Fr::from(4u64), SatCheckCS::<Fr>::one()),
        );
        assert!(!sat.is_satisfied());
        assert_eq!(sat.which_is_unsatisfied(), Some(0));
    }
}
