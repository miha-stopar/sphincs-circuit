//! Minimal R1CS, relaxed R1CS, and the Nova folding operation.
//!
//! This is intentionally a from-scratch, dense, fully readable implementation.
//! It is NOT optimized and NOT zero-knowledge: it exposes full vectors so the
//! folding math is inspectable. A production system (Nova, NeutronNova, Spartan2)
//! replaces the raw vectors `z` and `E` with *commitments* and proves satisfaction
//! with a SNARK; the algebra below is exactly what those commitments are over.

use crate::Scalar;
use ff::Field;

/// An R1CS instance shape: matrices A, B, C with `num_constraints` rows and
/// `num_vars` columns. The witness vector `z` has length `num_vars` and uses the
/// convention `z[0] == 1` (the constant wire).
#[derive(Debug, Clone)]
pub struct R1cs {
    pub num_constraints: usize,
    pub num_vars: usize,
    pub a: Vec<Vec<Scalar>>,
    pub b: Vec<Vec<Scalar>>,
    pub c: Vec<Vec<Scalar>>,
}

impl R1cs {
    /// Build an all-zero R1CS of the given shape; fill rows with [`R1cs::set`].
    pub fn zeros(num_constraints: usize, num_vars: usize) -> Self {
        let row = || vec![Scalar::ZERO; num_vars];
        Self {
            num_constraints,
            num_vars,
            a: (0..num_constraints).map(|_| row()).collect(),
            b: (0..num_constraints).map(|_| row()).collect(),
            c: (0..num_constraints).map(|_| row()).collect(),
        }
    }

    /// Matrix-vector product `M · z` for one of the matrices (returns one value
    /// per constraint row).
    fn matvec(m: &[Vec<Scalar>], z: &[Scalar]) -> Vec<Scalar> {
        m.iter()
            .map(|row| {
                row.iter()
                    .zip(z.iter())
                    .fold(Scalar::ZERO, |acc, (m_ij, z_j)| acc + *m_ij * *z_j)
            })
            .collect()
    }

    pub fn az(&self, z: &[Scalar]) -> Vec<Scalar> {
        Self::matvec(&self.a, z)
    }
    pub fn bz(&self, z: &[Scalar]) -> Vec<Scalar> {
        Self::matvec(&self.b, z)
    }
    pub fn cz(&self, z: &[Scalar]) -> Vec<Scalar> {
        Self::matvec(&self.c, z)
    }

    /// Strict satisfaction: `(A z) ∘ (B z) == (C z)` for every row.
    pub fn is_satisfied(&self, z: &[Scalar]) -> bool {
        let az = self.az(z);
        let bz = self.bz(z);
        let cz = self.cz(z);
        az.iter()
            .zip(&bz)
            .zip(&cz)
            .all(|((a, b), c)| *a * *b == *c)
    }

    /// Wrap a strict witness as a relaxed instance with `u = 1`, `E = 0`.
    pub fn relax(&self, z: Vec<Scalar>) -> RelaxedInstance {
        RelaxedInstance {
            z,
            u: Scalar::ONE,
            e: vec![Scalar::ZERO; self.num_constraints],
        }
    }
}

/// A relaxed R1CS instance: the satisfaction equation is loosened to
/// `(A z) ∘ (B z) == u · (C z) + E`, where `u` is a scalar and `E` is an error
/// vector. Strict R1CS is the special case `u = 1, E = 0`. Folding produces
/// relaxed instances with `u != 1` and `E != 0` — that is the whole point.
#[derive(Debug, Clone)]
pub struct RelaxedInstance {
    pub z: Vec<Scalar>,
    pub u: Scalar,
    pub e: Vec<Scalar>,
}

impl RelaxedInstance {
    /// Check `(A z) ∘ (B z) == u · (C z) + E`.
    pub fn is_satisfied(&self, shape: &R1cs) -> bool {
        let az = shape.az(&self.z);
        let bz = shape.bz(&self.z);
        let cz = shape.cz(&self.z);
        for i in 0..shape.num_constraints {
            let lhs = az[i] * bz[i];
            let rhs = self.u * cz[i] + self.e[i];
            if lhs != rhs {
                return false;
            }
        }
        true
    }
}

/// The Nova "cross term" `T` for folding two relaxed instances over `shape`:
///
/// `T = (A z1) ∘ (B z2) + (A z2) ∘ (B z1) − u1 · (C z2) − u2 · (C z1)`
///
/// In real Nova the prover commits to `T` and the verifier folds the commitment;
/// here we return the raw vector.
pub fn cross_term(shape: &R1cs, i1: &RelaxedInstance, i2: &RelaxedInstance) -> Vec<Scalar> {
    let az1 = shape.az(&i1.z);
    let bz1 = shape.bz(&i1.z);
    let cz1 = shape.cz(&i1.z);
    let az2 = shape.az(&i2.z);
    let bz2 = shape.bz(&i2.z);
    let cz2 = shape.cz(&i2.z);

    (0..shape.num_constraints)
        .map(|i| az1[i] * bz2[i] + az2[i] * bz1[i] - i1.u * cz2[i] - i2.u * cz1[i])
        .collect()
}

/// Fold `i2` into `i1` with challenge `r`, returning a single relaxed instance.
///
/// `z = z1 + r·z2`, `u = u1 + r·u2`, `E = E1 + r·T + r²·E2`.
///
/// Soundness fact (proven by the algebra and exercised in tests): the folded
/// instance satisfies the relaxed equation **iff** both inputs did (except with
/// negligible probability over a random `r`). One satisfied folded instance thus
/// stands in for two satisfied instances — repeat to collapse N into one.
pub fn fold(
    shape: &R1cs,
    i1: &RelaxedInstance,
    i2: &RelaxedInstance,
    r: Scalar,
) -> RelaxedInstance {
    let t = cross_term(shape, i1, i2);
    let r2 = r * r;

    let z = i1
        .z
        .iter()
        .zip(&i2.z)
        .map(|(a, b)| *a + r * *b)
        .collect();
    let u = i1.u + r * i2.u;
    let e = (0..shape.num_constraints)
        .map(|i| i1.e[i] + r * t[i] + r2 * i2.e[i])
        .collect();

    RelaxedInstance { z, u, e }
}
