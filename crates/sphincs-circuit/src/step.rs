//! Step circuit wrapper: one PQClean trace row satisfies `C_step`.

use crate::sha256_compress;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// Inputs for one folded step instance (matches PQClean trace row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepInput {
    pub h_in: [u8; 32],
    pub block: [u8; 64],
    pub h_out: [u8; 32],
}

/// Single-compression step circuit (`C_step`).
pub struct StepCircuit;

impl StepCircuit {
    pub fn synthesize<Scalar, CS>(cs: CS, input: &StepInput) -> Result<(), SynthesisError>
    where
        Scalar: ff::PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        sha256_compress::synthesize_compression(cs, &input.h_in, &input.block, &input.h_out)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

    fn step_from_row(c: &sphincs_ref::Sha256Compression) -> StepInput {
        StepInput {
            h_in: c.h_in,
            block: c.block,
            h_out: c.h_out,
        }
    }

    #[test]
    fn step_satisfied_for_trace_prefix() {
        let seed = [7u8; CRYPTO_SEEDBYTES];
        let msg = b"sphincs-circuit M1 step test";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        assert!(trace.len() > 100);

        for (i, row) in trace.compressions.iter().take(20).enumerate() {
            let input = step_from_row(row);
            let mut cs = TestConstraintSystem::<Fr>::new();
            StepCircuit::synthesize(&mut cs, &input).expect("synth");
            assert!(
                cs.is_satisfied(),
                "row {i} unsatisfied: {:?}",
                cs.which_is_unsatisfied()
            );
        }
    }

    #[test]
    fn step_constraint_count_in_expected_range() {
        let seed = [8u8; CRYPTO_SEEDBYTES];
        let msg = b"constraint count";
        let (pk, sig) = sign_deterministic(&seed, msg).unwrap();
        let trace = verify_with_trace(&pk, msg, &sig).unwrap();
        let input = step_from_row(&trace.compressions[0]);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let before = cs.num_constraints();
        StepCircuit::synthesize(&mut cs, &input).unwrap();
        let step_constraints = cs.num_constraints() - before;
        // bellpepper SHA-256 compression is ~25k constraints (see bellpepper sha256 tests).
        assert!(step_constraints > 15_000, "got {step_constraints}");
        assert!(step_constraints < 35_000, "got {step_constraints}");
    }

    #[test]
    fn wrong_h_out_fails() {
        let seed = [9u8; CRYPTO_SEEDBYTES];
        let msg = b"bad h_out";
        let (pk, sig) = sign_deterministic(&seed, msg).unwrap();
        let trace = verify_with_trace(&pk, msg, &sig).unwrap();
        let mut input = step_from_row(&trace.compressions[0]);
        input.h_out[0] ^= 1;

        let mut cs = TestConstraintSystem::<Fr>::new();
        StepCircuit::synthesize(&mut cs, &input).unwrap();
        assert!(!cs.is_satisfied());
    }
}
