//! NeutronNova fold + prove on the first compressions from a real PQClean trace.

#![cfg(feature = "pqclean")]

use bellpepper_core::test_cs::TestConstraintSystem;
use spartan2::{
    provider::T256HyraxEngine,
    traits::Engine,
};
use sphincs_circuit::{sha256_compress, step::StepInput};
use sphincs_prover::{fold_and_prove, verify_proof, FoldCoreCircuit, FoldStepCircuit};
use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

const NUM_STEPS: usize = 4;

type Scalar = <T256HyraxEngine as Engine>::Scalar;

#[test]
fn trace_row_satisfies_allocated_block_compression_on_t256() {
    let seed = [0x33u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover fold smoke test";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");

    for (i, row) in trace.compressions.iter().take(NUM_STEPS).enumerate() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        sha256_compress::synthesize_compression_allocated_block(
            &mut cs,
            &row.h_in,
            &row.block,
            &row.h_out,
        )
        .expect("synth");
        assert!(
            cs.is_satisfied(),
            "row {i} unsatisfied on T256: {:?}",
            cs.which_is_unsatisfied()
        );
    }
}

#[test]
fn fold_trace_prefix_proves_and_verifies() {
    let seed = [0x33u8; CRYPTO_SEEDBYTES];
    let msg = b"sphincs-prover fold smoke test";
    let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
    let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
    assert!(trace.len() > NUM_STEPS);

    let steps: Vec<FoldStepCircuit> = trace
        .compressions
        .iter()
        .take(NUM_STEPS)
        .map(|row| {
            FoldStepCircuit::new(StepInput {
                h_in: row.h_in,
                block: row.block,
                h_out: row.h_out,
            })
        })
        .collect();

    let (pk_fold, vk) =
        sphincs_prover::setup_with_default_core(&steps[0], NUM_STEPS);
    let core = FoldCoreCircuit::new();
    let proof = fold_and_prove(&pk_fold, &steps, &core);
    verify_proof(&vk, &proof, NUM_STEPS);

    let bytes = bincode::serialize(&proof).expect("serialize proof");
    assert!(bytes.len() > 100, "proof should be non-trivial");
}
