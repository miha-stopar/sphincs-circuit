//! End-to-end NeutronNova fold of WOTS+ chain `thash`-F compressions.
//!
//! Proves the offload works through the real Spartan2 fold protocol: `N` folded
//! `thash`-F steps + one WOTS chain core, linked by the shared `addr/in/out` bus.

use sphincs_prover::{
    fold_and_prove_general, setup_with_proto, thash_f_chain_fold, thash_h_compute_root_fold,
    verify_proof,
};

/// Fold a full 8-step WOTS+ chain and check prove + verify both succeed.
#[test]
fn fold_thash_f_chain_prove_and_verify() {
    let pub_seed = [0x21u8; 16];
    let mut addr_base = [0u8; 22];
    addr_base[9] = 0; // SPX_ADDR_TYPE_WOTS
    addr_base[13] = 7; // keypair address
    addr_base[17] = 3; // chain address
    let chain_in = [0x42u8; 16];
    let start = 7u32;
    let steps = 8u32; // power-of-two batch; chain hash addresses j = 7..15

    let (step_circuits, core) =
        thash_f_chain_fold(&pub_seed, &addr_base, &chain_in, start, steps);
    assert_eq!(step_circuits.len(), steps as usize);

    let proto = &step_circuits[0];
    let (pk, vk) = setup_with_proto(proto, &core, step_circuits.len());
    // Wide field-element bus columns require the general commitment path.
    let proof = fold_and_prove_general(&pk, &step_circuits, &core);
    verify_proof(&vk, &proof, step_circuits.len());
}

/// Fold an 8-level Merkle `compute_root` (thash-H) and check prove + verify.
#[test]
fn fold_thash_h_compute_root_prove_and_verify() {
    let pub_seed = [0x57u8; 16];
    let mut addr_base = [0u8; 22];
    addr_base[9] = 2; // SPX_ADDR_TYPE_HASHTREE
    let leaf = [0x6bu8; 16];
    let tree_height = 8u32; // power-of-two batch → 8 thash-H steps
    let auth: Vec<u8> = (0..tree_height as usize * 16).map(|i| (i * 7 + 1) as u8).collect();
    let leaf_idx = 181u32;

    let (step_circuits, core) =
        thash_h_compute_root_fold(&pub_seed, &addr_base, &leaf, leaf_idx, 0, &auth, tree_height);
    assert_eq!(step_circuits.len(), tree_height as usize);

    let proto = &step_circuits[0];
    let (pk, vk) = setup_with_proto(proto, &core, step_circuits.len());
    let proof = fold_and_prove_general(&pk, &step_circuits, &core);
    verify_proof(&vk, &proof, step_circuits.len());
}
