//! Narrated walkthrough: `cargo run -p folding-demo --bin walkthrough`.
//!
//! Prints, step by step, how N uniform "step" instances are folded into ONE
//! accumulator and how the separate "core" circuit enforces everything folding
//! cannot (chain linking, public root, non-hash checksum).

use folding_demo::r1cs::{fold, RelaxedInstance};
use folding_demo::step::{step_shape, OUT};
use folding_demo::{verify, verify_chain, Chain, Scalar};
use ff::Field;

fn line() {
    println!("{}", "-".repeat(68));
}

fn main() {
    let n = 6;
    let blocks: Vec<Scalar> = (0..n).map(|i| Scalar::from(i as u64 + 1)).collect();
    let chain = Chain::new(Scalar::from(3u64), blocks);

    println!("FOLDING + CORE WALKTHROUGH");
    println!("step relation (stand-in for SHA-256 compression):  out = in^2 + block");
    println!("chain of N = {n} steps,  in_0 = start = 3,  in_(i+1) = out_i");
    line();

    // 1. Show the chain.
    println!("1) The honest chain (each row is one folded step):");
    for i in 0..n {
        println!(
            "   step {i}:  in={:<4} block={:<2}  ->  out={}",
            short(&chain.ins[i]),
            short(&chain.blocks[i]),
            short(&chain.outs[i]),
        );
    }
    println!("   public root   = out_(N-1) = {}", short(&chain.root()));
    println!("   public checksum = Σ out_i = {}", short(&chain.checksum()));
    line();

    // 2. Each step is its own R1CS satisfaction.
    let shape = step_shape();
    let witnesses = chain.step_witnesses();
    println!("2) Each step is a satisfying assignment of the SAME R1CS shape");
    println!(
        "   shape: {} constraints, {} witness vars; all satisfied individually: {}",
        shape.num_constraints,
        shape.num_vars,
        witnesses.iter().all(|w| shape.is_satisfied(w)),
    );
    line();

    // 3. Fold them one by one, showing u grow.
    println!("3) Fold the {n} step instances into ONE relaxed accumulator");
    let mut acc: RelaxedInstance = shape.relax(witnesses[0].clone());
    println!("   acc = step 0           u = {}", short(&acc.u));
    for (i, w) in witnesses.iter().enumerate().skip(1) {
        let r = Scalar::from((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(7));
        acc = fold(&shape, &acc, &shape.relax(w.clone()), r);
        println!(
            "   fold(step {i})           u = {}   (E now nonzero, satisfied: {})",
            short(&acc.u),
            acc.is_satisfied(&shape),
        );
    }
    println!(
        "   => ONE accumulator now stands in for all {n} step satisfactions: {}",
        acc.is_satisfied(&shape)
    );
    line();

    // 4. Core circuit catches what folding cannot.
    println!("4) The CORE circuit (proven once, NOT folded) wires endpoints:");
    println!("   - in_0 == start, out_(N-1) == root");
    println!("   - out_i == in_(i+1)  (chain linking)");
    println!("   - Σ out_i == checksum  (non-hash predicate)");
    let honest = verify_chain(&chain);
    println!(
        "   honest run:  folded_ok={}  core_ok={}  link_ok={}  ACCEPT={}",
        honest.folded_ok,
        honest.core_ok,
        honest.link_ok,
        honest.accept()
    );
    line();

    // 5. The crucial contrast: a broken chain that folding cannot see.
    println!("5) Break the chain WITHOUT breaking any single step");
    println!("   (each step still computes out=in^2+block, but in_3 != out_2)");
    let mut ins = vec![chain.start];
    let mut outs = Vec::new();
    for i in 0..n {
        let out = folding_demo::step::step_native(ins[i], chain.blocks[i]);
        outs.push(out);
        if i + 1 < n {
            ins.push(if i == 2 { Scalar::from(999u64) } else { out });
        }
    }
    let witnesses_broken: Vec<Vec<Scalar>> = (0..n)
        .map(|i| folding_demo::step::step_witness(ins[i], chain.blocks[i]))
        .collect();
    // sanity: every step still individually valid
    let each_ok = witnesses_broken.iter().all(|w| shape.is_satisfied(w));
    let root = *outs.last().unwrap();
    let checksum = outs.iter().fold(Scalar::ZERO, |a, x| a + *x);
    let broken = verify(&witnesses_broken, &ins, &outs, ins[0], root, checksum);
    println!("   every step individually valid: {each_ok}");
    println!(
        "   broken run:  folded_ok={}  core_ok={}  link_ok={}  ACCEPT={}",
        broken.folded_ok, broken.core_ok, broken.link_ok, broken.accept()
    );
    println!();
    println!("   >>> folding accepted the bad chain; the CORE rejected it.");
    println!("   >>> THIS is why you cannot drop the linking constraints:");
    println!("       folding proves each compression, the core proves the chain.");
    let _ = OUT;
    line();
    println!("done.");
}

/// Print only the low 64 bits of a field element for readability.
fn short(s: &Scalar) -> String {
    let bytes = s.to_bytes_le();
    let mut v = 0u128;
    for (i, b) in bytes.iter().take(8).enumerate() {
        v |= (*b as u128) << (8 * i);
    }
    v.to_string()
}
