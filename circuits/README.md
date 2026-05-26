# R1CS circuits

Implemented in **`crates/sphincs-circuit`** (bellpepper).

Gadget implementation order:

1. `sha256_compress` — single compression function (**M1 done**)
2. `sha256_padded` — multi-block + length-hiding digest lookup
3. `sphincs/` — FORS, WOTS+, hypertree per `docs/CIRCUIT.md`
4. `prepare_sphincs` — Prepare relation composing issuer verify + field hashes

Target toolchain: **Circom** → R1CS → **Spartan2** / bellpepper (OpenAC path).

Uniform SHA steps should use **NeutronNova folding** (VegaMC) when integrated with the prover backend.
