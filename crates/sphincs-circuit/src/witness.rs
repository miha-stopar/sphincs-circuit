//! PQClean compression trace ↔ circuit witness alignment.
//!
//! Track A (`step.rs`) proves each trace row satisfies `C_step`.
//! Track B (`verify.rs` + sub-gadgets) proves SPHINCS+ dataflow.
//! This module validates both against the same `(pk, msg, sig)` inputs —
//! the prerequisite before M3 wires folded steps into the core proof.

use circuit_spec::{Sha256Compression, VerifyWitness, SPHINCS_SIG_BYTES};
use crate::step::StepInput;

/// One contiguous within-hash compression chain: indices `start..=end` where
/// `h_out[i] == h_in[i+1]` for all internal links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalChain {
    pub start: usize,
    pub end: usize,
    pub len: usize,
}

/// Summary of a compression trace after analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStats {
    pub total_compressions: usize,
    pub local_chain_count: usize,
    pub local_chain_links: usize,
    pub longest_local_chain: usize,
    pub global_chain: bool,
}

/// Convert one trace row to a `C_step` input.
pub fn step_input_from_row(row: &Sha256Compression) -> StepInput {
    StepInput {
        h_in: row.h_in,
        block: row.block,
        h_out: row.h_out,
    }
}

/// Build a [`VerifyWitness`] from compression rows and a signature.
pub fn witness_from_compressions(
    compressions: Vec<Sha256Compression>,
    signature: [u8; SPHINCS_SIG_BYTES],
) -> VerifyWitness {
    VerifyWitness {
        signature,
        sha256_compressions: compressions,
        sphincs_aux: Default::default(),
    }
}

fn global_chain(compressions: &[Sha256Compression]) -> bool {
    compressions
        .windows(2)
        .all(|w| w[0].h_out == w[1].h_in)
}

/// Analyze trace topology (local vs global chaining).
pub fn trace_stats(compressions: &[Sha256Compression]) -> TraceStats {
    let mut local_chain_count = 0usize;
    let mut local_chain_links = 0usize;
    let mut longest = 1usize;
    let mut current_len = 1usize;

    for w in compressions.windows(2) {
        if w[0].h_out == w[1].h_in {
            local_chain_links += 1;
            current_len += 1;
        } else {
            if current_len > 1 {
                local_chain_count += 1;
            }
            longest = longest.max(current_len);
            current_len = 1;
        }
    }
    if current_len > 1 {
        local_chain_count += 1;
    }
    longest = longest.max(current_len);

    TraceStats {
        total_compressions: compressions.len(),
        local_chain_count,
        local_chain_links,
        longest_local_chain: longest,
        global_chain: global_chain(compressions),
    }
}

/// Split compressions into maximal local chains (within one SHA-256 invocation).
pub fn local_chain_segments(compressions: &[Sha256Compression]) -> Vec<LocalChain> {
    if compressions.is_empty() {
        return Vec::new();
    }

    let mut segments = Vec::new();
    let mut start = 0usize;

    for (i, w) in compressions.windows(2).enumerate() {
        if w[0].h_out != w[1].h_in {
            if i + 1 > start {
                segments.push(LocalChain {
                    start,
                    end: i,
                    len: i - start + 1,
                });
            }
            start = i + 1;
        }
    }
    if start < compressions.len() {
        segments.push(LocalChain {
            start,
            end: compressions.len() - 1,
            len: compressions.len() - start,
        });
    }
    segments
}

/// Result of validating trace rows against `C_step`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepValidationResult {
    pub checked: usize,
    pub satisfied: usize,
    pub first_failure: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::StepCircuit;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES, SPHINCS_PK_BYTES};

    fn sample_compressions() -> (
        [u8; SPHINCS_PK_BYTES],
        [u8; SPHINCS_SIG_BYTES],
        Vec<Sha256Compression>,
    ) {
        let seed = [0x2au8; CRYPTO_SEEDBYTES];
        let msg = b"witness trace validation";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let rows: Vec<Sha256Compression> = trace
            .compressions
            .into_iter()
            .map(|r| Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();
        (pk, sig, rows)
    }

    fn validate_trace_steps(compressions: &[Sha256Compression], limit: usize) -> StepValidationResult {
        let limit = limit.min(compressions.len());
        let mut first_failure = None;
        let mut satisfied = 0usize;

        for (i, row) in compressions.iter().take(limit).enumerate() {
            let input = step_input_from_row(row);
            let mut cs = TestConstraintSystem::<Fr>::new();
            StepCircuit::synthesize(&mut cs, &input).expect("synth");
            if cs.is_satisfied() {
                satisfied += 1;
            } else if first_failure.is_none() {
                first_failure = Some(i);
            }
        }

        StepValidationResult {
            checked: limit,
            satisfied,
            first_failure,
        }
    }

    #[test]
    fn witness_from_compressions_populates_rows() {
        let (_pk, sig, rows) = sample_compressions();
        let w = witness_from_compressions(rows.clone(), sig);
        assert_eq!(w.sha256_compressions.len(), rows.len());
        assert_eq!(w.signature, sig);
        assert_eq!(w.sha256_compressions[0].h_in, rows[0].h_in);
    }

    #[test]
    fn trace_has_local_chains_not_global() {
        let (_pk, _sig, rows) = sample_compressions();
        let stats = trace_stats(&rows);
        assert!(stats.total_compressions > 1000);
        assert!(!stats.global_chain);
        assert!(stats.local_chain_links > 0);
        assert!(stats.longest_local_chain >= 2);
    }

    #[test]
    fn local_chain_segments_partition_trace() {
        let (_pk, _sig, rows) = sample_compressions();
        let segments = local_chain_segments(&rows);
        assert!(!segments.is_empty());
        let covered: usize = segments.iter().map(|s| s.len).sum();
        assert_eq!(covered, rows.len());
    }

    #[test]
    fn c_step_satisfied_for_trace_prefix() {
        let (_pk, _sig, rows) = sample_compressions();
        let result = validate_trace_steps(&rows, 30);
        assert_eq!(result.checked, 30);
        assert_eq!(result.satisfied, 30, "first failure at {:?}", result.first_failure);
        assert!(result.first_failure.is_none());
    }

    #[test]
    #[ignore = "validates full trace; run with --release --ignored (~minutes)"]
    fn c_step_satisfied_for_entire_trace() {
        let (_pk, _sig, rows) = sample_compressions();
        let result = validate_trace_steps(&rows, rows.len());
        assert_eq!(result.satisfied, rows.len());
        assert!(result.first_failure.is_none());
    }
}
