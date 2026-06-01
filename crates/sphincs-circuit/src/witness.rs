//! PQClean compression trace ↔ circuit witness alignment.
//!
//! Track A (`step.rs`) proves each trace row satisfies `C_step`.
//! Track B (`verify.rs` + sub-gadgets) proves SPHINCS+ dataflow.
//! This module validates both against the same `(pk, msg, sig)` inputs —
//! the prerequisite before M3 wires folded steps into the core proof.

use crate::step::{StepCircuit, StepInput};
use bellpepper_core::test_cs::TestConstraintSystem;
use blstrs::Scalar as Fr;
use circuit_spec::{Sha256Compression as SpecCompression, VerifyWitness, SPHINCS_SIG_BYTES};
use sphincs_ref::{Sha256Compression, Sha256Trace, SPHINCS_PK_BYTES};

fn to_spec_row(row: &Sha256Compression) -> SpecCompression {
    SpecCompression {
        index: row.index,
        h_in: row.h_in,
        block: row.block,
        h_out: row.h_out,
    }
}

/// One contiguous within-hash compression chain: indices `start..=end` where
/// `h_out[i] == h_in[i+1]` for all internal links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalChain {
    pub start: usize,
    pub end: usize,
    pub len: usize,
}

/// Summary of a PQClean trace after analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStats {
    pub total_compressions: usize,
    pub local_chain_count: usize,
    pub local_chain_links: usize,
    pub longest_local_chain: usize,
    pub global_chain: bool,
}

/// Convert one PQClean trace row to a `C_step` input.
pub fn step_input_from_row(row: &Sha256Compression) -> StepInput {
    StepInput {
        h_in: row.h_in,
        block: row.block,
        h_out: row.h_out,
    }
}

/// Build a [`VerifyWitness`] skeleton from a PQClean trace and signature.
///
/// `sphincs_aux` is left default — populate from `hash_message` outputs when
/// the core needs explicit indices outside the trace.
pub fn witness_from_trace(trace: &Sha256Trace, signature: [u8; SPHINCS_SIG_BYTES]) -> VerifyWitness {
    VerifyWitness {
        signature,
        sha256_compressions: trace.compressions.iter().map(to_spec_row).collect(),
        sphincs_aux: Default::default(),
    }
}

/// Analyze trace topology (local vs global chaining).
pub fn trace_stats(trace: &Sha256Trace) -> TraceStats {
    let mut local_chain_count = 0usize;
    let mut local_chain_links = 0usize;
    let mut longest = 1usize;
    let mut current_len = 1usize;

    for w in trace.compressions.windows(2) {
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
        total_compressions: trace.len(),
        local_chain_count,
        local_chain_links,
        longest_local_chain: longest,
        global_chain: trace.check_step_chains(),
    }
}

/// Split the trace into maximal local chains (within one SHA-256 invocation).
pub fn local_chain_segments(trace: &Sha256Trace) -> Vec<LocalChain> {
    if trace.compressions.is_empty() {
        return Vec::new();
    }

    let mut segments = Vec::new();
    let mut start = 0usize;

    for (i, w) in trace.compressions.windows(2).enumerate() {
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
    if start < trace.compressions.len() {
        segments.push(LocalChain {
            start,
            end: trace.compressions.len() - 1,
            len: trace.compressions.len() - start,
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

/// Check that trace rows `[0..limit)` each satisfy `C_step`.
pub fn validate_trace_steps(trace: &Sha256Trace, limit: usize) -> StepValidationResult {
    let limit = limit.min(trace.compressions.len());
    let mut first_failure = None;
    let mut satisfied = 0usize;

    for (i, row) in trace.compressions.iter().take(limit).enumerate() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

    fn sample_trace() -> ( [u8; SPHINCS_PK_BYTES], [u8; SPHINCS_SIG_BYTES], Sha256Trace) {
        let seed = [0x2au8; CRYPTO_SEEDBYTES];
        let msg = b"witness trace validation";
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        (pk, sig, trace)
    }

    #[test]
    fn witness_from_trace_populates_compressions() {
        let (_pk, sig, trace) = sample_trace();
        let w = witness_from_trace(&trace, sig);
        assert_eq!(w.sha256_compressions.len(), trace.len());
        assert_eq!(w.signature, sig);
        assert_eq!(w.sha256_compressions[0].h_in, trace.compressions[0].h_in);
    }

    #[test]
    fn trace_has_local_chains_not_global() {
        let (_pk, _sig, trace) = sample_trace();
        let stats = trace_stats(&trace);
        assert!(stats.total_compressions > 1000);
        assert!(!stats.global_chain);
        assert!(stats.local_chain_links > 0);
        assert!(stats.longest_local_chain >= 2);
    }

    #[test]
    fn local_chain_segments_partition_trace() {
        let (_pk, _sig, trace) = sample_trace();
        let segments = local_chain_segments(&trace);
        assert!(!segments.is_empty());
        let covered: usize = segments.iter().map(|s| s.len).sum();
        assert_eq!(covered, trace.len());
    }

    #[test]
    fn c_step_satisfied_for_trace_prefix() {
        let (_pk, _sig, trace) = sample_trace();
        let result = validate_trace_steps(&trace, 30);
        assert_eq!(result.checked, 30);
        assert_eq!(result.satisfied, 30, "first failure at {:?}", result.first_failure);
        assert!(result.first_failure.is_none());
    }

    /// Validates every compression row (~2200+) against `C_step`.
    #[test]
    #[ignore = "validates full trace; run with --release --ignored (~minutes)"]
    fn c_step_satisfied_for_entire_trace() {
        let (_pk, _sig, trace) = sample_trace();
        let result = validate_trace_steps(&trace, trace.len());
        assert_eq!(result.satisfied, trace.len());
        assert!(result.first_failure.is_none());
    }
}
