//! PQClean trace → `FoldStepCircuit` batching (M3).

use circuit_spec::Sha256Compression;
use sphincs_circuit::witness::{local_chain_segments, step_input_from_row, LocalChain};

use crate::fold::FoldStepCircuit;

/// Build step circuits from compression rows (same order as trace).
pub fn fold_steps_from_rows(rows: &[Sha256Compression]) -> Vec<FoldStepCircuit> {
    rows.iter()
        .map(|row| FoldStepCircuit::new(step_input_from_row(row)))
        .collect()
}

/// `(h_out, h_in)` for each internal link `i .. i+1` inside a local chain segment.
pub fn chain_boundary_links(
    rows: &[Sha256Compression],
    chain: &LocalChain,
) -> Vec<([u8; 32], [u8; 32])> {
    assert!(chain.start < rows.len());
    assert!(chain.end < rows.len());
    assert!(chain.start < chain.end);

    (chain.start..chain.end)
        .map(|i| (rows[i].h_out, rows[i + 1].h_in))
        .collect()
}

/// Longest local chain in the trace (PQClean verify topology).
pub fn longest_local_chain(rows: &[Sha256Compression]) -> Option<LocalChain> {
    local_chain_segments(rows)
        .into_iter()
        .max_by_key(|c| c.len)
}

/// First `max_steps` compressions from the longest local chain, capped by chain length.
pub fn longest_chain_prefix(
    rows: &[Sha256Compression],
    max_steps: usize,
) -> Option<(LocalChain, Vec<FoldStepCircuit>, Vec<([u8; 32], [u8; 32])>)> {
    let chain = longest_local_chain(rows)?;
    let take = chain.len.min(max_steps);
    if take < 2 {
        return None;
    }
    let end = chain.start + take - 1;
    let sub = LocalChain {
        start: chain.start,
        end,
        len: take,
    };
    let step_rows = &rows[sub.start..=sub.end];
    let steps = fold_steps_from_rows(step_rows);
    let links = chain_boundary_links(rows, &sub);
    Some((sub, steps, links))
}
