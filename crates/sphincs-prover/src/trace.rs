//! PQClean trace → `FoldStepCircuit` batching (M3).

use circuit_spec::{Sha256Compression, SPHINCS_PK_BYTES};
use sphincs_circuit::{
    locate_hash_message_trace_span_for_mlen,
    thash::SPX_N, witness::{local_chain_segments, step_input_from_row, LocalChain},
    HashMessageTraceSpan,
};

use crate::bound::{bound_steps_from_inputs, FoldCoreBoundCircuit, FoldStepBoundCircuit};
use crate::fold::FoldStepCircuit;
use crate::packed::FoldPackedChainCircuit;

/// Plain step circuits over the full `hash_message` span (seed + MGF1; not one local chain).
pub fn hash_message_chain_prefix(
    rows: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    mlen: usize,
) -> Option<(HashMessageTraceSpan, Vec<FoldStepCircuit>, Vec<([u8; 32], [u8; 32])>)> {
    let span = locate_hash_message_trace_span_for_mlen(rows, r, pk, mlen)?;
    let chain = span.full_chain();
    if chain.len < 2 {
        return None;
    }
    let steps = fold_steps_from_rows(&rows[chain.start..=chain.end]);
    let links = chain_boundary_links(rows, &chain);
    Some((span, steps, links))
}

/// Bound folded steps over the **seed-SHA** local chain (MGF1 is a separate hash).
///
/// Returns `None` when seed compressions are not a power of two — e.g. `mlen=15` → 2 steps.
pub fn hash_message_seed_chain_bound(
    rows: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    mlen: usize,
) -> Option<(
    HashMessageTraceSpan,
    Vec<FoldStepBoundCircuit>,
    Vec<([u8; 32], [u8; 32])>,
)> {
    let span = locate_hash_message_trace_span_for_mlen(rows, r, pk, mlen)?;
    let chain = span.seed.clone();
    let n = chain.len;
    if n < 2 || !n.is_power_of_two() {
        return None;
    }
    let inputs: Vec<_> = rows[chain.start..=chain.end]
        .iter()
        .map(step_input_from_row)
        .collect();
    let links = chain_boundary_links(rows, &chain);
    let digests = link_digests_from_boundary(&links);
    let bound = bound_steps_from_inputs(&inputs, n, digests);
    Some((span, bound, links))
}

/// First `n` compressions in trace order (global index, not necessarily a local chain).
pub fn fold_steps_prefix(rows: &[Sha256Compression], n: usize) -> Vec<FoldStepCircuit> {
    rows.iter().take(n).map(|row| FoldStepCircuit::new(step_input_from_row(row))).collect()
}

/// NeutronNova pads instance count to a power of two; duplicate the last step to pad.
pub fn pad_steps_to_power_of_two(mut steps: Vec<FoldStepCircuit>) -> Vec<FoldStepCircuit> {
    if steps.is_empty() {
        return steps;
    }
    while !steps.len().is_power_of_two() {
        steps.push(steps.last().expect("non-empty").clone());
    }
    steps
}

/// Build step circuits from compression rows (same order as trace).
pub fn fold_steps_from_rows(rows: &[Sha256Compression]) -> Vec<FoldStepCircuit> {
    rows.iter()
        .map(|row| FoldStepCircuit::new(step_input_from_row(row)))
        .collect()
}

/// Digest stored in shared witness slot `k` (the `h_out` side of boundary `k .. k+1`).
pub fn link_digests_from_boundary(links: &[([u8; 32], [u8; 32])]) -> Vec<[u8; 32]> {
    links.iter().map(|(left, _)| *left).collect()
}

/// Longest local chain prefix as shared-bound step circuits + core.
///
/// `max_steps` must be a power of two (NeutronNova batch size). Use
/// [`pad_steps_to_power_of_two`] on plain [`FoldStepCircuit`] batches when padding is required;
/// padding bound steps needs an extra satisfiable link per duplicated row.
pub fn longest_chain_bound(
    rows: &[Sha256Compression],
    max_steps: usize,
) -> Option<(
    LocalChain,
    Vec<FoldStepBoundCircuit>,
    FoldCoreBoundCircuit,
    Vec<([u8; 32], [u8; 32])>,
)> {
    if !max_steps.is_power_of_two() {
        return None;
    }
    let (chain, steps, links) = longest_chain_prefix(rows, max_steps)?;
    let digests = link_digests_from_boundary(&links);
    let bound = bound_steps_from_inputs(
        &steps.iter().map(|s| *s.input()).collect::<Vec<_>>(),
        steps.len(),
        digests.clone(),
    );
    let core = FoldCoreBoundCircuit::new(digests);
    Some((chain, bound, core, links))
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

/// Longest local chain prefix as one [`FoldPackedChainCircuit`] (exactly `N` rows).
pub fn longest_chain_packed<const N: usize>(
    rows: &[Sha256Compression],
) -> Option<(LocalChain, FoldPackedChainCircuit<N>)> {
    let chain = longest_local_chain(rows)?;
    if chain.len < N {
        return None;
    }
    let end = chain.start + N - 1;
    let sub = LocalChain {
        start: chain.start,
        end,
        len: N,
    };
    let step_rows: Vec<_> = rows[sub.start..=sub.end]
        .iter()
        .map(step_input_from_row)
        .collect();
    let packed = FoldPackedChainCircuit::from_slice(&step_rows)?;
    Some((sub, packed))
}

/// One [`FoldPackedChainCircuit`] per local chain segment with `len >= N`.
pub fn packed_chains_from_trace<const N: usize>(
    rows: &[Sha256Compression],
) -> Vec<(LocalChain, FoldPackedChainCircuit<N>)> {
    local_chain_segments(rows)
        .into_iter()
        .filter(|c| c.len >= N)
        .filter_map(|chain| {
            let inputs: Vec<_> = rows[chain.start..=chain.end]
                .iter()
                .map(step_input_from_row)
                .collect();
            let packed = FoldPackedChainCircuit::from_slice(&inputs)?;
            Some((chain, packed))
        })
        .collect()
}
