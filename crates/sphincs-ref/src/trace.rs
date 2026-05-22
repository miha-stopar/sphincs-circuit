//! FFI to the C SHA-256 compression trace buffer (see `c/spx_sha256_trace.c`).

use crate::{Sha256Compression, Sha256Trace};

#[repr(C)]
struct CompressionC {
    h_in: [u8; 32],
    block: [u8; 64],
    h_out: [u8; 32],
}

extern "C" {
    fn spx_sha256_trace_reset();
    fn spx_sha256_trace_count() -> usize;
    fn spx_sha256_trace_get(index: usize, out: *mut CompressionC) -> i32;
}

pub fn trace_reset() {
    unsafe { spx_sha256_trace_reset() }
}

pub fn trace_collect() -> Sha256Trace {
    let n = unsafe { spx_sha256_trace_count() };
    let mut compressions = Vec::with_capacity(n);
    for i in 0..n {
        let mut raw = CompressionC {
            h_in: [0u8; 32],
            block: [0u8; 64],
            h_out: [0u8; 32],
        };
        let rc = unsafe { spx_sha256_trace_get(i, &mut raw) };
        assert_eq!(rc, 0, "trace_get failed at index {i}");
        compressions.push(Sha256Compression {
            index: i,
            h_in: raw.h_in,
            block: raw.block,
            h_out: raw.h_out,
        });
    }
    Sha256Trace { compressions }
}
