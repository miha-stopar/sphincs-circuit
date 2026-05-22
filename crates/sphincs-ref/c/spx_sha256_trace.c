#include "spx_sha256_trace.h"

#include <string.h>

#ifndef SPX_SHA256_TRACE_MAX
#define SPX_SHA256_TRACE_MAX 16384
#endif

static spx_sha256_compression_t trace_buf[SPX_SHA256_TRACE_MAX];
static size_t trace_len;

void spx_sha256_trace_reset(void) {
    trace_len = 0;
}

void spx_sha256_trace_record(const uint8_t h_in[32], const uint8_t block[64],
                             const uint8_t h_out[32]) {
    if (trace_len >= SPX_SHA256_TRACE_MAX) {
        return;
    }
    memcpy(trace_buf[trace_len].h_in, h_in, 32);
    memcpy(trace_buf[trace_len].block, block, 64);
    memcpy(trace_buf[trace_len].h_out, h_out, 32);
    trace_len++;
}

size_t spx_sha256_trace_count(void) {
    return trace_len;
}

int spx_sha256_trace_get(size_t index, spx_sha256_compression_t *out) {
    if (index >= trace_len || out == NULL) {
        return -1;
    }
    *out = trace_buf[index];
    return 0;
}
