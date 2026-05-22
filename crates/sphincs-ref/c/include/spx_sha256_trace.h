#ifndef SPX_SHA256_TRACE_H
#define SPX_SHA256_TRACE_H

#include <stddef.h>
#include <stdint.h>

/** One SHA-256 compression: H_out = Compress(H_in, block). */
typedef struct {
    uint8_t h_in[32];
    uint8_t block[64];
    uint8_t h_out[32];
} spx_sha256_compression_t;

/** Clear the trace buffer (call before each instrumented verify). */
void spx_sha256_trace_reset(void);

/** Record one compression (only when tracing is enabled at compile time). */
void spx_sha256_trace_record(const uint8_t h_in[32], const uint8_t block[64],
                             const uint8_t h_out[32]);

/** Number of compressions recorded since last reset. */
size_t spx_sha256_trace_count(void);

/** Copy compression `index` into `out`. Returns 0 on success, -1 if out of range. */
int spx_sha256_trace_get(size_t index, spx_sha256_compression_t *out);

#endif
