#ifndef SPX_THASH_ORACLE_H
#define SPX_THASH_ORACLE_H

#include <stdint.h>

/*
 * Ground-truth `thash` for circuit validation.
 *
 * Builds a SPHINCS+-SHA2-128s context from `pub_seed` (SPX_N = 16 bytes),
 * runs the scheme's `thash` over `inblocks` blocks of `SPX_N` bytes with the
 * given 22-byte SHA-256 address prefix, and writes the 16-byte (SPX_N) output.
 *
 *   out       : 16-byte output buffer
 *   pub_seed  : 16 bytes (SPX_N), seeds ctx->state_seeded
 *   addr_bytes: 22 bytes (SPX_SHA256_ADDR_BYTES), copied verbatim into addr
 *   in        : inblocks * 16 bytes
 *   inblocks  : number of SPX_N-sized input blocks (>= 1)
 */
void spx_thash_oracle(uint8_t out[16], const uint8_t pub_seed[16],
                      const uint8_t addr_bytes[22], const uint8_t *in,
                      unsigned int inblocks);

#endif /* SPX_THASH_ORACLE_H */
