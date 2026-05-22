/**
 * Deterministic randombytes for `sphincs-ref` tests and witness generation.
 * NOT cryptographically secure — do not use for production signing.
 */
#include "randombytes.h"

#include <stdint.h>
#include <string.h>

static uint64_t spx_rng_state = 0x243f6a8885a308d3ULL;

int randombytes(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        spx_rng_state ^= spx_rng_state >> 12;
        spx_rng_state ^= spx_rng_state << 25;
        spx_rng_state ^= spx_rng_state >> 27;
        out[i] = (uint8_t)(spx_rng_state >> 56);
    }
    return 0;
}

void randombytes_seed(uint64_t seed) {
    spx_rng_state = seed ? seed : 1;
}
