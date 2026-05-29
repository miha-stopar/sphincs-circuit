#include "spx_thash_oracle.h"

#include <string.h>

#include "context.h"
#include "params.h"
#include "thash.h"

void spx_thash_oracle(uint8_t out[16], const uint8_t pub_seed[16],
                      const uint8_t addr_bytes[22], const uint8_t *in,
                      unsigned int inblocks) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pub_seed, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);

    /* Absorb pub_seed into ctx->state_seeded (one 64-byte block: pub_seed||0). */
    initialize_hash_function(&ctx);

    /* thash copies SPX_SHA256_ADDR_BYTES (22) bytes from addr; the rest is unused. */
    uint32_t addr[8];
    memset(addr, 0, sizeof addr);
    memcpy(addr, addr_bytes, 22);

    thash(out, in, inblocks, &ctx, addr);

    free_hash_function(&ctx);
}
