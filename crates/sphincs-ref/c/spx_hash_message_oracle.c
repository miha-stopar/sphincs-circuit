#include "spx_hash_message_oracle.h"

#include <string.h>

#include "context.h"
#include "hash.h"
#include "params.h"

void spx_hash_message_oracle(uint8_t mhash[21], uint64_t *tree, uint32_t *leaf_idx,
                             const uint8_t R[16], const uint8_t pk[32],
                             const uint8_t *m, size_t mlen) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pk, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    initialize_hash_function(&ctx);

    hash_message(mhash, tree, leaf_idx, R, pk, m, mlen, &ctx);

    free_hash_function(&ctx);
}
