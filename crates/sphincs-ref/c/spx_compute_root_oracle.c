#include "spx_compute_root_oracle.h"

#include <string.h>

#include "context.h"
#include "params.h"
#include "utils.h"

void spx_compute_root_oracle(uint8_t out[16], const uint8_t pub_seed[16],
                             const uint8_t addr_bytes[22], const uint8_t leaf[16],
                             uint32_t leaf_idx, uint32_t idx_offset,
                             const uint8_t *auth_path, uint32_t tree_height) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pub_seed, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    initialize_hash_function(&ctx);

    /* compute_root overwrites only tree_height/tree_index (offsets 17..21),
       so the first 22 bytes of addr carry the caller-set type/layer/tree. */
    uint32_t addr[8];
    memset(addr, 0, sizeof addr);
    memcpy(addr, addr_bytes, 22);

    compute_root(out, leaf, leaf_idx, idx_offset, auth_path, tree_height, &ctx, addr);

    free_hash_function(&ctx);
}
