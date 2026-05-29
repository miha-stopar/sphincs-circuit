#include "spx_wots_oracle.h"

#include <string.h>

#include "context.h"
#include "params.h"
#include "wots.h"

void spx_wots_pk_from_sig_oracle(uint8_t pk[560], const uint8_t pub_seed[16],
                                 const uint8_t addr_bytes[22], const uint8_t *sig,
                                 const uint8_t msg[16]) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pub_seed, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    initialize_hash_function(&ctx);

    /* wots_pk_from_sig only overwrites chain/hash addresses (offsets 17, 21),
       so the first 22 bytes of addr carry the caller-set type/layer/tree/kp. */
    uint32_t addr[8];
    memset(addr, 0, sizeof addr);
    memcpy(addr, addr_bytes, 22);

    wots_pk_from_sig(pk, sig, msg, &ctx, addr);

    free_hash_function(&ctx);
}
