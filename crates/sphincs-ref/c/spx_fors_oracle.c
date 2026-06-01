#include "spx_fors_oracle.h"

#include <string.h>

#include "context.h"
#include "fors.h"
#include "params.h"

void spx_fors_pk_from_sig_oracle(uint8_t pk[16], const uint8_t pub_seed[16],
                                 const uint8_t addr_bytes[22], const uint8_t *sig,
                                 const uint8_t mhash[21]) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pub_seed, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    initialize_hash_function(&ctx);

    uint32_t addr[8];
    memset(addr, 0, sizeof addr);
    memcpy(addr, addr_bytes, 22);

    fors_pk_from_sig(pk, sig, mhash, &ctx, addr);

    free_hash_function(&ctx);
}
