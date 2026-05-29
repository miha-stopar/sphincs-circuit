#ifndef SPX_WOTS_ORACLE_H
#define SPX_WOTS_ORACLE_H

#include <stdint.h>

/*
 * Ground-truth `wots_pk_from_sig` for circuit validation.
 *
 * Recovers a WOTS+ public key (SPX_WOTS_BYTES = 560 bytes for 128s) from a WOTS+
 * signature and the signed message, exactly as PQClean `wots.c:wots_pk_from_sig`.
 *
 *   pk        : 560-byte output (SPX_WOTS_LEN * SPX_N)
 *   pub_seed  : 16 bytes (SPX_N), seeds ctx->state_seeded
 *   addr_bytes: 22 bytes; base address with type=WOTS and layer/tree/keypair set
 *               (chain and hash addresses are overwritten internally)
 *   sig       : 560-byte WOTS+ signature (SPX_WOTS_LEN chains of SPX_N bytes)
 *   msg       : 16-byte (SPX_N) message the WOTS+ key signs
 */
void spx_wots_pk_from_sig_oracle(uint8_t pk[560], const uint8_t pub_seed[16],
                                 const uint8_t addr_bytes[22], const uint8_t *sig,
                                 const uint8_t msg[16]);

#endif /* SPX_WOTS_ORACLE_H */
