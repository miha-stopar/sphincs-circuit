#ifndef SPX_FORS_ORACLE_H
#define SPX_FORS_ORACLE_H

#include <stdint.h>

/*
 * Ground-truth `fors_pk_from_sig` for circuit validation.
 *
 * Recovers the 16-byte FORS public key from a FORS signature and the message
 * hash, exactly as PQClean `fors.c:fors_pk_from_sig`.
 *
 *   pk         : 16-byte output (SPX_FORS_PK_BYTES)
 *   pub_seed   : 16 bytes (SPX_N)
 *   addr_bytes : 22 bytes; base address with layer/tree/keypair set
 *                (type is overwritten internally to FORSTREE / FORSPK)
 *   sig        : 2912-byte FORS signature (SPX_FORS_BYTES)
 *   mhash      : 21-byte message hash (SPX_FORS_MSG_BYTES)
 */
void spx_fors_pk_from_sig_oracle(uint8_t pk[16], const uint8_t pub_seed[16],
                                 const uint8_t addr_bytes[22], const uint8_t *sig,
                                 const uint8_t mhash[21]);

#endif /* SPX_FORS_ORACLE_H */
