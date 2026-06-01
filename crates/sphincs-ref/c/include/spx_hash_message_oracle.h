#ifndef SPX_HASH_MESSAGE_ORACLE_H
#define SPX_HASH_MESSAGE_ORACLE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Ground-truth `hash_message` for circuit validation.
 *
 * Derives the FORS message hash, hypertree index, and leaf index from
 * R || PK || M, exactly as PQClean `hash_sha2.c:hash_message`.
 *
 *   mhash    : 21-byte output (SPX_FORS_MSG_BYTES)
 *   tree     : 54-bit hypertree index (SPX_TREE_BITS)
 *   leaf_idx : 9-bit leaf index within current subtree (SPX_LEAF_BITS)
 *   R        : 16-byte randomness prefix from signature
 *   pk       : 32-byte public key (pub_seed || root)
 *   m, mlen  : message bytes (only first mlen are hashed)
 */
void spx_hash_message_oracle(uint8_t mhash[21], uint64_t *tree, uint32_t *leaf_idx,
                             const uint8_t R[16], const uint8_t pk[32],
                             const uint8_t *m, size_t mlen);

#endif /* SPX_HASH_MESSAGE_ORACLE_H */
