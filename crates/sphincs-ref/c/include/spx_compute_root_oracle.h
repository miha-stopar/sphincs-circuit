#ifndef SPX_COMPUTE_ROOT_ORACLE_H
#define SPX_COMPUTE_ROOT_ORACLE_H

#include <stdint.h>

/*
 * Ground-truth `compute_root` for circuit validation.
 *
 * Reconstructs a Merkle root from a leaf and an authentication path, exactly as
 * PQClean `utils.c:compute_root` does (used by both FORS and the hypertree).
 *
 *   out         : 16-byte (SPX_N) root output
 *   pub_seed    : 16 bytes (SPX_N), seeds ctx->state_seeded
 *   addr_bytes  : 22 bytes; the base address with type/layer/tree/keypair set
 *                 (tree_height and tree_index are overwritten per level)
 *   leaf        : 16 bytes (SPX_N)
 *   leaf_idx    : index of the leaf within its tree
 *   idx_offset  : index offset (continues counting across trees)
 *   auth_path   : tree_height * 16 bytes of sibling nodes
 *   tree_height : number of Merkle levels (e.g. 12 for FORS, 9 for hypertree)
 */
void spx_compute_root_oracle(uint8_t out[16], const uint8_t pub_seed[16],
                             const uint8_t addr_bytes[22], const uint8_t leaf[16],
                             uint32_t leaf_idx, uint32_t idx_offset,
                             const uint8_t *auth_path, uint32_t tree_height);

#endif /* SPX_COMPUTE_ROOT_ORACLE_H */
