# SPHINCS+ structure and verification flow

Parameter set for this repo: **SHA2-128s simple** (PQClean `sphincs-sha2-128s-simple`).

Constants: `N=16` byte hash output, `d=7` hypertree layers, tree height `h=9` per layer, `k=14` FORS trees, FORS height `a=12`, WOTS+ length `35` chains.

---

## 1. Key idea

SPHINCS+ is a **stateless hash-based** signature:

- No secret state updates (unlike XMSS).
- Security from hash function one-wayness + tree structure.
- Large signatures, fast verify dominated by **many SHA-256 calls**.

```mermaid
flowchart TB
  subgraph keys["Keys"]
    PK["PK = pub_seed ‖ root"]
    SK["SK = sk_seed ‖ sk_prf ‖ pub_seed ‖ root"]
  end

  subgraph sign["Sign (not in our circuit)"]
    M_in["Message M"]
    SIG["σ = R ‖ FORS_sig ‖ 7×(WOTS_sig ‖ auth_path)"]
    M_in --> SIG
  end

  subgraph verify["Verify (our circuit)"]
    V_IN["PK, M, σ"]
    V_OK["root' == PK.root"]
    V_IN --> V_OK
  end

  PK --> verify
  SIG --> verify
```

---

## 2. Signature layout (128s)

```text
σ (7856 bytes)
├── R                    16 B   randomness (prefix of sig)
├── FORS signature       (12+1)×14×16 = 2184 B  (approx: k×(a+1)×n)
└── Hypertree × d=7
    each layer:
    ├── WOTS+ signature  35×16 = 560 B
    └── auth path        h×16 = 9×16 = 144 B
```

Exact layout: `SPX_BYTES` in `params.h` / `sign.c`.

---

## 3. Hypertree (XMSS stack)

A **hypertree** stacks `d` layers of Merkle trees. Each leaf is a WOTS+ public key; each WOTS+ key signs the root of the layer below.

```mermaid
flowchart TB
  ROOT["PK.root (top)"]

  subgraph L6["Layer 6"]
    T6["XMSS tree height 9"]
  end

  subgraph L1["Layer 1"]
    T1["XMSS tree height 9"]
  end

  subgraph L0["Layer 0"]
    F["FORS PK → signed by WOTS here"]
  end

  ROOT --> T6
  T6 --> T1
  T1 --> F
```

**Indices** `(tree, leaf_idx)` are derived from `hash_message(R, PK, M)` — 54 bits of tree position + 9 bits of leaf per layer (for 128s).

---

## 4. FORS (few-time signature, bottom layer)

**FORS** = Forest of Random Subsets: `k=14` trees of height `a=12`. Message digest selects one leaf per tree; signature reveals secret values + siblings to reconstruct per-tree roots, then hashes roots together.

```mermaid
flowchart LR
  MH["mhash (21 B)"]
  IDX["indices per tree"]
  MH --> IDX

  subgraph tree_i["Tree i"]
    LEAF["leaf = thash(sk)"]
    PATH["12 sibling nodes from σ"]
    LEAF --> R_i["subtree root"]
    PATH --> R_i
  end

  IDX --> tree_i
  R1["root_1"] --> TH["thash(root_1‖…‖root_14)"]
  Rk["root_14"] --> TH
  TH --> FORS_PK["FORS public key"]
```

Verify (`fors_pk_from_sig`): for each tree, recover leaf from sig, `compute_root` up height 12, aggregate with `thash(14 blocks)`.

---

## 5. WOTS+ (one Merkle leaf)

Winternitz OTS with `w=16`: message split into `35` base-16 digits. Each chain applies `thash` up to 15 times from signature chunk to public chain end.

```mermaid
flowchart TB
  MSG["16-byte root from layer below"]
  BASE["base_w → lengths[0..34]"]

  subgraph chain_j["Chain j"]
    S0["sig chunk"]
    T["thash × (15 - lengths[j])"]
    S0 --> T --> PUBJ["pub_j"]
  end

  MSG --> BASE
  BASE --> chain_j
  PUB0["pub_0…pub_34"] --> TH2["thash(35 blocks) → leaf"]
```

---

## 6. Merkle authentication (`compute_root`)

Given leaf and auth path siblings, walk up height `h=9`, each step `thash(left‖right)` with address-dependent ordering.

```mermaid
flowchart BT
  LEAF["leaf"]
  S0["sibling_0"]
  LEAF --> N1["thash → node"]
  S0 --> N1
  N1 --> N2["…"]
  N2 --> ROOTL["subtree root"]
```

Used in FORS (height 12) and each hypertree layer (height 9).

---

## 7. `thash` — the universal hash inside SPHINCS+

Almost every hash is `thash`:

```c
// thash_sha2_simple.c
clone(state_seeded);           // state already absorbed pub_seed
finalize(buf = addr[22] ‖ in[inblocks×16]);
truncate to 16 bytes out
```

`state_seeded` = one SHA-256 compression of padded `pub_seed` at init.

```mermaid
sequenceDiagram
  participant Init as initialize_hash_function
  participant Ctx as state_seeded
  participant T as thash

  Init->>Ctx: absorb 64B block (pub_seed)
  Note over T: each thash call
  T->>Ctx: clone
  T->>T: finalize(addr ‖ data)
  T->>T: output 16 B
```

Our **step circuit** implements only the compressions inside `finalize` (and init), not the high-level `thash` API — core wires them.

---

## 8. Full verify algorithm (PQClean)

Matches `crypto_sign_verify` in `sign.c`:

```mermaid
flowchart TB
  START(["Input: PK, M, σ"])
  INIT["seed_state(pub_seed)"]
  HM["hash_message(R, PK, M)<br/>→ mhash, tree, idx_leaf"]
  FORS["fors_pk_from_sig → root₀"]
  LOOP{"layer i = 0..6"}
  WOTS["wots_pk_from_sig → wots_pk"]
  LEAF["thash(wots_pk) → leaf"]
  MERKLE["compute_root → rootᵢ₊₁"]
  CHECK{"root₇ == PK.root?"}
  OK(["accept"])
  FAIL(["reject"])

  START --> INIT --> HM --> FORS --> LOOP
  LOOP --> WOTS --> LEAF --> MERKLE --> LOOP
  LOOP -->|i=7 done| CHECK
  CHECK -->|yes| OK
  CHECK -->|no| FAIL
```

### 8.1 `hash_message` detail

```mermaid
flowchart LR
  R["R from σ"]
  PK["PK"]
  M["M variable length"]
  R --> H1["SHA-256 incremental<br/>R ‖ PK ‖ M"]
  PK --> H1
  M --> H1
  H1 --> SEED["seed 48 B"]
  SEED --> MGF["mgf1 → 30 B digest"]
  MGF --> SPLIT["mhash ‖ tree ‖ leaf_idx"]
```

This is the **only** step whose compression count grows with `|M|`.

---

## 9. Mapping to ZK circuits

| Native | Circuit |
|--------|---------|
| `initialize_hash_function` | First compression(s) in trace |
| `hash_message` | Core control + compressed steps |
| `thash` | Sequence of compressions + core `H` links |
| `compute_root` | `h-1` × `thash(2)` + final `thash(2)` per call |
| `memcmp(root, pk.root)` | 128-bit (or byte) equality constraints |

See [FOLDING.md](FOLDING.md) for folding across all compressions.
