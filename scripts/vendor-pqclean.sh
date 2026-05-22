#!/usr/bin/env bash
# Vendor PQClean SPHINCS+-SHA2-128s simple for native verify + KATs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/third_party/PQClean"
REPO="https://github.com/PQClean/PQClean.git"
SCHEME="crypto_sign/sphincs-sha2-128s-simple"

if [[ -d "$DEST/.git" ]]; then
  echo "PQClean already cloned at $DEST"
else
  git clone --depth 1 "$REPO" "$DEST"
fi

echo "Scheme path: $DEST/$SCHEME"
echo "Build with: cargo build -p sphincs-ref --features pqclean"
echo "(Wire build.rs to compile $SCHEME — not yet implemented)"
