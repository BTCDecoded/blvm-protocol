#!/bin/bash
# Seed corpus directory layout for cargo-fuzz (optional seeds can be added per target).
set -e
FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="${1:-$FUZZ_DIR/corpus}"
mkdir -p "$CORPUS_DIR"
TARGETS_FILE="${FUZZ_DIR}/TARGETS.md"
while IFS= read -r line || [ -n "$line" ]; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  mkdir -p "$CORPUS_DIR/$line"
done < "$TARGETS_FILE"
echo "Corpus dirs under $CORPUS_DIR ($(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l) targets)"
