# blvm-protocol fuzz (cargo-fuzz)

Coverage-guided fuzzing with **libFuzzer**. Harness names are the **`[[bin]]`** entries in **`fuzz/Cargo.toml`** and the list in **`TARGETS.md`** — those files are authoritative.

Narrative overview (timeless): [Fuzzing (BLVM docs)](https://docs.thebitcoincommons.org/development/fuzzing.html).

## `production` / feature alignment

- **`blvm-consensus`** is depended on **without** `default-features = false`, so consensus **default features** apply — including **`production`** (`cfg(feature = "production")` paths in consensus compile).
- **`blvm-protocol`** is built with **`utxo-commitments`**, **`bip324`**, and **`production`** so **`cfg(feature = "production")`** code in this crate (for example spam-filter fast paths) matches typical release-style gates.

If you change **`fuzz/Cargo.toml`** to disable consensus defaults or drop **`production`** on the protocol crate, update every **`cargo fuzz run`** example below to document the smaller feature set.

## Quick start

### 1. Corpus (optional)

```bash
cd blvm-protocol/fuzz
./init_corpus.sh   # if present; otherwise start from empty corpus
```

### 2. Run a harness

```bash
cargo +nightly fuzz run protocol_p2p_decode

# With corpus directory
cargo +nightly fuzz run protocol_p2p_decode fuzz/corpus/protocol_p2p_decode

cargo +nightly fuzz list
```

Use **`TARGETS.md`** for the full harness name list.

### 3. Monorepo patches

Local checkouts often rely on **`[patch.crates-io]`** in **`fuzz/Cargo.toml`** (mirroring the repo root). CI strips patches for crates.io-only workflows — same pattern as **`blvm-consensus/fuzz`**.

## See also

- **`blvm-consensus/fuzz/README.md`** — consensus-side **`production`** discussion (dependency defaults).
- Workspace hardening plan **Track A** / **A3** — fuzz **`production`** parity expectations.
