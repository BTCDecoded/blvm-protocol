# Type Usage Guidelines

Clarifies which types should be imported from which layer in the BLVM architecture.

## Architecture Layers

```
blvm-consensus (Tier 2 - Pure Math)
    ↓
blvm-protocol (Tier 3 - Protocol Abstraction)
    ↓
blvm-node (Tier 4 - Full Node Implementation)
```

## Type Import Rules

### For blvm-node Code

**✅ DO:**
- Import types from `blvm_protocol` (not `blvm_consensus` directly)
- Use protocol re-exports: `use blvm_protocol::{Block, Transaction, ...}`
- Access consensus functionality through protocol layer

**❌ DON'T:**
- Import types directly from `blvm_consensus` (except spec-lock helpers)
- Bypass protocol layer for consensus operations

**Exception:**
- Spec-lock proof helpers may use `blvm_consensus` types directly
- Fuzz targets may use consensus types directly

### For blvm-protocol Code

**✅ DO:**
- Import types from `blvm_consensus`
- Re-export commonly used types for convenience
- Add protocol-specific types and wrappers

**❌ DON'T:**
- Import types from `blvm-node` (creates circular dependency)

## Common Types

### Core Types (Re-exported by Protocol)

These types are re-exported by `blvm-protocol` and should be imported from there:

```rust
// ✅ Correct (in blvm-node)
use blvm_protocol::{Block, Transaction, BlockHeader, UtxoSet, ValidationResult};

// ❌ Incorrect (in blvm-node)
use blvm_consensus::{Block, Transaction, ...};
```

### Protocol-Specific Types

These types are defined in `blvm-protocol`:

```rust
use blvm_protocol::{
    BitcoinProtocolEngine,
    ProtocolVersion,
    ProtocolConfig,
    ProtocolValidationContext,
    NetworkMessage,
};
```

### Consensus Types (Only for Protocol Layer)

These should only be used in `blvm-protocol`:

```rust
// ✅ Correct (in blvm-protocol)
use blvm_consensus::{ConsensusProof, ConsensusError};

// ❌ Incorrect (in blvm-node)
use blvm_consensus::ConsensusProof;
```

## Examples

### ✅ Correct Usage in blvm-node

```rust
use blvm_protocol::{
    BitcoinProtocolEngine,
    Block,
    Transaction,
    ProtocolVersion,
    ValidationResult,
};

fn process_block(
    protocol: &BitcoinProtocolEngine,
    block: &Block,
) -> Result<ValidationResult> {
    // Use protocol layer for validation
    protocol.validate_block(block, &utxos, height)
}
```

### ❌ Incorrect Usage in blvm-node

```rust
// Don't import directly from consensus
use blvm_consensus::{Block, ConsensusProof};

// Don't bypass protocol layer
let result = consensus.validate_block(...);
```

### ✅ Exception: Spec-lock Verification

Spec-lock verification is run via `cargo spec-lock verify --crate-path .` in blvm-consensus.
It does not require direct consensus imports from blvm-node.

## Benefits

Following these guidelines ensures:

1. **Clear Layer Boundaries**: Each layer has well-defined responsibilities
2. **Protocol Validation**: Protocol-specific rules (size limits, feature flags) are always applied
3. **Maintainability**: Changes to consensus layer propagate correctly through protocol layer
4. **Testability**: Integration points are clear and testable

## Migration Guide

If you find code importing directly from `blvm_consensus`:

1. Check if the type is re-exported by `blvm_protocol`
2. Replace import: `use blvm_consensus::Type` → `use blvm_protocol::Type`
3. Verify functionality still works (types are the same, just different import path)
4. Exception: Spec-lock helpers and fuzz targets can keep direct imports

## Verification

To verify type usage is correct:

```bash
# Find direct consensus imports in blvm-node
grep -r "use blvm_consensus" blvm-node/src
```

Expected: blvm-node should import from blvm_protocol; direct consensus imports should be rare (e.g. fuzz targets).
