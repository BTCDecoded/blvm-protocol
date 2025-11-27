# Type Usage Guidelines

Clarifies which types should be imported from which layer in the BLLVM architecture.

## Architecture Layers

```
bllvm-consensus (Tier 2 - Pure Math)
    ↓
bllvm-protocol (Tier 3 - Protocol Abstraction)
    ↓
bllvm-node (Tier 4 - Full Node Implementation)
```

## Type Import Rules

### For bllvm-node Code

**✅ DO:**
- Import types from `bllvm_protocol` (not `bllvm_consensus` directly)
- Use protocol re-exports: `use bllvm_protocol::{Block, Transaction, ...}`
- Access consensus functionality through protocol layer

**❌ DON'T:**
- Import types directly from `bllvm_consensus` (except Kani helpers)
- Bypass protocol layer for consensus operations

**Exception:**
- Kani proof helpers (`src/network/kani_helpers.rs`) may use `bllvm_consensus` types directly
- Fuzz targets may use consensus types directly

### For bllvm-protocol Code

**✅ DO:**
- Import types from `bllvm_consensus`
- Re-export commonly used types for convenience
- Add protocol-specific types and wrappers

**❌ DON'T:**
- Import types from `bllvm-node` (creates circular dependency)

## Common Types

### Core Types (Re-exported by Protocol)

These types are re-exported by `bllvm-protocol` and should be imported from there:

```rust
// ✅ Correct (in bllvm-node)
use bllvm_protocol::{Block, Transaction, BlockHeader, UtxoSet, ValidationResult};

// ❌ Incorrect (in bllvm-node)
use bllvm_consensus::{Block, Transaction, ...};
```

### Protocol-Specific Types

These types are defined in `bllvm-protocol`:

```rust
use bllvm_protocol::{
    BitcoinProtocolEngine,
    ProtocolVersion,
    ProtocolConfig,
    ProtocolValidationContext,
    NetworkMessage,
};
```

### Consensus Types (Only for Protocol Layer)

These should only be used in `bllvm-protocol`:

```rust
// ✅ Correct (in bllvm-protocol)
use bllvm_consensus::{ConsensusProof, ConsensusError};

// ❌ Incorrect (in bllvm-node)
use bllvm_consensus::ConsensusProof;
```

## Examples

### ✅ Correct Usage in bllvm-node

```rust
use bllvm_protocol::{
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

### ❌ Incorrect Usage in bllvm-node

```rust
// Don't import directly from consensus
use bllvm_consensus::{Block, ConsensusProof};

// Don't bypass protocol layer
let result = consensus.validate_block(...);
```

### ✅ Exception: Kani Helpers

```rust
// In bllvm-node/src/network/kani_helpers.rs
// This is acceptable - proof-time utilities
use bllvm_consensus::kani_helpers::assume_block_bounds;
```

## Benefits

Following these guidelines ensures:

1. **Clear Layer Boundaries**: Each layer has well-defined responsibilities
2. **Protocol Validation**: Protocol-specific rules (size limits, feature flags) are always applied
3. **Maintainability**: Changes to consensus layer propagate correctly through protocol layer
4. **Testability**: Integration points are clear and testable

## Migration Guide

If you find code importing directly from `bllvm_consensus`:

1. Check if the type is re-exported by `bllvm_protocol`
2. Replace import: `use bllvm_consensus::Type` → `use bllvm_protocol::Type`
3. Verify functionality still works (types are the same, just different import path)
4. Exception: Kani helpers and fuzz targets can keep direct imports

## Verification

To verify type usage is correct:

```bash
# Find direct consensus imports in bllvm-node (excluding Kani helpers)
grep -r "use bllvm_consensus" bllvm-node/src --exclude-dir=kani_helpers
```

Expected: Only Kani helpers should have direct consensus imports.

