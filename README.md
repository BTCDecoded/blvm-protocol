# Bitcoin Protocol Engine

**Bitcoin protocol abstraction layer for multiple variants and evolution.**

This crate provides a Bitcoin protocol abstraction layer that enables:
- Multiple Bitcoin variants (mainnet, testnet, regtest)
- Protocol evolution support (Bitcoin V1, V2, etc.)
- Economic model abstraction (PoW, future variants)
- Research-friendly interfaces

## Architecture Position

This is **Tier 3** of the 5-tier Bitcoin Commons architecture (BLLVM technology stack):

```
1. Orange Paper (mathematical foundation)
2. consensus-proof (pure math implementation)
3. protocol-engine (Bitcoin abstraction) ← THIS CRATE
4. reference-node (full node implementation)
5. developer-sdk (governance infrastructure)
```

## Purpose

The protocol-engine sits between the pure mathematical consensus rules (consensus-proof) and the full Bitcoin implementation (reference-node). It provides:

### Protocol Abstraction
- **Multiple Variants**: Support for mainnet, testnet, and regtest
- **Network Parameters**: Magic bytes, ports, genesis blocks, difficulty targets
- **Feature Flags**: SegWit, Taproot, RBF, and other protocol features
- **Validation Rules**: Protocol-specific size limits and validation logic

### Protocol Evolution
- **Version Support**: Bitcoin V1 (current), V2 (future), and experimental variants
- **Feature Management**: Enable/disable features based on protocol version
- **Breaking Changes**: Track and manage protocol evolution

## Core Components

### Protocol Variants
- **BitcoinV1**: Production Bitcoin mainnet
- **Testnet3**: Bitcoin test network
- **Regtest**: Regression testing network

### Network Parameters
- **Magic Bytes**: P2P protocol identification
- **Ports**: Default network ports
- **Genesis Blocks**: Network-specific genesis blocks
- **Difficulty**: Proof-of-work targets
- **Halving**: Block subsidy intervals

### Validation Rules
- **Size Limits**: Block, transaction, and script size limits
- **Feature Flags**: SegWit, Taproot, RBF support
- **Fee Rules**: Minimum and maximum fee rates
- **Protocol Context**: Block height and network state

## Usage

### Basic Protocol Engine

```rust
use protocol_engine::{BitcoinProtocolEngine, ProtocolVersion};

// Create a mainnet protocol engine
let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;

// Get network parameters
let params = engine.get_network_params();
println!("Network: {}", params.network_name);
println!("Port: {}", params.default_port);

// Check feature support
if engine.supports_feature("segwit") {
    println!("SegWit is supported");
}
```

### Protocol-Specific Validation

```rust
use protocol_engine::{BitcoinProtocolEngine, ProtocolVersion, ProtocolValidationContext};

let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;
let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000)?;

// Validate block with protocol rules
let result = engine.validate_block_with_protocol(&block, &context)?;

// Validate transaction with protocol rules
let result = engine.validate_transaction_with_protocol(&tx, &context)?;
```

### Regtest Mode

```rust
use protocol_engine::{BitcoinProtocolEngine, ProtocolVersion};

// Create regtest protocol engine
let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest)?;

// Regtest mode has fast mining for testing
assert!(engine.supports_feature("fast_mining"));
assert!(engine.supports_feature("segwit"));
```

## Protocol Evolution

### Bitcoin V1 (Current)
- Basic transactions and proof-of-work
- Economic model and P2P networking
- SegWit and Taproot support
- RBF (Replace-By-Fee) support

### Bitcoin V2 (Future)
- Enhanced scripting capabilities
- Privacy features
- Advanced economic models
- Protocol improvements

## Security Considerations

### Production Use
- **Mainnet**: Full consensus rules and security
- **Testnet**: Same rules as mainnet, different parameters
- **Regtest**: Relaxed rules for testing only

### Development Use
- **Regtest**: Safe for development and testing
- **Fast Mining**: Configurable difficulty for testing
- **Isolated**: No connection to real networks

## Dependencies

All dependencies are pinned to exact versions for security:

```toml
# Consensus layer
consensus-proof = { git = "https://github.com/BTCDecoded/consensus-proof", tag = "v0.1.0" }

# Serialization - EXACT VERSIONS
serde = "=1.0.193"
serde_json = "=1.0.108"

# Error handling - EXACT VERSIONS
anyhow = "=1.0.93"
thiserror = "=1.0.69"

# Cryptography - EXACT VERSIONS
sha2 = "=0.10.9"
ripemd = "=0.1.3"
```

## Testing

```bash
# Run all tests
cargo test

# Run with specific protocol version
cargo test --features testnet

# Run educational mode tests
cargo test --features educational
```

## License

MIT License - see LICENSE file for details.

## Security

See [SECURITY.md](SECURITY.md) for security policies and [BTCDecoded Security Policy](https://github.com/BTCDecoded/.github/blob/main/SECURITY.md) for organization-wide guidelines.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [BTCDecoded Contribution Guide](https://github.com/BTCDecoded/.github/blob/main/CONTRIBUTING.md).
