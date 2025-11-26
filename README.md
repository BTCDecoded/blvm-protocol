# Bitcoin Protocol Engine

**Bitcoin protocol abstraction layer for multiple variants and evolution.**

> **For verified system status**: See [SYSTEM_STATUS.md](https://github.com/BTCDecoded/.github/blob/main/SYSTEM_STATUS.md) in the BTCDecoded organization repository.

This crate provides a Bitcoin protocol abstraction layer that enables:
- Multiple Bitcoin variants (mainnet, testnet, regtest)
- Protocol evolution support (Bitcoin V1, V2, etc.)
- Economic model abstraction (PoW, future variants)
- **Commons-specific protocol extensions** (UTXO commitments, ban list sharing)
- Research-friendly interfaces

## Architecture Position

This is **Tier 3** of the 5-tier Bitcoin Commons architecture (BLLVM technology stack):

```
1. Orange Paper (mathematical foundation)
2. bllvm-consensus (pure math implementation)
3. bllvm-protocol (Bitcoin abstraction) ← THIS CRATE
4. bllvm-node (full node implementation)
5. bllvm-sdk (developer toolkit)
```

## Purpose

The bllvm-protocol sits between the pure mathematical consensus rules (bllvm-consensus) and the full Bitcoin implementation (bllvm-node). It provides:

### Protocol Abstraction
- **Multiple Variants**: Support for mainnet, testnet, and regtest
- **Network Parameters**: Magic bytes, ports, genesis blocks, difficulty targets
- **Feature Flags**: SegWit, Taproot, RBF, and other protocol features
- **Validation Rules**: Protocol-specific size limits and validation logic

### Protocol Evolution
- **Version Support**: Bitcoin V1 (current), V2 (future), and experimental variants
- **Feature Management**: Enable/disable features based on protocol version
- **Breaking Changes**: Track and manage protocol evolution

### Commons-Specific Extensions
- **UTXO Commitments**: Protocol messages for UTXO set synchronization and verification
- **Filtered Blocks**: Spam-filtered block relay for efficient syncing
- **Ban List Sharing**: Distributed ban list management
- **Service Flags**: Standard and Commons-specific capability flags

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

### Network Messages
- **Core P2P Messages**: Version, VerAck, Addr, Inv, GetData, GetHeaders, Headers, Block, Tx, Ping, Pong, MemPool, FeeFilter
- **Additional Core Messages**: GetBlocks, GetAddr, NotFound, Reject, SendHeaders
- **BIP152 (Compact Block Relay)**: SendCmpct, CmpctBlock, GetBlockTxn, BlockTxn
- **Commons Extensions**: GetUTXOSet, UTXOSet, GetFilteredBlock, FilteredBlock, GetBanList, BanList

### Service Flags
- **Standard Flags**: NODE_NETWORK, NODE_WITNESS, NODE_COMPACT_FILTERS, etc.
- **Commons Flags**: NODE_UTXO_COMMITMENTS, NODE_BAN_LIST_SHARING, NODE_FIBRE, NODE_DANDELION, NODE_PACKAGE_RELAY

### Validation Rules
- **Size Limits**: Block, transaction, and script size limits
- **Feature Flags**: SegWit, Taproot, RBF support
- **Fee Rules**: Minimum and maximum fee rates
- **Protocol Context**: Block height and network state
- **DoS Protection**: Protocol-level message size limits

## Usage

### Basic Protocol Engine

```rust
use bllvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

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

### Service Flags

```rust
use bllvm_protocol::service_flags::{self, standard, commons};

// Check service flags
let services = standard::NODE_NETWORK | standard::NODE_WITNESS | commons::NODE_FIBRE;
assert!(service_flags::has_flag(services, standard::NODE_NETWORK));
assert!(service_flags::has_flag(services, commons::NODE_FIBRE));

// Get all Commons flags
let commons_flags = service_flags::get_commons_flags();
assert!(service_flags::has_flag(commons_flags, commons::NODE_FIBRE));
assert!(service_flags::has_flag(commons_flags, commons::NODE_BAN_LIST_SHARING));
```

### Network Message Processing

```rust
use bllvm_protocol::network::{process_network_message, NetworkMessage, PeerState};
use bllvm_protocol::BitcoinProtocolEngine;

let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;
let mut peer_state = PeerState::new();

// Process a version message
let version_msg = NetworkMessage::Version(/* ... */);
let response = process_network_message(
    &engine,
    &version_msg,
    &mut peer_state,
    None,
    None,
    None,
)?;
```

### Commons Protocol Extensions

```rust
use bllvm_protocol::commons::{GetUTXOSetMessage, GetBanListMessage};
use bllvm_protocol::network::NetworkMessage;

// Request UTXO set at specific height
let get_utxo = NetworkMessage::GetUTXOSet(GetUTXOSetMessage {
    height: 700000,
    block_hash: [/* ... */],
});

// Request ban list
let get_banlist = NetworkMessage::GetBanList(GetBanListMessage {
    request_id: 12345,
    min_score: Some(100),
});
```

### BIP152 Compact Block Relay

```rust
use bllvm_protocol::network::{NetworkMessage, SendCmpctMessage};

// Negotiate compact block relay
let sendcmpct = NetworkMessage::SendCmpct(SendCmpctMessage {
    version: 2,  // Compact block version
    prefer_cmpct: 1,  // Prefer compact blocks
});
```

### Protocol-Specific Validation

```rust
use bllvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1)?;

// Validate block with protocol rules
let result = engine.validate_block(&block, &utxos, height)?;

// Validate transaction with protocol rules
let result = engine.validate_transaction(&tx)?;
```

### Regtest Mode

```rust
use bllvm_protocol::{BitcoinProtocolEngine, ProtocolVersion};

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
- BIP152 Compact Block Relay
- BIP157 Block Filtering

### Commons Extensions
- UTXO Commitments protocol
- Filtered block relay (spam filtering)
- Ban list sharing
- FIBRE support
- Dandelion++ privacy relay

### Bitcoin V2 (Future)
- Enhanced scripting capabilities
- Privacy features
- Advanced economic models
- Protocol improvements

## Modules

### Core Modules
- `network` - P2P network message types and processing
- `service_flags` - Service flags for node capabilities
- `commons` - Commons-specific protocol extensions
- `varint` - Variable-length integer encoding
- `economic` - Economic parameters and calculations
- `features` - Feature activation and management
- `validation` - Protocol-specific validation rules

### BIP Implementations
- `bip157` - Client-side block filtering (BIP157)
- `bip158` - Compact block filters (BIP158)
- `address` - Bech32/Bech32m address encoding (BIP173/350/351)
- `payment` - Payment protocol (BIP70)
- `fibre` - FIBRE protocol definitions

## Testing

```bash
# Run all tests
cargo test

# Run network message tests
cargo test --test network_message_tests

# Run protocol limits tests
cargo test --test protocol_limits_tests

# Run with specific protocol version
cargo test --features testnet

# Run with UTXO commitments
cargo test --features utxo-commitments
```

## Test Coverage

- **125 passing tests** (up from 118)
- Network message processing tests (22 tests)
- Protocol limits tests (10 tests)
- Service flags tests
- Varint encoding tests
- Protocol integration tests

## Security Considerations

### Production Use
- **Mainnet**: Full consensus rules and security
- **Testnet**: Same rules as mainnet, different parameters
- **Regtest**: Relaxed rules for testing only

### Development Use
- **Regtest**: Safe for development and testing
- **Fast Mining**: Configurable difficulty for testing
- **Isolated**: No connection to real networks

### DoS Protection
- Protocol-level message size limits
- Address count limits (1000)
- Inventory item limits (50000)
- Header count limits (2000)
- Transaction count limits (10000 per block)

## Dependencies

All dependencies are pinned to exact versions for security:

```toml
# Consensus layer
bllvm-consensus = { path = "../bllvm-consensus" }

# Serialization - EXACT VERSIONS
serde = "=1.0.228"
serde_json = "=1.0.108"
bincode = "=1.3.3"

# Error handling - EXACT VERSIONS
anyhow = "=1.0.93"
thiserror = "=1.0.69"

# Cryptography - EXACT VERSIONS
sha2 = "=0.10.9"
ripemd = "=0.1.3"
secp256k1 = "=0.28.2"
```

## License

MIT License - see LICENSE file for details.

## Security

See [SECURITY.md](SECURITY.md) for security policies and [BTCDecoded Security Policy](https://github.com/BTCDecoded/.github/blob/main/SECURITY.md) for organization-wide guidelines.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [BTCDecoded Contribution Guide](https://github.com/BTCDecoded/.github/blob/main/CONTRIBUTING.md).
