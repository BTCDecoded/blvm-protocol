//! Bitcoin P2P framing constants: magic bytes, max message size, and common count limits.

/// Mainnet P2P magic (first four bytes of each message on the wire).
pub const BITCOIN_MAGIC_MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Mainnet magic as `u32` (little-endian), for comparison with `u32::from_le_bytes` on the header.
pub const BITCOIN_P2P_MAGIC_MAINNET_LE: u32 = u32::from_le_bytes(BITCOIN_MAGIC_MAINNET);

/// Testnet magic.
pub const BITCOIN_MAGIC_TESTNET: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

/// Regtest magic.
pub const BITCOIN_MAGIC_REGTEST: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

/// Maximum P2P message size including 24-byte header (32 MiB payload cap in practice).
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 32 * 1024 * 1024;

/// Maximum addresses in an `addr` message (`MAX_ADDR_TO_SEND`).
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Maximum inventory entries in `inv` / `getdata` (`MAX_INV_SZ`).
pub const MAX_INV_SZ: usize = 50000;

/// Maximum headers in a `headers` message (`MAX_HEADERS_RESULTS`).
pub const MAX_HEADERS_RESULTS: usize = 2000;
