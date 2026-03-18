//! Message framing constants and payload checksum (first 4 bytes of double-SHA256).

use sha2::{Digest, Sha256};

/// Bitcoin P2P message header size (magic + command + length + checksum)
pub const MESSAGE_HEADER_SIZE: usize = 4 + 12 + 4 + 4;

/// Maximum message payload size (32 MB)
pub const MAX_MESSAGE_PAYLOAD: usize = 32 * 1024 * 1024;

/// Calculate checksum for message payload (first 4 bytes of double SHA256)
pub fn calculate_checksum(payload: &[u8]) -> [u8; 4] {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash2[..4]);
    checksum
}
