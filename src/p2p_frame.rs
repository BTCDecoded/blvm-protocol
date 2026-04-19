//! Bitcoin P2P message framing: magic, 12-byte command, LE length, 4-byte checksum, payload.
//!
//! Shared between crates so [`crate::p2p_framing::MAX_PROTOCOL_MESSAGE_LENGTH`] and checksum
//! rules stay single-sourced.

use crate::error::{ProtocolError, Result};
use crate::p2p_framing::MAX_PROTOCOL_MESSAGE_LENGTH;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// First four bytes of double-SHA256(payload), Bitcoin P2P checksum.
#[inline]
pub fn bitcoin_p2p_payload_checksum(payload: &[u8]) -> [u8; 4] {
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash2[..4]);
    out
}

/// Parse the 24-byte header and verify checksum; returns command name and payload slice.
///
/// `command_allowed` should return true for commands this node/process accepts (e.g. allowlist).
pub fn parse_p2p_frame<'a>(
    data: &'a [u8],
    expected_magic_le: u32,
    command_allowed: impl Fn(&str) -> bool,
) -> Result<(&'a str, &'a [u8])> {
    if data.len() < 24 {
        return Err(ProtocolError::InvalidMessage(Cow::Owned(format!(
            "Message too short: {} bytes",
            data.len()
        ))));
    }
    if data.len() > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(ProtocolError::MessageTooLarge {
            size: data.len(),
            max: MAX_PROTOCOL_MESSAGE_LENGTH,
        });
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != expected_magic_le {
        return Err(ProtocolError::InvalidMessage(Cow::Owned(format!(
            "Invalid magic number 0x{:08x}",
            magic
        ))));
    }

    let cmd_bytes = &data[4..16];
    let end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = std::str::from_utf8(&cmd_bytes[..end]).map_err(|_| {
        ProtocolError::InvalidMessage(Cow::Borrowed("Invalid UTF-8 in P2P command"))
    })?;

    if !command_allowed(command) {
        return Err(ProtocolError::InvalidMessage(Cow::Owned(format!(
            "Unknown command: {}",
            command
        ))));
    }

    let payload_length = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    if payload_length > MAX_PROTOCOL_MESSAGE_LENGTH.saturating_sub(24) {
        return Err(ProtocolError::InvalidMessage(Cow::Borrowed(
            "Payload too large",
        )));
    }
    if data.len() < 24 + payload_length {
        return Err(ProtocolError::InvalidMessage(Cow::Borrowed(
            "Incomplete message",
        )));
    }

    let payload = &data[24..24 + payload_length];
    let checksum = &data[20..24];
    let expected = bitcoin_p2p_payload_checksum(payload);
    if checksum != &expected {
        return Err(ProtocolError::InvalidMessage(Cow::Borrowed(
            "Invalid checksum",
        )));
    }

    Ok((command, payload))
}

/// Build a full P2P frame: magic + command (null-padded) + length + checksum + payload.
pub fn build_p2p_frame(magic: [u8; 4], command: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if command.len() > 12 {
        return Err(ProtocolError::InvalidMessage(Cow::Borrowed(
            "P2P command longer than 12 bytes",
        )));
    }

    let mut message = Vec::with_capacity(24 + payload.len());
    message.extend_from_slice(&magic);
    let mut command_bytes = [0u8; 12];
    command_bytes[..command.len()].copy_from_slice(command.as_bytes());
    message.extend_from_slice(&command_bytes);
    message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    message.extend_from_slice(&bitcoin_p2p_payload_checksum(payload));
    message.extend_from_slice(payload);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_framing::BITCOIN_MAGIC_MAINNET;

    #[test]
    fn checksum_matches_double_sha256_prefix() {
        let p = [1u8, 2, 3];
        let c = bitcoin_p2p_payload_checksum(&p);
        let h1 = Sha256::digest(p);
        let h2 = Sha256::digest(h1);
        assert_eq!(c, h2[..4]);
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let payload = vec![0xab, 0xcd];
        let frame = build_p2p_frame(BITCOIN_MAGIC_MAINNET, "ping", &payload).unwrap();
        let magic_le = u32::from_le_bytes(BITCOIN_MAGIC_MAINNET);
        let (cmd, pl) = parse_p2p_frame(&frame, magic_le, |c| c == "ping" || c == "pong").unwrap();
        assert_eq!(cmd, "ping");
        assert_eq!(pl, payload.as_slice());
    }

    #[test]
    fn unknown_command_rejected() {
        let frame = build_p2p_frame(BITCOIN_MAGIC_MAINNET, "weird", &[]).unwrap();
        let magic_le = u32::from_le_bytes(BITCOIN_MAGIC_MAINNET);
        let err = parse_p2p_frame(&frame, magic_le, |c| c == "ping").unwrap_err();
        assert!(format!("{}", err).contains("Unknown command"));
    }
}
