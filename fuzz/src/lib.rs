//! Shared helpers for `blvm-protocol-fuzz` binaries (P2P framing, mainnet magic).
#![allow(dead_code)]

use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{calculate_checksum, MAX_MESSAGE_PAYLOAD};

/// Build a valid mainnet P2P frame: magic + 12-byte command + length + checksum + payload.
pub fn build_mainnet_frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let payload = if payload.len() > MAX_MESSAGE_PAYLOAD {
        &payload[..MAX_MESSAGE_PAYLOAD]
    } else {
        payload
    };
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&BITCOIN_MAGIC_MAINNET);
    let mut cmd_bytes = [0u8; 12];
    let b = command.as_bytes();
    let n = b.len().min(12);
    cmd_bytes[..n].copy_from_slice(&b[..n]);
    out.extend_from_slice(&cmd_bytes);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&calculate_checksum(payload));
    out.extend_from_slice(payload);
    out
}
