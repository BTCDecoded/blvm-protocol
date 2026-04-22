#![no_main]
//! Full P2P frame parse: magic, command, length, checksum, then payload dispatch.
use std::io::Cursor;

use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{calculate_checksum, deserialize_message, MAX_MESSAGE_PAYLOAD};
use libfuzzer_sys::fuzz_target;

/// Commands handled by `deserialize_message` (including optional utxo-commitment arms).
const COMMANDS: &[&str] = &[
    "version",
    "verack",
    "addr",
    "addrv2",
    "inv",
    "getdata",
    "getheaders",
    "headers",
    "block",
    "tx",
    "ping",
    "pong",
    "mempool",
    "feefilter",
    "getblocks",
    "getaddr",
    "notfound",
    "reject",
    "sendheaders",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "getutxoset",
    "utxoset",
    "getfilteredblock",
    "filteredblock",
    "getbanlist",
    "banlist",
];

fn build_frame(cmd: &str, payload: &[u8]) -> Vec<u8> {
    let payload = if payload.len() > MAX_MESSAGE_PAYLOAD {
        &payload[..MAX_MESSAGE_PAYLOAD]
    } else {
        payload
    };
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&BITCOIN_MAGIC_MAINNET);
    let mut cmd_bytes = [0u8; 12];
    let b = cmd.as_bytes();
    let n = b.len().min(12);
    cmd_bytes[..n].copy_from_slice(&b[..n]);
    out.extend_from_slice(&cmd_bytes);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&calculate_checksum(payload));
    out.extend_from_slice(payload);
    out
}

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_message(&mut Cursor::new(data), BITCOIN_MAGIC_MAINNET);

    if data.is_empty() {
        return;
    }
    let idx = (data[0] as usize) % COMMANDS.len();
    let cmd = COMMANDS[idx];
    let payload = &data[1..];
    let frame = build_frame(cmd, payload);
    let _ = deserialize_message(&mut Cursor::new(&frame), BITCOIN_MAGIC_MAINNET);

    if data.len() > 2 {
        let idx2 = (data[1] as usize) % COMMANDS.len();
        let payload2 = &data[2..];
        let frame2 = build_frame(COMMANDS[idx2], payload2);
        let _ = deserialize_message(&mut Cursor::new(&frame2), BITCOIN_MAGIC_MAINNET);
    }
});
