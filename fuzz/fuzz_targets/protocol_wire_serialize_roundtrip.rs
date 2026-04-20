#![no_main]
//! Deserialize → serialize → deserialize for mainnet P2P frames; `NetworkMessage` must round-trip.
use std::io::Cursor;

use blvm_protocol::p2p_frame::{build_p2p_frame, parse_p2p_frame};
use blvm_protocol::p2p_framing::{BITCOIN_MAGIC_MAINNET, BITCOIN_P2P_MAGIC_MAINNET_LE};
use blvm_protocol::wire::{
    calculate_checksum, deserialize_message, serialize_message, MAX_MESSAGE_PAYLOAD,
};
use libfuzzer_sys::fuzz_target;

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
    "econreg",
    "econveto",
    "econstatus",
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

fn roundtrip(msg_bytes: &[u8]) {
    let Ok((msg, _)) = deserialize_message(&mut Cursor::new(msg_bytes), BITCOIN_MAGIC_MAINNET) else {
        return;
    };
    let Ok(wire) = serialize_message(&msg, BITCOIN_MAGIC_MAINNET) else {
        return;
    };
    let Ok((msg2, _)) = deserialize_message(&mut Cursor::new(&wire), BITCOIN_MAGIC_MAINNET) else {
        return;
    };
    assert_eq!(msg, msg2);
}

fuzz_target!(|data: &[u8]| {
    roundtrip(data);

    if !data.is_empty() {
        let idx = (data[0] as usize) % COMMANDS.len();
        let cmd = COMMANDS[idx];
        let payload = &data[1..];
        let frame = build_frame(cmd, payload);
        roundtrip(&frame);
    }

    if data.len() > 2 {
        let idx = (data[1] as usize) % COMMANDS.len();
        let frame = build_frame(COMMANDS[idx], &data[2..]);
        roundtrip(&frame);
    }

    if !data.is_empty() {
        let idx = (data[0] as usize) % COMMANDS.len();
        let payload = &data[1..];
        let payload = if payload.len() > MAX_MESSAGE_PAYLOAD {
            &payload[..MAX_MESSAGE_PAYLOAD]
        } else {
            payload
        };
        if let Ok(frame) = build_p2p_frame(BITCOIN_MAGIC_MAINNET, COMMANDS[idx], payload) {
            let _ = parse_p2p_frame(&frame, BITCOIN_P2P_MAGIC_MAINNET_LE, |_| true);
        }
    }
});
