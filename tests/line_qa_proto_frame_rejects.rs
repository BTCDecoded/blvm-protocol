//! Truncated and rejected Bitcoin P2P frames.

use blvm_protocol::p2p_frame::{build_p2p_frame, parse_p2p_frame};
use blvm_protocol::p2p_framing::BITCOIN_MAGIC_MAINNET;
use blvm_protocol::wire::{deserialize_feefilter, deserialize_ping, deserialize_pong};

fn magic_le() -> u32 {
    u32::from_le_bytes(BITCOIN_MAGIC_MAINNET)
}

fn allow_ping(command: &str) -> bool {
    command == "ping"
}

#[test]
fn parse_p2p_frame_rejects_every_short_header() {
    for len in 0..24 {
        let data = vec![0u8; len];
        match parse_p2p_frame(&data, magic_le(), allow_ping) {
            Err(err) => {
                let message = err.to_string();
                assert!(
                    message.contains(&format!("Message too short: {len} bytes")),
                    "length {len} returned {message}"
                );
            }
            Ok((command, payload)) => {
                panic!("length {len} parsed as {command} payload {}", payload.len())
            }
        }
    }
}

#[test]
fn parse_p2p_frame_rejects_a_bad_magic() {
    let mut data = vec![0u8; 24];
    data[4..8].copy_from_slice(b"ping");
    match parse_p2p_frame(&data, magic_le(), allow_ping) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("Invalid magic number"),
                "bad magic returned {message}"
            );
        }
        Ok((command, _)) => panic!("bad magic parsed as {command}"),
    }
}

#[test]
fn parse_p2p_frame_rejects_an_unknown_command() {
    let frame = build_p2p_frame(BITCOIN_MAGIC_MAINNET, "weird", &[]).expect("frame");
    match parse_p2p_frame(&frame, magic_le(), allow_ping) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("Unknown command: weird"),
                "unknown command returned {message}"
            );
        }
        Ok((command, _)) => panic!("unknown command parsed as {command}"),
    }
}

#[test]
fn parse_p2p_frame_rejects_a_bad_checksum() {
    let mut frame = build_p2p_frame(BITCOIN_MAGIC_MAINNET, "ping", &[0; 8]).expect("frame");
    frame[20] ^= 0xff;
    match parse_p2p_frame(&frame, magic_le(), allow_ping) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("Invalid checksum"),
                "bad checksum returned {message}"
            );
        }
        Ok((command, _)) => panic!("bad checksum parsed as {command}"),
    }
}

#[test]
fn build_p2p_frame_rejects_a_long_command() {
    match build_p2p_frame(BITCOIN_MAGIC_MAINNET, "thirteenbytes", &[]) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("P2P command longer than 12 bytes"),
                "long command returned {message}"
            );
        }
        Ok(frame) => panic!("long command built a {} byte frame", frame.len()),
    }
}

#[test]
fn deserialize_ping_rejects_a_short_payload() {
    for len in 0..8 {
        match deserialize_ping(&vec![0u8; len]) {
            Err(err) => {
                let message = err.to_string();
                assert!(
                    message.contains(&format!("Ping message too short: {len} bytes")),
                    "ping length {len} returned {message}"
                );
            }
            Ok(ping) => panic!("ping length {len} decoded nonce {}", ping.nonce),
        }
    }
}

#[test]
fn deserialize_pong_rejects_a_short_payload() {
    for len in 0..8 {
        match deserialize_pong(&vec![0u8; len]) {
            Err(err) => {
                let message = err.to_string();
                assert!(
                    message.contains(&format!("Pong message too short: {len} bytes")),
                    "pong length {len} returned {message}"
                );
            }
            Ok(pong) => panic!("pong length {len} decoded nonce {}", pong.nonce),
        }
    }
}

#[test]
fn deserialize_feefilter_rejects_a_short_payload() {
    match deserialize_feefilter(&[0u8; 7]) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("FeeFilter message too short"),
                "feefilter returned {message}"
            );
        }
        Ok(filter) => panic!("short feefilter decoded {}", filter.feerate),
    }
}
