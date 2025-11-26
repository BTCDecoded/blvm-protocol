//! Bitcoin P2P wire format serialization
//!
//! Implements Bitcoin P2P protocol message framing:
//! Format: [magic:4][command:12][length:4][checksum:4][payload:var]
//!
//! - Magic bytes: Network identifier (mainnet, testnet, etc.)
//! - Command: 12-byte ASCII string (null-padded)
//! - Length: Payload length in bytes (little-endian u32)
//! - Checksum: First 4 bytes of double SHA256 of payload
//! - Payload: Message-specific data

use crate::{Hash, Result};
use bllvm_consensus::ConsensusError;
use std::borrow::Cow;
use crate::network::NetworkMessage;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

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

/// Serialize a network message to Bitcoin P2P wire format
pub fn serialize_message(
    message: &NetworkMessage,
    magic_bytes: [u8; 4],
) -> Result<Vec<u8>> {
    use crate::network::*;

    // Serialize payload based on message type
    let (command, payload) = match message {
        NetworkMessage::Version(v) => ("version", serialize_version(v)?),
        NetworkMessage::VerAck => ("verack", vec![]),
        NetworkMessage::Addr(a) => ("addr", serialize_addr(a)?),
        NetworkMessage::Inv(i) => ("inv", serialize_inv(i)?),
        NetworkMessage::GetData(g) => ("getdata", serialize_getdata(g)?),
        NetworkMessage::GetHeaders(gh) => ("getheaders", serialize_getheaders(gh)?),
        NetworkMessage::Headers(h) => ("headers", serialize_headers(h)?),
        NetworkMessage::Block(b) => ("block", serialize_block(b)?),
        NetworkMessage::Tx(tx) => ("tx", serialize_tx(tx)?),
        NetworkMessage::Ping(p) => ("ping", serialize_ping(p)?),
        NetworkMessage::Pong(p) => ("pong", serialize_pong(p)?),
        NetworkMessage::MemPool => ("mempool", vec![]),
        NetworkMessage::FeeFilter(f) => ("feefilter", serialize_feefilter(f)?),
        NetworkMessage::GetBlocks(gb) => ("getblocks", serialize_getblocks(gb)?),
        NetworkMessage::GetAddr => ("getaddr", vec![]),
        NetworkMessage::NotFound(nf) => ("notfound", serialize_notfound(nf)?),
        NetworkMessage::Reject(r) => ("reject", serialize_reject(r)?),
        NetworkMessage::SendHeaders => ("sendheaders", vec![]),
        NetworkMessage::SendCmpct(sc) => ("sendcmpct", serialize_sendcmpct(sc)?),
        NetworkMessage::CmpctBlock(cb) => ("cmpctblock", serialize_cmpctblock(cb)?),
        NetworkMessage::GetBlockTxn(gbt) => ("getblocktxn", serialize_getblocktxn(gbt)?),
        NetworkMessage::BlockTxn(bt) => ("blocktxn", serialize_blocktxn(bt)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetUTXOSet(gus) => ("getutxoset", serialize_getutxoset(gus)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::UTXOSet(us) => ("utxoset", serialize_utxoset(us)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetFilteredBlock(gfb) => ("getfilteredblock", serialize_getfilteredblock(gfb)?),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::FilteredBlock(fb) => ("filteredblock", serialize_filteredblock(fb)?),
        NetworkMessage::GetBanList(gbl) => ("getbanlist", serialize_getbanlist(gbl)?),
        NetworkMessage::BanList(bl) => ("banlist", serialize_banlist(bl)?),
    };

    // Validate payload size
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(crate::ConsensusError::Serialization(Cow::Owned(format!(
            "Message payload too large: {} bytes",
            payload.len()
        )));
    }

    // Calculate checksum
    let checksum = calculate_checksum(&payload);

    // Build message
    let mut message_bytes = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len());

    // Magic bytes
    message_bytes.extend_from_slice(&magic_bytes);

    // Command (12 bytes, null-padded)
    let mut command_bytes = [0u8; 12];
    let cmd_len = command.len().min(12);
    command_bytes[..cmd_len].copy_from_slice(&command.as_bytes()[..cmd_len]);
    message_bytes.extend_from_slice(&command_bytes);

    // Payload length (little-endian u32)
    message_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Checksum
    message_bytes.extend_from_slice(&checksum);

    // Payload
    message_bytes.extend_from_slice(&payload);

    Ok(message_bytes)
}

/// Deserialize Bitcoin P2P wire format to network message
pub fn deserialize_message<R: Read>(
    reader: &mut R,
    expected_magic: [u8; 4],
) -> Result<(NetworkMessage, usize)> {
    use crate::network::*;

    // Read header
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    reader.read_exact(&mut header).map_err(|e| ConsensusError::Serialization(Cow::Owned(format!("IO error: {}", e))))?;

    // Check magic bytes
    let magic = [header[0], header[1], header[2], header[3]];
    if magic != expected_magic {
        return Err(crate::ConsensusError::Serialization(Cow::Owned(format!(
            "Invalid magic bytes: {:?}, expected {:?}",
            magic, expected_magic
        )));
    }

    // Read command (12 bytes, null-terminated)
    let command_bytes = &header[4..16];
    let command_len = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = std::str::from_utf8(&command_bytes[..command_len])
        .map_err(|e| crate::ConsensusError::Serialization(Cow::Owned(format!("Invalid command: {}", e)))?;

    // Read payload length
    let length_bytes = [header[16], header[17], header[18], header[19]];
    let payload_length = u32::from_le_bytes(length_bytes) as usize;

    if payload_length > MAX_MESSAGE_PAYLOAD {
        return Err(crate::ConsensusError::Serialization(Cow::Owned(format!(
            "Payload length too large: {} bytes",
            payload_length
        )));
    }

    // Read checksum
    let checksum = [header[20], header[21], header[22], header[23]];

    // Read payload
    let mut payload = vec![0u8; payload_length];
    if payload_length > 0 {
        reader.read_exact(&mut payload).map_err(|e| ConsensusError::Serialization(Cow::Owned(format!("IO error: {}", e))))?;
    }

    // Verify checksum
    let calculated_checksum = calculate_checksum(&payload);
    if calculated_checksum != checksum {
        return Err(crate::ConsensusError::Serialization(
            "Checksum mismatch".to_string(),
        ));
    }

    // Deserialize message based on command
    let message = match command {
        "version" => NetworkMessage::Version(deserialize_version(&payload)?),
        "verack" => NetworkMessage::VerAck,
        "addr" => NetworkMessage::Addr(deserialize_addr(&payload)?),
        "inv" => NetworkMessage::Inv(deserialize_inv(&payload)?),
        "getdata" => NetworkMessage::GetData(deserialize_getdata(&payload)?),
        "getheaders" => NetworkMessage::GetHeaders(deserialize_getheaders(&payload)?),
        "headers" => NetworkMessage::Headers(deserialize_headers(&payload)?),
        "block" => NetworkMessage::Block(deserialize_block(&payload)?),
        "tx" => NetworkMessage::Tx(Box::new(deserialize_tx(&payload)?)),
        "ping" => NetworkMessage::Ping(deserialize_ping(&payload)?),
        "pong" => NetworkMessage::Pong(deserialize_pong(&payload)?),
        "mempool" => NetworkMessage::MemPool,
        "feefilter" => NetworkMessage::FeeFilter(deserialize_feefilter(&payload)?),
        "getblocks" => NetworkMessage::GetBlocks(deserialize_getblocks(&payload)?),
        "getaddr" => NetworkMessage::GetAddr,
        "notfound" => NetworkMessage::NotFound(deserialize_notfound(&payload)?),
        "reject" => NetworkMessage::Reject(deserialize_reject(&payload)?),
        "sendheaders" => NetworkMessage::SendHeaders,
        "sendcmpct" => NetworkMessage::SendCmpct(deserialize_sendcmpct(&payload)?),
        "cmpctblock" => NetworkMessage::CmpctBlock(deserialize_cmpctblock(&payload)?),
        "getblocktxn" => NetworkMessage::GetBlockTxn(deserialize_getblocktxn(&payload)?),
        "blocktxn" => NetworkMessage::BlockTxn(deserialize_blocktxn(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "getutxoset" => NetworkMessage::GetUTXOSet(deserialize_getutxoset(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "utxoset" => NetworkMessage::UTXOSet(deserialize_utxoset(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "getfilteredblock" => NetworkMessage::GetFilteredBlock(deserialize_getfilteredblock(&payload)?),
        #[cfg(feature = "utxo-commitments")]
        "filteredblock" => NetworkMessage::FilteredBlock(deserialize_filteredblock(&payload)?),
        "getbanlist" => NetworkMessage::GetBanList(deserialize_getbanlist(&payload)?),
        "banlist" => NetworkMessage::BanList(deserialize_banlist(&payload)?),
        _ => {
            return Err(crate::ConsensusError::Serialization(Cow::Owned(format!(
                "Unknown command: {}",
                command
            )));
        }
    };

    Ok((message, MESSAGE_HEADER_SIZE + payload_length))
}

// Serialization helpers (simplified - using bincode for now)
// In a full implementation, these would use proper Bitcoin wire format encoding

fn serialize_version(v: &crate::network::VersionMessage) -> Result<Vec<u8>> {
    use bincode;
    bincode::serialize(v).map_err(|e| crate::ConsensusError::Serialization(Cow::Owned(format!("Serialization error: {}", e)))
}

fn deserialize_version(data: &[u8]) -> Result<crate::network::VersionMessage> {
    use bincode;
    bincode::deserialize(data).map_err(|e| crate::ConsensusError::Serialization(Cow::Owned(format!("Deserialization error: {}", e)))
}

// Stub implementations for other message types (would need full wire format encoding)
fn serialize_addr(_a: &crate::network::AddrMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_addr(_data: &[u8]) -> Result<crate::network::AddrMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_inv(_i: &crate::network::InvMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_inv(_data: &[u8]) -> Result<crate::network::InvMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_getdata(_g: &crate::network::GetDataMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_getdata(_data: &[u8]) -> Result<crate::network::GetDataMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_getheaders(_gh: &crate::network::GetHeadersMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_getheaders(_data: &[u8]) -> Result<crate::network::GetHeadersMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_headers(_h: &crate::network::HeadersMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_headers(_data: &[u8]) -> Result<crate::network::HeadersMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_block(_b: &crate::Block) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_block(_data: &[u8]) -> Result<crate::Block> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_tx(_tx: &crate::Transaction) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_tx(_data: &[u8]) -> Result<crate::Transaction> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_ping(_p: &crate::network::PingMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_ping(_data: &[u8]) -> Result<crate::network::PingMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_pong(_p: &crate::network::PongMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_pong(_data: &[u8]) -> Result<crate::network::PongMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_feefilter(_f: &crate::network::FeeFilterMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_feefilter(_data: &[u8]) -> Result<crate::network::FeeFilterMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_getblocks(_gb: &crate::network::GetBlocksMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_getblocks(_data: &[u8]) -> Result<crate::network::GetBlocksMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_notfound(_nf: &crate::network::NotFoundMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_notfound(_data: &[u8]) -> Result<crate::network::NotFoundMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_reject(_r: &crate::network::RejectMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_reject(_data: &[u8]) -> Result<crate::network::RejectMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_sendcmpct(_sc: &crate::network::SendCmpctMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_sendcmpct(_data: &[u8]) -> Result<crate::network::SendCmpctMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_cmpctblock(_cb: &crate::network::CmpctBlockMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_cmpctblock(_data: &[u8]) -> Result<crate::network::CmpctBlockMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_getblocktxn(_gbt: &crate::network::GetBlockTxnMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_getblocktxn(_data: &[u8]) -> Result<crate::network::GetBlockTxnMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_blocktxn(_bt: &crate::network::BlockTxnMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_blocktxn(_data: &[u8]) -> Result<crate::network::BlockTxnMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getutxoset(_gus: &crate::commons::GetUTXOSetMessage) -> Result<Vec<u8>> { Ok(vec![]) }
#[cfg(feature = "utxo-commitments")]
fn deserialize_getutxoset(_data: &[u8]) -> Result<crate::commons::GetUTXOSetMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_utxoset(_us: &crate::commons::UTXOSetMessage) -> Result<Vec<u8>> { Ok(vec![]) }
#[cfg(feature = "utxo-commitments")]
fn deserialize_utxoset(_data: &[u8]) -> Result<crate::commons::UTXOSetMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getfilteredblock(_gfb: &crate::commons::GetFilteredBlockMessage) -> Result<Vec<u8>> { Ok(vec![]) }
#[cfg(feature = "utxo-commitments")]
fn deserialize_getfilteredblock(_data: &[u8]) -> Result<crate::commons::GetFilteredBlockMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_filteredblock(_fb: &crate::commons::FilteredBlockMessage) -> Result<Vec<u8>> { Ok(vec![]) }
#[cfg(feature = "utxo-commitments")]
fn deserialize_filteredblock(_data: &[u8]) -> Result<crate::commons::FilteredBlockMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_getbanlist(_gbl: &crate::commons::GetBanListMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_getbanlist(_data: &[u8]) -> Result<crate::commons::GetBanListMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

fn serialize_banlist(_bl: &crate::commons::BanListMessage) -> Result<Vec<u8>> { Ok(vec![]) }
fn deserialize_banlist(_data: &[u8]) -> Result<crate::commons::BanListMessage> { 
    Err(crate::ConsensusError::Serialization("Not implemented".to_string()))
}

