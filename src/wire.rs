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

use crate::error::ProtocolError;
use crate::network::NetworkMessage;
use crate::Result;
use crate::ConsensusError;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::io::Read;
use std::sync::Arc;

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
pub fn serialize_message(message: &NetworkMessage, magic_bytes: [u8; 4]) -> Result<Vec<u8>> {
    use crate::network::*;

    // Serialize payload based on message type
    let (command, payload) = match message {
        NetworkMessage::Version(v) => ("version", serialize_version(v)?),
        NetworkMessage::VerAck => ("verack", vec![]),
        NetworkMessage::Addr(a) => ("addr", serialize_addr(a)?),
        NetworkMessage::AddrV2(a) => ("addrv2", serialize_addrv2(a)?),
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
        NetworkMessage::GetFilteredBlock(gfb) => {
            ("getfilteredblock", serialize_getfilteredblock(gfb)?)
        }
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::FilteredBlock(fb) => ("filteredblock", serialize_filteredblock(fb)?),
        NetworkMessage::GetBanList(gbl) => ("getbanlist", serialize_getbanlist(gbl)?),
        NetworkMessage::BanList(bl) => ("banlist", serialize_banlist(bl)?),
        // Governance messages
        NetworkMessage::EconomicNodeRegistration(msg) => {
            ("econreg", serialize_economic_node_registration(msg)?)
        }
        NetworkMessage::EconomicNodeVeto(msg) => ("econveto", serialize_economic_node_veto(msg)?),
        NetworkMessage::EconomicNodeStatus(msg) => {
            ("econstatus", serialize_economic_node_status(msg)?)
        }
    };

    // Validate payload size
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!(
                "Message payload too large: {} bytes",
                payload.len()
            )),
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
    reader.read_exact(&mut header).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "IO error: {e}"
        ))))
    })?;

    // Check magic bytes
    let magic = [header[0], header[1], header[2], header[3]];
    if magic != expected_magic {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!(
                "Invalid magic bytes: {magic:?}, expected {expected_magic:?}"
            )),
        )));
    }

    // Read command (12 bytes, null-terminated)
    let command_bytes = &header[4..16];
    let command_len = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = std::str::from_utf8(&command_bytes[..command_len]).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Invalid command: {e}"
        ))))
    })?;

    // Read payload length
    let length_bytes = [header[16], header[17], header[18], header[19]];
    let payload_length = u32::from_le_bytes(length_bytes) as usize;

    if payload_length > MAX_MESSAGE_PAYLOAD {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Payload length too large: {payload_length} bytes")),
        )));
    }

    // Read checksum
    let checksum = [header[20], header[21], header[22], header[23]];

    // Read payload
    let mut payload = vec![0u8; payload_length];
    if payload_length > 0 {
        reader.read_exact(&mut payload).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "IO error: {e}"
            ))))
        })?;
    }

    // Verify checksum
    let calculated_checksum = calculate_checksum(&payload);
    if calculated_checksum != checksum {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Checksum mismatch".to_string()),
        )));
    }

    // Deserialize message based on command
    let message = match command {
        "version" => NetworkMessage::Version(deserialize_version(&payload)?),
        "verack" => NetworkMessage::VerAck,
        "addr" => NetworkMessage::Addr(deserialize_addr(&payload)?),
        "addrv2" => NetworkMessage::AddrV2(deserialize_addrv2(&payload)?),
        "inv" => NetworkMessage::Inv(deserialize_inv(&payload)?),
        "getdata" => NetworkMessage::GetData(deserialize_getdata(&payload)?),
        "getheaders" => NetworkMessage::GetHeaders(deserialize_getheaders(&payload)?),
        "headers" => NetworkMessage::Headers(deserialize_headers(&payload)?),
        "block" => NetworkMessage::Block(Arc::new(deserialize_block(&payload)?)),
        "tx" => NetworkMessage::Tx(Arc::new(deserialize_tx(&payload)?)),
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
        "getfilteredblock" => {
            NetworkMessage::GetFilteredBlock(deserialize_getfilteredblock(&payload)?)
        }
        #[cfg(feature = "utxo-commitments")]
        "filteredblock" => NetworkMessage::FilteredBlock(deserialize_filteredblock(&payload)?),
        "getbanlist" => NetworkMessage::GetBanList(deserialize_getbanlist(&payload)?),
        "banlist" => NetworkMessage::BanList(deserialize_banlist(&payload)?),
        // Governance messages
        "econreg" => NetworkMessage::EconomicNodeRegistration(
            deserialize_economic_node_registration(&payload)?,
        ),
        "econveto" => NetworkMessage::EconomicNodeVeto(deserialize_economic_node_veto(&payload)?),
        "econstatus" => {
            NetworkMessage::EconomicNodeStatus(deserialize_economic_node_status(&payload)?)
        }
        _ => {
            return Err(ProtocolError::Consensus(ConsensusError::Serialization(
                Cow::Owned(format!("Unknown command: {command}")),
            )));
        }
    };

    Ok((message, MESSAGE_HEADER_SIZE + payload_length))
}

// Serialization helpers - Bitcoin P2P wire format encoding

/// Serialize NetworkAddress to Bitcoin wire format (26 bytes)
/// Format: services (8 bytes LE) + ip (16 bytes) + port (2 bytes BE)
fn serialize_network_address(addr: &crate::network::NetworkAddress) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26);
    // services: u64 little-endian
    buf.extend_from_slice(&addr.services.to_le_bytes());
    // ip: [u8; 16] (IPv6 format, IPv4 is 0x0000...0000FFFF + IPv4 bytes)
    buf.extend_from_slice(&addr.ip);
    // port: u16 big-endian (network byte order)
    buf.extend_from_slice(&addr.port.to_be_bytes());
    buf
}

/// Deserialize NetworkAddress from Bitcoin wire format (26 bytes)
fn deserialize_network_address(data: &[u8]) -> Result<crate::network::NetworkAddress> {
    if data.len() < 26 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("NetworkAddress too short".to_string()),
        )));
    }

    // services: u64 little-endian (bytes 0-7)
    let services = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    // ip: [u8; 16] (bytes 8-23)
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&data[8..24]);

    // port: u16 big-endian (bytes 24-25)
    let port = u16::from_be_bytes([data[24], data[25]]);

    Ok(crate::network::NetworkAddress { services, ip, port })
}

/// Serialize VersionMessage to Bitcoin wire format
/// Format per Bitcoin protocol specification:
/// - version: i32 (4 bytes LE)
/// - services: u64 (8 bytes LE)
/// - timestamp: i64 (8 bytes LE)
/// - addr_recv: NetworkAddress (26 bytes)
/// - addr_from: NetworkAddress (26 bytes)
/// - nonce: u64 (8 bytes LE)
/// - user_agent: CompactSize + string bytes
/// - start_height: i32 (4 bytes LE)
/// - relay: u8 (1 byte, 0 or 1)
pub fn serialize_version(v: &crate::network::VersionMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;

    let mut buf = Vec::new();

    // version: i32 (4 bytes, little-endian)
    // Note: VersionMessage uses u32, but protocol expects i32
    buf.extend_from_slice(&(v.version as i32).to_le_bytes());

    // services: u64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.services.to_le_bytes());

    // timestamp: i64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.timestamp.to_le_bytes());

    // addr_recv: NetworkAddress (26 bytes)
    buf.extend_from_slice(&serialize_network_address(&v.addr_recv));

    // addr_from: NetworkAddress (26 bytes)
    buf.extend_from_slice(&serialize_network_address(&v.addr_from));

    // nonce: u64 (8 bytes, little-endian)
    buf.extend_from_slice(&v.nonce.to_le_bytes());

    // user_agent: CompactSize (varint) + string bytes
    let user_agent_bytes = v.user_agent.as_bytes();
    write_varint(&mut buf, user_agent_bytes.len() as u64)?;
    buf.extend_from_slice(user_agent_bytes);

    // start_height: i32 (4 bytes, little-endian)
    buf.extend_from_slice(&v.start_height.to_le_bytes());

    // relay: u8 (1 byte, 0 or 1)
    buf.push(if v.relay { 1 } else { 0 });

    Ok(buf)
}

/// Deserialize VersionMessage from Bitcoin wire format
pub fn deserialize_version(data: &[u8]) -> Result<crate::network::VersionMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;

    let mut cursor = Cursor::new(data);

    // version: i32 (4 bytes, little-endian)
    let mut version_bytes = [0u8; 4];
    cursor.read_exact(&mut version_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read version: {e}"
        ))))
    })?;
    let version = i32::from_le_bytes(version_bytes) as u32;

    // services: u64 (8 bytes, little-endian)
    let mut services_bytes = [0u8; 8];
    cursor.read_exact(&mut services_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read services: {e}"
        ))))
    })?;
    let services = u64::from_le_bytes(services_bytes);

    // timestamp: i64 (8 bytes, little-endian)
    let mut timestamp_bytes = [0u8; 8];
    cursor.read_exact(&mut timestamp_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read timestamp: {e}"
        ))))
    })?;
    let timestamp = i64::from_le_bytes(timestamp_bytes);

    // addr_recv: NetworkAddress (26 bytes)
    let mut addr_recv_bytes = [0u8; 26];
    cursor.read_exact(&mut addr_recv_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read addr_recv: {e}"
        ))))
    })?;
    let addr_recv = deserialize_network_address(&addr_recv_bytes)?;

    // addr_from: NetworkAddress (26 bytes)
    let mut addr_from_bytes = [0u8; 26];
    cursor.read_exact(&mut addr_from_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read addr_from: {e}"
        ))))
    })?;
    let addr_from = deserialize_network_address(&addr_from_bytes)?;

    // nonce: u64 (8 bytes, little-endian)
    let mut nonce_bytes = [0u8; 8];
    cursor.read_exact(&mut nonce_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read nonce: {e}"
        ))))
    })?;
    let nonce = u64::from_le_bytes(nonce_bytes);

    // user_agent: CompactSize (varint) + string bytes
    let user_agent_len = read_varint(&mut cursor)?;
    if user_agent_len > 10000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("User agent too long".to_string()),
        )));
    }
    let mut user_agent_bytes = vec![0u8; user_agent_len as usize];
    cursor.read_exact(&mut user_agent_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read user_agent: {e}"
        ))))
    })?;
    let user_agent = String::from_utf8(user_agent_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Invalid user_agent UTF-8: {e}"
        ))))
    })?;

    // start_height: i32 (4 bytes, little-endian)
    let mut start_height_bytes = [0u8; 4];
    cursor.read_exact(&mut start_height_bytes).map_err(|e| {
        ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
            "Failed to read start_height: {e}"
        ))))
    })?;
    let start_height = i32::from_le_bytes(start_height_bytes);

    // relay: u8 (1 byte, 0 or 1) - OPTIONAL field (version >= 70001)
    let relay = {
        let mut relay_byte = [0u8; 1];
        match cursor.read_exact(&mut relay_byte) {
            Ok(_) => relay_byte[0] != 0,
            Err(_) => true, // Default to relay=true if not present
        }
    };

    Ok(crate::network::VersionMessage {
        version,
        services,
        timestamp,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
        relay,
    })
}

// Stub implementations for other message types (would need full wire format encoding)
fn serialize_addr(_a: &crate::network::AddrMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_addr(_data: &[u8]) -> Result<crate::network::AddrMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

/// Serialize AddrV2Message to Bitcoin wire format (BIP155)
/// Format: CompactSize(count) + [time(4) + services(8) + address_type(1) + address(var) + port(2)]*
pub fn serialize_addrv2(addrv2: &crate::network::AddrV2Message) -> Result<Vec<u8>> {
    use crate::varint::write_varint;
    
    let mut buf = Vec::new();
    
    // CompactSize: number of addresses
    write_varint(&mut buf, addrv2.addresses.len() as u64)?;
    
    // Serialize each address
    for addr in &addrv2.addresses {
        // time: u32 (4 bytes, little-endian)
        buf.extend_from_slice(&addr.time.to_le_bytes());
        
        // services: u64 (8 bytes, little-endian)
        buf.extend_from_slice(&addr.services.to_le_bytes());
        
        // address_type: u8 (1 byte)
        buf.push(addr.address_type as u8);
        
        // address: variable length based on type
        buf.extend_from_slice(&addr.address);
        
        // port: u16 (2 bytes, big-endian)
        buf.extend_from_slice(&addr.port.to_be_bytes());
    }
    
    Ok(buf)
}

/// Deserialize AddrV2Message from Bitcoin wire format (BIP155)
pub fn deserialize_addrv2(data: &[u8]) -> Result<crate::network::AddrV2Message> {
    use crate::varint::read_varint;
    use std::io::Cursor;
    
    let mut cursor = Cursor::new(data);
    
    // CompactSize: number of addresses
    let count = read_varint(&mut cursor)?;
    if count > 1000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Too many addresses in addrv2".to_string()),
        )));
    }
    
    let mut addresses = Vec::with_capacity(count as usize);
    
    // Deserialize each address
    for _ in 0..count {
        // time: u32 (4 bytes, little-endian)
        let mut time_bytes = [0u8; 4];
        cursor.read_exact(&mut time_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read time: {e}"
            ))))
        })?;
        let time = u32::from_le_bytes(time_bytes);
        
        // services: u64 (8 bytes, little-endian)
        let mut services_bytes = [0u8; 8];
        cursor.read_exact(&mut services_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read services: {e}"
            ))))
        })?;
        let services = u64::from_le_bytes(services_bytes);
        
        // address_type: u8 (1 byte)
        let mut addr_type_byte = [0u8; 1];
        cursor.read_exact(&mut addr_type_byte).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read address_type: {e}"
            ))))
        })?;
        let address_type = crate::network::AddressType::from_u8(addr_type_byte[0])
            .ok_or_else(|| {
                ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                    "Invalid address type: {}",
                    addr_type_byte[0]
                ))))
            })?;
        
        // address: variable length based on type
        let addr_len = address_type.address_length();
        let mut address = vec![0u8; addr_len];
        cursor.read_exact(&mut address).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read address: {e}"
            ))))
        })?;
        
        // port: u16 (2 bytes, big-endian)
        let mut port_bytes = [0u8; 2];
        cursor.read_exact(&mut port_bytes).map_err(|e| {
            ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(format!(
                "Failed to read port: {e}"
            ))))
        })?;
        let port = u16::from_be_bytes(port_bytes);
        
        // Create NetworkAddressV2
        let addr_v2 = crate::network::NetworkAddressV2::new(
            time,
            services,
            address_type,
            address,
            port,
        )?;
        
        addresses.push(addr_v2);
    }
    
    Ok(crate::network::AddrV2Message { addresses })
}

/// Serialize InvMessage to Bitcoin wire format
/// Format: count (varint) + count * (type u32 LE + hash 32 bytes)
pub fn serialize_inv(i: &crate::network::InvMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;
    
    let capacity = 9 + (36 * i.inventory.len()); // varint + (4 + 32) per item
    let mut buf = Vec::with_capacity(capacity);
    
    write_varint(&mut buf, i.inventory.len() as u64)?;
    
    for item in &i.inventory {
        buf.extend_from_slice(&item.inv_type.to_le_bytes());
        buf.extend_from_slice(&item.hash);
    }
    
    Ok(buf)
}

/// Deserialize InvMessage from Bitcoin wire format
pub fn deserialize_inv(data: &[u8]) -> Result<crate::network::InvMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;
    
    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Inv message is empty".to_string()),
        )));
    }
    
    let mut cursor = Cursor::new(data);
    
    let count = read_varint(&mut cursor)? as usize;
    
    // Sanity check (max 50000 inventory items per message)
    if count > 50000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many inventory items: {}", count)),
        )));
    }
    
    let mut inventory = Vec::with_capacity(count);
    
    for _ in 0..count {
        let mut type_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut type_bytes)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        let inv_type = u32::from_le_bytes(type_bytes);
        
        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        
        inventory.push(crate::network::InventoryVector { inv_type, hash });
    }
    
    Ok(crate::network::InvMessage { inventory })
}

fn serialize_getdata(_g: &crate::network::GetDataMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_getdata(_data: &[u8]) -> Result<crate::network::GetDataMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

/// Serialize GetHeadersMessage to Bitcoin wire format
/// Format: version (4 bytes LE) + hash_count (varint) + hashes (32 bytes each) + hash_stop (32 bytes)
pub fn serialize_getheaders(gh: &crate::network::GetHeadersMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;
    use std::io::Cursor;
    
    // Estimate capacity: 4 + 1-9 + (32 * hash_count) + 32
    let capacity = 4 + 9 + (32 * gh.block_locator_hashes.len()) + 32;
    let mut buf = Vec::with_capacity(capacity);
    
    // Protocol version (4 bytes, little-endian)
    buf.extend_from_slice(&(gh.version as i32).to_le_bytes());
    
    // Hash count (varint)
    let mut cursor = Cursor::new(&mut buf);
    cursor.set_position(4);
    write_varint(&mut buf, gh.block_locator_hashes.len() as u64)?;
    
    // Block locator hashes (32 bytes each, in internal byte order)
    for hash in &gh.block_locator_hashes {
        buf.extend_from_slice(hash);
    }
    
    // Hash stop (32 bytes)
    buf.extend_from_slice(&gh.hash_stop);
    
    Ok(buf)
}

/// Deserialize GetHeadersMessage from Bitcoin wire format
pub fn deserialize_getheaders(data: &[u8]) -> Result<crate::network::GetHeadersMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;
    
    if data.len() < 4 + 1 + 32 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("GetHeaders message too short".to_string()),
        )));
    }
    
    let mut cursor = Cursor::new(data);
    
    // Protocol version (4 bytes, little-endian)
    let mut version_bytes = [0u8; 4];
    std::io::Read::read_exact(&mut cursor, &mut version_bytes)
        .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
    let version = i32::from_le_bytes(version_bytes) as u32;
    
    // Hash count (varint)
    let hash_count = read_varint(&mut cursor)? as usize;
    
    // Sanity check on hash count
    if hash_count > 2000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many locator hashes: {}", hash_count)),
        )));
    }
    
    // Block locator hashes
    let mut block_locator_hashes = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        let mut hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut hash)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        block_locator_hashes.push(hash);
    }
    
    // Hash stop (32 bytes)
    let mut hash_stop = [0u8; 32];
    std::io::Read::read_exact(&mut cursor, &mut hash_stop)
        .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
    
    Ok(crate::network::GetHeadersMessage {
        version,
        block_locator_hashes,
        hash_stop,
    })
}

/// Serialize HeadersMessage to Bitcoin wire format
/// Format: count (varint) + headers (each: 80 bytes header + varint tx_count which is always 0)
pub fn serialize_headers(h: &crate::network::HeadersMessage) -> Result<Vec<u8>> {
    use crate::varint::write_varint;
    
    // Estimate capacity: 1-9 varint + (81 bytes per header: 80 header + 1 tx_count)
    let capacity = 9 + (81 * h.headers.len());
    let mut buf = Vec::with_capacity(capacity);
    
    // Header count (varint)
    write_varint(&mut buf, h.headers.len() as u64)?;
    
    // Headers (80 bytes each + 1 byte tx_count = 0)
    for header in &h.headers {
        // version (4 bytes LE)
        buf.extend_from_slice(&(header.version as i32).to_le_bytes());
        // prev_block_hash (32 bytes)
        buf.extend_from_slice(&header.prev_block_hash);
        // merkle_root (32 bytes)
        buf.extend_from_slice(&header.merkle_root);
        // timestamp (4 bytes LE)
        buf.extend_from_slice(&(header.timestamp as u32).to_le_bytes());
        // bits (4 bytes LE)
        buf.extend_from_slice(&(header.bits as u32).to_le_bytes());
        // nonce (4 bytes LE)
        buf.extend_from_slice(&(header.nonce as u32).to_le_bytes());
        // tx_count (varint, always 0 for headers message)
        buf.push(0);
    }
    
    Ok(buf)
}

/// Deserialize HeadersMessage from Bitcoin wire format
pub fn deserialize_headers(data: &[u8]) -> Result<crate::network::HeadersMessage> {
    use crate::varint::read_varint;
    use std::io::Cursor;
    
    if data.is_empty() {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned("Headers message is empty".to_string()),
        )));
    }
    
    let mut cursor = Cursor::new(data);
    
    // Header count (varint)
    let header_count = read_varint(&mut cursor)? as usize;
    
    // Sanity check on header count (max 2000 per Bitcoin protocol)
    if header_count > 2000 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Too many headers: {}", header_count)),
        )));
    }
    
    let mut headers = Vec::with_capacity(header_count);
    
    for _ in 0..header_count {
        // version (4 bytes LE)
        let mut version_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut version_bytes)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        let version = i32::from_le_bytes(version_bytes) as i64;
        
        // prev_block_hash (32 bytes)
        let mut prev_block_hash = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut prev_block_hash)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        
        // merkle_root (32 bytes)
        let mut merkle_root = [0u8; 32];
        std::io::Read::read_exact(&mut cursor, &mut merkle_root)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        
        // timestamp (4 bytes LE)
        let mut timestamp_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut timestamp_bytes)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        let timestamp = u32::from_le_bytes(timestamp_bytes) as u64;
        
        // bits (4 bytes LE)
        let mut bits_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut bits_bytes)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        let bits = u32::from_le_bytes(bits_bytes) as u64;
        
        // nonce (4 bytes LE)
        let mut nonce_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut cursor, &mut nonce_bytes)
            .map_err(|e| ProtocolError::Consensus(ConsensusError::Serialization(Cow::Owned(e.to_string()))))?;
        let nonce = u32::from_le_bytes(nonce_bytes) as u64;
        
        // tx_count (varint, should be 0 for headers message, but we read and discard)
        let _tx_count = read_varint(&mut cursor)?;
        
        headers.push(crate::BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        });
    }
    
    Ok(crate::network::HeadersMessage { headers })
}

fn serialize_block(_b: &crate::Block) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_block(_data: &[u8]) -> Result<crate::Block> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_tx(_tx: &crate::Transaction) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_tx(_data: &[u8]) -> Result<crate::Transaction> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

/// Serialize PingMessage to Bitcoin wire format (8-byte nonce)
pub fn serialize_ping(p: &crate::network::PingMessage) -> Result<Vec<u8>> {
    Ok(p.nonce.to_le_bytes().to_vec())
}

/// Deserialize PingMessage from Bitcoin wire format
pub fn deserialize_ping(data: &[u8]) -> Result<crate::network::PingMessage> {
    if data.len() < 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Ping message too short: {} bytes", data.len())),
        )));
    }
    
    let nonce = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    
    Ok(crate::network::PingMessage { nonce })
}

/// Serialize PongMessage to Bitcoin wire format (8-byte nonce)
pub fn serialize_pong(p: &crate::network::PongMessage) -> Result<Vec<u8>> {
    Ok(p.nonce.to_le_bytes().to_vec())
}

/// Deserialize PongMessage from Bitcoin wire format
pub fn deserialize_pong(data: &[u8]) -> Result<crate::network::PongMessage> {
    if data.len() < 8 {
        return Err(ProtocolError::Consensus(ConsensusError::Serialization(
            Cow::Owned(format!("Pong message too short: {} bytes", data.len())),
        )));
    }
    
    let nonce = u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
    
    Ok(crate::network::PongMessage { nonce })
}

fn serialize_feefilter(_f: &crate::network::FeeFilterMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_feefilter(_data: &[u8]) -> Result<crate::network::FeeFilterMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_getblocks(_gb: &crate::network::GetBlocksMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_getblocks(_data: &[u8]) -> Result<crate::network::GetBlocksMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_notfound(_nf: &crate::network::NotFoundMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_notfound(_data: &[u8]) -> Result<crate::network::NotFoundMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_reject(_r: &crate::network::RejectMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_reject(_data: &[u8]) -> Result<crate::network::RejectMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_sendcmpct(_sc: &crate::network::SendCmpctMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_sendcmpct(_data: &[u8]) -> Result<crate::network::SendCmpctMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_cmpctblock(_cb: &crate::network::CmpctBlockMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_cmpctblock(_data: &[u8]) -> Result<crate::network::CmpctBlockMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_getblocktxn(_gbt: &crate::network::GetBlockTxnMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_getblocktxn(_data: &[u8]) -> Result<crate::network::GetBlockTxnMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_blocktxn(_bt: &crate::network::BlockTxnMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_blocktxn(_data: &[u8]) -> Result<crate::network::BlockTxnMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getutxoset(_gus: &crate::commons::GetUTXOSetMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_getutxoset(_data: &[u8]) -> Result<crate::commons::GetUTXOSetMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_utxoset(_us: &crate::commons::UTXOSetMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_utxoset(_data: &[u8]) -> Result<crate::commons::UTXOSetMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_getfilteredblock(_gfb: &crate::commons::GetFilteredBlockMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_getfilteredblock(_data: &[u8]) -> Result<crate::commons::GetFilteredBlockMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

#[cfg(feature = "utxo-commitments")]
fn serialize_filteredblock(_fb: &crate::commons::FilteredBlockMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
#[cfg(feature = "utxo-commitments")]
fn deserialize_filteredblock(_data: &[u8]) -> Result<crate::commons::FilteredBlockMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_getbanlist(_gbl: &crate::commons::GetBanListMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_getbanlist(_data: &[u8]) -> Result<crate::commons::GetBanListMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

fn serialize_banlist(_bl: &crate::commons::BanListMessage) -> Result<Vec<u8>> {
    Ok(vec![])
}
fn deserialize_banlist(_data: &[u8]) -> Result<crate::commons::BanListMessage> {
    Err(ProtocolError::Consensus(ConsensusError::Serialization(
        Cow::Owned("Not implemented".to_string()),
    )))
}

// Governance message serialization

fn serialize_economic_node_registration(
    msg: &crate::commons::EconomicNodeRegistrationMessage,
) -> Result<Vec<u8>> {
    bincode::serialize(msg).map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

fn deserialize_economic_node_registration(
    data: &[u8],
) -> Result<crate::commons::EconomicNodeRegistrationMessage> {
    bincode::deserialize(data)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

fn serialize_economic_node_veto(msg: &crate::commons::EconomicNodeVetoMessage) -> Result<Vec<u8>> {
    bincode::serialize(msg).map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

fn deserialize_economic_node_veto(data: &[u8]) -> Result<crate::commons::EconomicNodeVetoMessage> {
    bincode::deserialize(data)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

fn serialize_economic_node_status(
    msg: &crate::commons::EconomicNodeStatusMessage,
) -> Result<Vec<u8>> {
    bincode::serialize(msg).map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}

fn deserialize_economic_node_status(
    data: &[u8],
) -> Result<crate::commons::EconomicNodeStatusMessage> {
    bincode::deserialize(data)
        .map_err(|e| crate::error::ProtocolError::Serialization(e.to_string()))
}
