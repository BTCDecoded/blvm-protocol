//! FIBRE: Fast Internet Bitcoin Relay Engine - Protocol Definitions
//!
//! This module provides FIBRE protocol packet format definitions, serialization,
//! and protocol-level types. Transport implementation is in bllvm-node.

use crate::Hash;
use serde::{Deserialize, Serialize};

/// FIBRE packet format constants
pub const FIBRE_MAGIC: [u8; 4] = [0xF1, 0xB3, 0xE0, 0x00]; // "FIBRE" in hex-like
pub const FIBRE_VERSION: u8 = 1;
pub const PACKET_TYPE_CHUNK: u8 = 0x01;
pub const PACKET_TYPE_ACK: u8 = 0x02;
pub const PACKET_TYPE_COMPLETE: u8 = 0x03;
pub const PACKET_TYPE_ERROR: u8 = 0x04;
pub const MAX_PACKET_SIZE: usize = 1500; // Ethernet MTU
pub const HEADER_SIZE: usize = 62;
pub const MAX_DATA_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE - 4; // 1434 bytes
pub const DEFAULT_SHARD_SIZE: usize = 1400; // UDP MTU - headers

/// FEC chunk with full metadata for FIBRE transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecChunk {
    /// Chunk index (0-based, includes both data and parity shards)
    pub index: u32,
    /// Total number of chunks (data + parity)
    pub total_chunks: u32,
    /// Number of data chunks (before parity)
    pub data_chunks: u32,
    /// Chunk data (FEC-encoded shard)
    pub data: Vec<u8>,
    /// Chunk size in bytes
    pub size: usize,
    /// Block hash (for validation and assembly)
    pub block_hash: Hash,
    /// Sequence number (for ordering and duplicate detection)
    pub sequence: u64,
    /// Magic bytes for packet validation
    pub magic: [u8; 4],
}

impl FecChunk {
    /// Serialize chunk to FIBRE packet format
    pub fn serialize(&self) -> Result<Vec<u8>, FibreProtocolError> {
        let mut packet = Vec::with_capacity(HEADER_SIZE + self.data.len() + 4);
        
        // Magic
        packet.extend_from_slice(&FIBRE_MAGIC);
        // Version
        packet.push(FIBRE_VERSION);
        // Type
        packet.push(PACKET_TYPE_CHUNK);
        // Block hash
        packet.extend_from_slice(&self.block_hash);
        // Sequence
        packet.extend_from_slice(&self.sequence.to_be_bytes());
        // Chunk index
        packet.extend_from_slice(&self.index.to_be_bytes());
        // Total chunks
        packet.extend_from_slice(&self.total_chunks.to_be_bytes());
        // Data chunks
        packet.extend_from_slice(&self.data_chunks.to_be_bytes());
        // Data length
        packet.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        // Data
        packet.extend_from_slice(&self.data);
        
        // Checksum (CRC32)
        let checksum = crc32fast::hash(&packet);
        packet.extend_from_slice(&checksum.to_be_bytes());
        
        Ok(packet)
    }
    
    /// Deserialize chunk from FIBRE packet format
    pub fn deserialize(data: &[u8]) -> Result<Self, FibreProtocolError> {
        // Validate minimum size
        if data.len() < HEADER_SIZE + 4 {
            return Err(FibreProtocolError::InvalidPacket("Packet too short".to_string()));
        }
        
        // Verify magic
        if &data[0..4] != &FIBRE_MAGIC {
            return Err(FibreProtocolError::InvalidPacket("Invalid magic bytes".to_string()));
        }
        
        // Verify checksum
        let received_checksum = u32::from_be_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        let calculated_checksum = crc32fast::hash(&data[..data.len() - 4]);
        if received_checksum != calculated_checksum {
            return Err(FibreProtocolError::InvalidPacket("Checksum mismatch".to_string()));
        }
        
        // Parse fields
        let version = data[4];
        if version != FIBRE_VERSION {
            return Err(FibreProtocolError::InvalidPacket(format!("Unsupported version: {}", version)));
        }
        
        let packet_type = data[5];
        if packet_type != PACKET_TYPE_CHUNK {
            return Err(FibreProtocolError::InvalidPacket(format!("Unexpected packet type: {}", packet_type)));
        }
        
        let block_hash: Hash = data[6..38].try_into()
            .map_err(|_| FibreProtocolError::InvalidPacket("Invalid block hash".to_string()))?;
        let sequence = u64::from_be_bytes(data[38..46].try_into().unwrap());
        let index = u32::from_be_bytes(data[46..50].try_into().unwrap());
        let total_chunks = u32::from_be_bytes(data[50..54].try_into().unwrap());
        let data_chunks = u32::from_be_bytes(data[54..58].try_into().unwrap());
        let data_length = u32::from_be_bytes(data[58..62].try_into().unwrap()) as usize;
        
        // Validate data length
        if data.len() < HEADER_SIZE + data_length + 4 {
            return Err(FibreProtocolError::InvalidPacket("Packet data length mismatch".to_string()));
        }
        
        // Extract data
        let chunk_data = data[62..62 + data_length].to_vec();
        let chunk_size = chunk_data.len();
        
        Ok(FecChunk {
            index,
            total_chunks,
            data_chunks,
            data: chunk_data,
            size: chunk_size,
            block_hash,
            sequence,
            magic: FIBRE_MAGIC,
        })
    }
}

/// FIBRE capabilities advertised by peers
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FibreCapabilities {
    /// Supports FEC encoding
    pub supports_fec: bool,
    /// Maximum chunk size
    pub max_chunk_size: usize,
    /// Minimum latency preference
    pub min_latency: bool,
}

impl Default for FibreCapabilities {
    fn default() -> Self {
        Self {
            supports_fec: true,
            max_chunk_size: DEFAULT_SHARD_SIZE,
            min_latency: true,
        }
    }
}

/// FIBRE protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FibreConfig {
    /// Enable FIBRE relay
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// FEC parity ratio (0.0-1.0, default: 0.2 = 20% parity)
    #[serde(default = "default_fec_parity_ratio")]
    pub fec_parity_ratio: f64,
    /// Chunk retransmission timeout (seconds)
    #[serde(default = "default_chunk_timeout")]
    pub chunk_timeout_secs: u64,
    /// Maximum retransmission attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Maximum concurrent block assemblies
    #[serde(default = "default_max_assemblies")]
    pub max_assemblies: usize,
}

fn default_true() -> bool { true }
fn default_fec_parity_ratio() -> f64 { 0.2 }
fn default_chunk_timeout() -> u64 { 2 }
fn default_max_retries() -> u32 { 3 }
fn default_max_assemblies() -> usize { 10 }

impl Default for FibreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fec_parity_ratio: 0.2,
            chunk_timeout_secs: 2,
            max_retries: 3,
            max_assemblies: 10,
        }
    }
}

/// FIBRE protocol errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum FibreProtocolError {
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fec_chunk_serialize_deserialize() {
        let chunk = FecChunk {
            index: 0,
            total_chunks: 10,
            data_chunks: 8,
            data: vec![1, 2, 3, 4, 5],
            size: 5,
            block_hash: [0x42; 32],
            sequence: 12345,
            magic: FIBRE_MAGIC,
        };
        
        let serialized = chunk.serialize().unwrap();
        assert!(serialized.len() >= HEADER_SIZE + 5 + 4);
        
        let deserialized = FecChunk::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.index, chunk.index);
        assert_eq!(deserialized.total_chunks, chunk.total_chunks);
        assert_eq!(deserialized.data_chunks, chunk.data_chunks);
        assert_eq!(deserialized.data, chunk.data);
        assert_eq!(deserialized.block_hash, chunk.block_hash);
        assert_eq!(deserialized.sequence, chunk.sequence);
    }
    
    #[test]
    fn test_fec_chunk_invalid_magic() {
        let mut data = vec![0u8; HEADER_SIZE + 4];
        data[0..4].copy_from_slice(&[0xFF; 4]); // Invalid magic
        
        let result = FecChunk::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic"));
    }
    
    #[test]
    fn test_fec_chunk_invalid_checksum() {
        let chunk = FecChunk {
            index: 0,
            total_chunks: 10,
            data_chunks: 8,
            data: vec![1, 2, 3],
            size: 3,
            block_hash: [0x42; 32],
            sequence: 12345,
            magic: FIBRE_MAGIC,
        };
        
        let serialized = chunk.serialize().unwrap();
        let mut corrupted = serialized.clone();
        // Corrupt checksum
        let last_idx = corrupted.len() - 1;
        corrupted[last_idx] ^= 0xFF;
        
        let result = FecChunk::deserialize(&corrupted);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Checksum"));
    }
    
    #[test]
    fn test_fibre_config_default() {
        let config = FibreConfig::default();
        assert!(config.enabled);
        assert_eq!(config.fec_parity_ratio, 0.2);
        assert_eq!(config.chunk_timeout_secs, 2);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.max_assemblies, 10);
    }
    
    #[test]
    fn test_fibre_capabilities_default() {
        let caps = FibreCapabilities::default();
        assert!(caps.supports_fec);
        assert_eq!(caps.max_chunk_size, DEFAULT_SHARD_SIZE);
        assert!(caps.min_latency);
    }
}

