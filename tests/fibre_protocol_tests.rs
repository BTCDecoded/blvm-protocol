//! FIBRE Protocol Comprehensive Tests
//!
//! Additional edge cases and error paths for FIBRE protocol.

use blvm_protocol::fibre::{
    FecChunk, FibreCapabilities, FibreConfig, FibreProtocolError, DEFAULT_SHARD_SIZE, FIBRE_MAGIC,
    HEADER_SIZE, MAX_DATA_SIZE,
};

#[test]
fn test_fec_chunk_edge_cases() {
    // Test edge cases for FEC chunk serialization/deserialization

    // Test with maximum data size
    let max_data = vec![0u8; MAX_DATA_SIZE];
    let chunk = FecChunk {
        index: 0,
        total_chunks: 10,
        data_chunks: 8,
        data: max_data.clone(),
        size: max_data.len(),
        block_hash: [0x42; 32],
        sequence: 12345,
        magic: FIBRE_MAGIC,
    };

    let serialized = chunk.serialize().unwrap();
    assert!(serialized.len() >= HEADER_SIZE + MAX_DATA_SIZE + 4);

    let deserialized = FecChunk::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.data.len(), MAX_DATA_SIZE);
}

#[test]
fn test_fec_chunk_empty_data() {
    // Test with empty data
    let chunk = FecChunk {
        index: 0,
        total_chunks: 1,
        data_chunks: 1,
        data: vec![],
        size: 0,
        block_hash: [0x42; 32],
        sequence: 12345,
        magic: FIBRE_MAGIC,
    };

    let serialized = chunk.serialize().unwrap();
    let deserialized = FecChunk::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.data.len(), 0);
}

#[test]
fn test_fec_chunk_invalid_version() {
    // Test deserialization with invalid version
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

    let mut serialized = chunk.serialize().unwrap();
    // Corrupt version byte (index 4)
    serialized[4] = 0xFF; // Invalid version

    let result = FecChunk::deserialize(&serialized);
    assert!(result.is_err());
    // Error message may vary, just verify it's an error
}

#[test]
fn test_fec_chunk_invalid_packet_type() {
    // Test deserialization with invalid packet type
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

    let mut serialized = chunk.serialize().unwrap();
    // Corrupt packet type byte (index 5)
    serialized[5] = 0xFF; // Invalid packet type

    let result = FecChunk::deserialize(&serialized);
    assert!(result.is_err());
}

#[test]
fn test_fec_chunk_data_length_mismatch() {
    // Test deserialization with data length mismatch
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

    let mut serialized = chunk.serialize().unwrap();
    // Corrupt data length field (bytes 58-62)
    serialized[58] = 0xFF;
    serialized[59] = 0xFF;
    serialized[60] = 0xFF;
    serialized[61] = 0xFF; // Set to invalid length

    let result = FecChunk::deserialize(&serialized);
    assert!(result.is_err());
}

#[test]
fn test_fec_chunk_too_short() {
    // Test deserialization with packet too short
    let short_data = vec![0u8; HEADER_SIZE + 3]; // One byte short

    let result = FecChunk::deserialize(&short_data);
    assert!(result.is_err());
    if let Err(FibreProtocolError::InvalidPacket(msg)) = result {
        assert!(msg.contains("short") || msg.contains("length"));
    }
}

#[test]
fn test_fibre_config_edge_cases() {
    // Test FibreConfig with edge case values

    // Test with zero parity ratio
    let config = FibreConfig {
        enabled: true,
        fec_parity_ratio: 0.0,
        chunk_timeout_secs: 1,
        max_retries: 1,
        max_assemblies: 1,
    };
    assert_eq!(config.fec_parity_ratio, 0.0);

    // Test with maximum parity ratio
    let config = FibreConfig {
        enabled: true,
        fec_parity_ratio: 1.0,
        chunk_timeout_secs: 100,
        max_retries: 10,
        max_assemblies: 100,
    };
    assert_eq!(config.fec_parity_ratio, 1.0);
}

#[test]
fn test_fibre_capabilities_edge_cases() {
    // Test FibreCapabilities with different configurations

    let caps1 = FibreCapabilities {
        supports_fec: true,
        max_chunk_size: DEFAULT_SHARD_SIZE,
        min_latency: true,
    };
    assert!(caps1.supports_fec);

    let caps2 = FibreCapabilities {
        supports_fec: false,
        max_chunk_size: 1000,
        min_latency: false,
    };
    assert!(!caps2.supports_fec);
    assert_eq!(caps2.max_chunk_size, 1000);
}

#[test]
fn test_fec_chunk_index_boundaries() {
    // Test FEC chunk with boundary index values

    // First chunk
    let chunk1 = FecChunk {
        index: 0,
        total_chunks: 10,
        data_chunks: 8,
        data: vec![1, 2, 3],
        size: 3,
        block_hash: [0x42; 32],
        sequence: 12345,
        magic: FIBRE_MAGIC,
    };
    let serialized1 = chunk1.serialize().unwrap();
    let deserialized1 = FecChunk::deserialize(&serialized1).unwrap();
    assert_eq!(deserialized1.index, 0);

    // Last chunk
    let chunk2 = FecChunk {
        index: 9,
        total_chunks: 10,
        data_chunks: 8,
        data: vec![1, 2, 3],
        size: 3,
        block_hash: [0x42; 32],
        sequence: 12345,
        magic: FIBRE_MAGIC,
    };
    let serialized2 = chunk2.serialize().unwrap();
    let deserialized2 = FecChunk::deserialize(&serialized2).unwrap();
    assert_eq!(deserialized2.index, 9);
}

#[test]
fn test_fec_chunk_sequence_numbers() {
    // Test FEC chunk with different sequence numbers

    let chunk1 = FecChunk {
        index: 0,
        total_chunks: 10,
        data_chunks: 8,
        data: vec![1, 2, 3],
        size: 3,
        block_hash: [0x42; 32],
        sequence: 0,
        magic: FIBRE_MAGIC,
    };
    let serialized1 = chunk1.serialize().unwrap();
    let deserialized1 = FecChunk::deserialize(&serialized1).unwrap();
    assert_eq!(deserialized1.sequence, 0);

    let chunk2 = FecChunk {
        index: 0,
        total_chunks: 10,
        data_chunks: 8,
        data: vec![1, 2, 3],
        size: 3,
        block_hash: [0x42; 32],
        sequence: u64::MAX,
        magic: FIBRE_MAGIC,
    };
    let serialized2 = chunk2.serialize().unwrap();
    let deserialized2 = FecChunk::deserialize(&serialized2).unwrap();
    assert_eq!(deserialized2.sequence, u64::MAX);
}
