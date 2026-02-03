//! Variable-length integer encoding (Bitcoin protocol)
//!
//! Bitcoin uses a variable-length integer encoding where:
//! - Values < 0xfd: encoded as single byte
//! - Values < 0xffff: encoded as 0xfd + 2 bytes (little-endian)
//! - Values < 0xffffffff: encoded as 0xfe + 4 bytes (little-endian)
//! - Values >= 0xffffffff: encoded as 0xff + 8 bytes (little-endian)

use crate::Result;
use crate::ConsensusError;
use std::io::{Read, Write};

/// Maximum value for a varint (2^64 - 1)
pub const MAX_VARINT: u64 = u64::MAX;

/// Read a variable-length integer from bytes
pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 1];
    reader
        .read_exact(&mut buf)
        .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
    let first_byte = buf[0];

    match first_byte {
        0xfd => {
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            reader
                .read_exact(&mut buf)
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(u64::from_le_bytes(buf))
        }
        _ => Ok(first_byte as u64),
    }
}

/// Write a variable-length integer to bytes
pub fn write_varint<W: Write>(writer: &mut W, value: u64) -> Result<usize> {
    match value {
        0..=0xfc => {
            writer
                .write_all(&[value as u8])
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(1)
        }
        0xfd..=0xffff => {
            writer
                .write_all(&[0xfd])
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            writer
                .write_all(&(value as u16).to_le_bytes())
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(3)
        }
        0x10000..=0xffff_ffff => {
            writer
                .write_all(&[0xfe])
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            writer
                .write_all(&(value as u32).to_le_bytes())
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(5)
        }
        _ => {
            writer
                .write_all(&[0xff])
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            writer
                .write_all(&value.to_le_bytes())
                .map_err(|e| ConsensusError::Serialization(format!("IO error: {e}").into()))?;
            Ok(9)
        }
    }
}

/// Get the encoded size of a varint without writing it
pub fn varint_size(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = vec![
            0,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ];

        for value in test_values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();
            let mut cursor = Cursor::new(&buf);
            let decoded = read_varint(&mut cursor).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(0xfc), 1);
        assert_eq!(varint_size(0xfd), 3);
        assert_eq!(varint_size(0xffff), 3);
        assert_eq!(varint_size(0x10000), 5);
        assert_eq!(varint_size(0xffff_ffff), 5);
        assert_eq!(varint_size(0x1_0000_0000), 9);
        assert_eq!(varint_size(u64::MAX), 9);
    }
}
