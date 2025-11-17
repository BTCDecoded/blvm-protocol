//! Address Encoding Tests (BIP173/350/351)
//!
//! Comprehensive tests for Bech32 and Bech32m address encoding/decoding.
//!
//! BIP173: Bech32 encoding for SegWit addresses (bc1...)
//! BIP350: Bech32m encoding for Taproot addresses (bc1p...)
//! BIP351: Version 1 witness encoding for Taproot

use bllvm_protocol::address::{BitcoinAddress, AddressError, Network};

/// Test helper: Create a valid P2WPKH witness program (20 bytes)
fn create_p2wpkh_program() -> Vec<u8> {
    vec![0x75; 20]
}

/// Test helper: Create a valid P2WSH witness program (32 bytes)
fn create_p2wsh_program() -> Vec<u8> {
    vec![0x75; 32]
}

/// Test helper: Create a valid P2TR witness program (32 bytes)
fn create_p2tr_program() -> Vec<u8> {
    vec![0x75; 32]
}

// ============================================================================
// Phase 1: Basic Encoding Tests
// ============================================================================

#[test]
fn test_bech32_mainnet_p2wpkh_encoding() {
    // Test encoding mainnet P2WPKH address (Bech32)
    let program = create_p2wpkh_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 0, program).unwrap();
    let encoded = addr.encode().unwrap();
    
    assert!(encoded.starts_with("bc1"));
    assert_eq!(addr.witness_version, 0);
    assert_eq!(addr.witness_program.len(), 20);
    assert_eq!(addr.network, Network::Mainnet);
    assert_eq!(addr.address_type(), "P2WPKH");
}

#[test]
fn test_bech32m_mainnet_p2tr_encoding() {
    // Test encoding mainnet P2TR address (Bech32m)
    let program = create_p2tr_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 1, program).unwrap();
    let encoded = addr.encode().unwrap();
    
    assert!(encoded.starts_with("bc1p"));
    assert_eq!(addr.witness_version, 1);
    assert_eq!(addr.witness_program.len(), 32);
    assert_eq!(addr.network, Network::Mainnet);
    assert_eq!(addr.address_type(), "P2TR");
    assert!(addr.is_taproot());
}

#[test]
fn test_bech32_testnet_encoding() {
    // Test testnet addresses
    let program = create_p2wpkh_program();
    let addr = BitcoinAddress::new(Network::Testnet, 0, program).unwrap();
    let encoded = addr.encode().unwrap();
    
    assert!(encoded.starts_with("tb1"));
    assert_eq!(addr.network, Network::Testnet);
}

#[test]
fn test_bech32_regtest_encoding() {
    // Test regtest addresses
    let program = create_p2wpkh_program();
    let addr = BitcoinAddress::new(Network::Regtest, 0, program).unwrap();
    let encoded = addr.encode().unwrap();
    
    assert!(encoded.starts_with("bcrt1"));
    assert_eq!(addr.network, Network::Regtest);
}

#[test]
fn test_bech32_mainnet_p2wsh_encoding() {
    // Test encoding mainnet P2WSH address (Bech32)
    let program = create_p2wsh_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 0, program).unwrap();
    let encoded = addr.encode().unwrap();
    
    assert!(encoded.starts_with("bc1"));
    assert_eq!(addr.witness_version, 0);
    assert_eq!(addr.witness_program.len(), 32);
    assert_eq!(addr.address_type(), "P2WSH");
}

// ============================================================================
// Phase 2: Decoding Tests
// ============================================================================

#[test]
fn test_bech32_decoding_valid_address() {
    // Test decoding valid Bech32 address (roundtrip)
    let program = create_p2wpkh_program();
    let addr1 = BitcoinAddress::new(Network::Mainnet, 0, program.clone()).unwrap();
    let encoded = addr1.encode().unwrap();
    
    let addr2 = BitcoinAddress::decode(&encoded).unwrap();
    assert_eq!(addr2.network, Network::Mainnet);
    assert_eq!(addr2.witness_version, 0);
    assert_eq!(addr2.witness_program, program);
    assert_eq!(addr2.address_type(), "P2WPKH");
}

#[test]
fn test_bech32m_decoding_valid_address() {
    // Test decoding valid Bech32m address (roundtrip)
    let program = create_p2tr_program();
    let addr1 = BitcoinAddress::new(Network::Mainnet, 1, program.clone()).unwrap();
    let encoded = addr1.encode().unwrap();
    
    let addr2 = BitcoinAddress::decode(&encoded).unwrap();
    assert_eq!(addr2.network, Network::Mainnet);
    assert_eq!(addr2.witness_version, 1);
    assert_eq!(addr2.witness_program, program);
    assert!(addr2.is_taproot());
}

#[test]
fn test_address_roundtrip_encoding() {
    // Test encoding then decoding produces same result
    let program = create_p2wpkh_program();
    let addr1 = BitcoinAddress::new(Network::Mainnet, 0, program.clone()).unwrap();
    let addr_str = addr1.encode().unwrap();
    let addr2 = BitcoinAddress::decode(&addr_str).unwrap();
    
    assert_eq!(addr1.network, addr2.network);
    assert_eq!(addr1.witness_version, addr2.witness_version);
    assert_eq!(addr1.witness_program, addr2.witness_program);
}

#[test]
fn test_address_roundtrip_taproot() {
    // Test roundtrip for Taproot addresses
    let program = create_p2tr_program();
    let addr1 = BitcoinAddress::new(Network::Mainnet, 1, program.clone()).unwrap();
    let addr_str = addr1.encode().unwrap();
    let addr2 = BitcoinAddress::decode(&addr_str).unwrap();
    
    assert_eq!(addr1.network, addr2.network);
    assert_eq!(addr1.witness_version, addr2.witness_version);
    assert_eq!(addr1.witness_program, addr2.witness_program);
    assert!(addr2.is_taproot());
}

// ============================================================================
// Phase 3: Error Handling Tests
// ============================================================================

#[test]
fn test_bech32_decoding_invalid_hrp() {
    // Test error handling for invalid human-readable part
    // The bech32 library will fail to decode, but we check for InvalidHRP
    // after successful bech32 decode but with unrecognized HRP
    let invalid_addr = "invalid1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let result = BitcoinAddress::decode(invalid_addr);
    // The bech32 library may return InvalidEncoding for invalid HRP,
    // or InvalidHRP if it decodes but HRP is unrecognized
    assert!(result.is_err());
    // Check that it's either InvalidEncoding (from bech32) or InvalidHRP
    match result {
        Err(AddressError::InvalidHRP) | Err(AddressError::InvalidEncoding) => {},
        Err(e) => panic!("Unexpected error: {:?}", e),
        Ok(_) => panic!("Should have failed"),
    }
}

#[test]
fn test_invalid_witness_version() {
    // Test that witness version > 16 is rejected
    let program = create_p2wpkh_program();
    let result = BitcoinAddress::new(Network::Mainnet, 17, program);
    assert!(matches!(result, Err(AddressError::InvalidWitnessVersion)));
}

#[test]
fn test_invalid_witness_length_p2wpkh() {
    // Test that P2WPKH must be exactly 20 bytes
    let program = vec![0x75; 19]; // Wrong length
    let result = BitcoinAddress::new(Network::Mainnet, 0, program);
    assert!(matches!(result, Err(AddressError::InvalidWitnessLength)));
}

#[test]
fn test_invalid_witness_length_p2wsh() {
    // Test that P2WSH must be exactly 32 bytes (when using version 0)
    let program = vec![0x75; 31]; // Wrong length
    let result = BitcoinAddress::new(Network::Mainnet, 0, program);
    assert!(matches!(result, Err(AddressError::InvalidWitnessLength)));
}

#[test]
fn test_invalid_witness_length_taproot() {
    // Test that Taproot must be exactly 32 bytes
    let program = vec![0x75; 20]; // Wrong length for Taproot
    let result = BitcoinAddress::new(Network::Mainnet, 1, program);
    assert!(matches!(result, Err(AddressError::InvalidWitnessLength)));
}

#[test]
fn test_address_network_mismatch() {
    // Test that addresses from different networks produce different encodings
    let program = create_p2wpkh_program();
    let mainnet_addr = BitcoinAddress::new(Network::Mainnet, 0, program.clone()).unwrap();
    let testnet_addr = BitcoinAddress::new(Network::Testnet, 0, program).unwrap();
    
    let mainnet_encoded = mainnet_addr.encode().unwrap();
    let testnet_encoded = testnet_addr.encode().unwrap();
    
    assert_ne!(mainnet_encoded, testnet_encoded);
    assert!(mainnet_encoded.starts_with("bc1"));
    assert!(testnet_encoded.starts_with("tb1"));
}

// ============================================================================
// Phase 4: Address Type Detection Tests
// ============================================================================

#[test]
fn test_is_segwit_p2wpkh() {
    // Test is_segwit() for P2WPKH
    let program = create_p2wpkh_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 0, program).unwrap();
    assert!(addr.is_segwit());
    assert!(!addr.is_taproot());
}

#[test]
fn test_is_segwit_p2wsh() {
    // Test is_segwit() for P2WSH
    let program = create_p2wsh_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 0, program).unwrap();
    assert!(addr.is_segwit());
    assert!(!addr.is_taproot());
}

#[test]
fn test_is_taproot() {
    // Test is_taproot() for P2TR
    let program = create_p2tr_program();
    let addr = BitcoinAddress::new(Network::Mainnet, 1, program).unwrap();
    assert!(addr.is_taproot());
    assert!(!addr.is_segwit());
}

#[test]
fn test_address_type_detection() {
    // Test address_type() for all types
    let p2wpkh = BitcoinAddress::new(Network::Mainnet, 0, create_p2wpkh_program()).unwrap();
    assert_eq!(p2wpkh.address_type(), "P2WPKH");
    
    let p2wsh = BitcoinAddress::new(Network::Mainnet, 0, create_p2wsh_program()).unwrap();
    assert_eq!(p2wsh.address_type(), "P2WSH");
    
    let p2tr = BitcoinAddress::new(Network::Mainnet, 1, create_p2tr_program()).unwrap();
    assert_eq!(p2tr.address_type(), "P2TR");
}

// ============================================================================
// Phase 5: Network-Specific Tests
// ============================================================================

#[test]
fn test_network_hrp_values() {
    // Test HRP values for all networks
    assert_eq!(Network::Mainnet.hrp(), "bc");
    assert_eq!(Network::Testnet.hrp(), "tb");
    assert_eq!(Network::Regtest.hrp(), "bcrt");
}

#[test]
fn test_all_networks_p2wpkh() {
    // Test P2WPKH encoding for all networks
    let program = create_p2wpkh_program();
    
    let mainnet = BitcoinAddress::new(Network::Mainnet, 0, program.clone()).unwrap();
    let testnet = BitcoinAddress::new(Network::Testnet, 0, program.clone()).unwrap();
    let regtest = BitcoinAddress::new(Network::Regtest, 0, program).unwrap();
    
    assert!(mainnet.encode().unwrap().starts_with("bc1"));
    assert!(testnet.encode().unwrap().starts_with("tb1"));
    assert!(regtest.encode().unwrap().starts_with("bcrt1"));
}

#[test]
fn test_all_networks_p2tr() {
    // Test P2TR encoding for all networks
    let program = create_p2tr_program();
    
    let mainnet = BitcoinAddress::new(Network::Mainnet, 1, program.clone()).unwrap();
    let testnet = BitcoinAddress::new(Network::Testnet, 1, program.clone()).unwrap();
    let regtest = BitcoinAddress::new(Network::Regtest, 1, program).unwrap();
    
    assert!(mainnet.encode().unwrap().starts_with("bc1p"));
    assert!(testnet.encode().unwrap().starts_with("tb1p"));
    assert!(regtest.encode().unwrap().starts_with("bcrt1p"));
}

