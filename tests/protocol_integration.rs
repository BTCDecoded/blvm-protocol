//! Protocol integration tests
//!
//! End-to-end tests for protocol engine functionality

use consensus_proof::types::{OutPoint, TransactionInput, TransactionOutput, UTXO};
use consensus_proof::{Block, BlockHeader, Transaction, ValidationResult};
use protocol_engine::{BitcoinProtocolEngine, NetworkParameters, ProtocolVersion};
use std::collections::HashMap;

#[test]
fn test_end_to_end_protocol_engine_initialization() {
    // Test that we can create engines for all protocol versions
    let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
    let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();

    // Verify they have correct network parameters
    assert_eq!(mainnet.get_network_params().network_name, "mainnet");
    assert_eq!(testnet.get_network_params().network_name, "testnet");
    assert_eq!(regtest.get_network_params().network_name, "regtest");

    // Verify they support the same features
    assert!(mainnet.supports_feature("segwit"));
    assert!(testnet.supports_feature("segwit"));
    assert!(regtest.supports_feature("segwit"));
}

#[test]
fn test_full_block_validation_workflow() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let utxos = HashMap::new();

    // Create a simple block with coinbase transaction
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![0x01, 0x00], // Height 0
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // P2PKH
            }],
            lock_time: 0,
        }],
    };

    // Validate the block
    let result = engine.validate_block(&block, &utxos, 0);
    assert!(result.is_ok());
}

#[test]
fn test_multi_block_chain_validation() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let mut utxos = HashMap::new();

    // Create first block (genesis)
    let block1 = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![0x01, 0x00], // Height 0
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // P2PKH
            }],
            lock_time: 0,
        }],
    };

    // Validate first block
    let result1 = engine.validate_block(&block1, &utxos, 0);
    assert!(result1.is_ok());

    // Add UTXO from first block
    utxos.insert(
        OutPoint {
            hash: [0u8; 32],
            index: 0,
        },
        UTXO {
            value: 50_0000_0000,
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            height: 0,
        },
    );

    // Create second block
    let block2 = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32], // Would be hash of block1 in real scenario
            merkle_root: [0u8; 32],
            timestamp: 1231006506,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![0x41, 0x04], // Signature
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 25_0000_0000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // P2PKH
            }],
            lock_time: 0,
        }],
    };

    // Validate second block
    let result2 = engine.validate_block(&block2, &utxos, 1);
    assert!(result2.is_ok());
}

#[test]
fn test_transaction_creation_and_validation_workflow() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();

    // Create a transaction
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            script_sig: vec![0x41, 0x04], // Signature
            sequence: 0xffffffff,
        }],
        outputs: vec![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ], // P2PKH
        }],
        lock_time: 0,
    };

    // Validate the transaction
    let result = engine.validate_transaction(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_utxo_tracking_across_transactions() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let mut utxos = HashMap::new();

    // Add initial UTXO
    utxos.insert(
        OutPoint {
            hash: [0u8; 32],
            index: 0,
        },
        UTXO {
            value: 100_0000_0000,
            script_pubkey: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            height: 0,
        },
    );

    // Create transaction that spends the UTXO
    let tx = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            script_sig: vec![0x41, 0x04], // Signature
            sequence: 0xffffffff,
        }],
        outputs: vec![
            TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // P2PKH
            },
            TransactionOutput {
                value: 49_0000_0000, // Change output
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // P2PKH
            },
        ],
        lock_time: 0,
    };

    // Validate the transaction
    let result = engine.validate_transaction(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_protocol_switching_scenarios() {
    // Test that we can create engines for different protocols
    let mainnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    let testnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
    let regtest_engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();

    // All engines should support the same basic features
    assert!(mainnet_engine.supports_feature("segwit"));
    assert!(testnet_engine.supports_feature("segwit"));
    assert!(regtest_engine.supports_feature("segwit"));

    // But they should have different network parameters
    assert_ne!(
        mainnet_engine.get_network_params().magic_bytes,
        testnet_engine.get_network_params().magic_bytes
    );
    assert_ne!(
        testnet_engine.get_network_params().magic_bytes,
        regtest_engine.get_network_params().magic_bytes
    );
}

#[test]
fn test_concurrent_validation_requests() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap());
    let mut handles = vec![];

    // Create multiple threads that validate the same transaction
    for i in 0..5 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let tx = Transaction {
                version: 1,
                inputs: vec![TransactionInput {
                    prevout: OutPoint {
                        hash: [i as u8; 32],
                        index: 0,
                    },
                    script_sig: vec![0x41, 0x04],
                    sequence: 0xffffffff,
                }],
                outputs: vec![TransactionOutput {
                    value: 50_0000_0000,
                    script_pubkey: vec![
                        0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ],
                }],
                lock_time: 0,
            };

            engine_clone.validate_transaction(&tx)
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }
}
