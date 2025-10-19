//! Common test utilities for protocol-engine tests
//! 
//! This module provides shared test utilities for building test data,
//! creating mock objects, and setting up test scenarios.

use consensus_proof::{Block, Transaction, BlockHeader};
use consensus_proof::types::{OutPoint, UTXO, TxInput, TxOutput};
use crate::{BitcoinProtocolEngine, ProtocolVersion, NetworkParameters, NetworkConstants};
use std::collections::HashMap;

/// Test block builder with sensible defaults
pub struct TestBlockBuilder {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl TestBlockBuilder {
    pub fn new() -> Self {
        Self {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            transactions: vec![],
        }
    }
    
    pub fn with_version(mut self, version: i32) -> Self {
        self.header.version = version;
        self
    }
    
    pub fn with_prev_hash(mut self, hash: [u8; 32]) -> Self {
        self.header.prev_block_hash = hash;
        self
    }
    
    pub fn with_timestamp(mut self, timestamp: u32) -> Self {
        self.header.timestamp = timestamp;
        self
    }
    
    pub fn with_bits(mut self, bits: u32) -> Self {
        self.header.bits = bits;
        self
    }
    
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.header.nonce = nonce;
        self
    }
    
    pub fn add_transaction(mut self, tx: Transaction) -> Self {
        self.transactions.push(tx);
        self
    }
    
    pub fn add_coinbase_transaction(mut self, script_pubkey: Vec<u8>) -> Self {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0xffffffff,
                },
                script_sig: vec![0x01, 0x00], // Height 0
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOutput {
                value: 50_0000_0000, // 50 BTC in satoshis
                script_pubkey,
            }],
            locktime: 0,
        };
        self.transactions.push(coinbase);
        self
    }
    
    pub fn build(self) -> Block {
        Block {
            header: self.header,
            transactions: self.transactions,
        }
    }
}

/// Test transaction builder with configurable inputs/outputs
pub struct TestTransactionBuilder {
    version: i32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    locktime: u32,
}

impl TestTransactionBuilder {
    pub fn new() -> Self {
        Self {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
        }
    }
    
    pub fn with_version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }
    
    pub fn add_input(mut self, prevout: OutPoint, script_sig: Vec<u8>, sequence: u32) -> Self {
        self.inputs.push(TxInput {
            prevout,
            script_sig,
            sequence,
        });
        self
    }
    
    pub fn add_output(mut self, value: u64, script_pubkey: Vec<u8>) -> Self {
        self.outputs.push(TxOutput {
            value,
            script_pubkey,
        });
        self
    }
    
    pub fn with_locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }
    
    pub fn build(self) -> Transaction {
        Transaction {
            version: self.version,
            inputs: self.inputs,
            outputs: self.outputs,
            locktime: self.locktime,
        }
    }
}

/// UTXO set generator for testing
pub struct TestUtxoSetBuilder {
    utxos: HashMap<OutPoint, UTXO>,
}

impl TestUtxoSetBuilder {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
        }
    }
    
    pub fn add_utxo(mut self, outpoint: OutPoint, value: u64, script_pubkey: Vec<u8>) -> Self {
        self.utxos.insert(outpoint, UTXO {
            value,
            script_pubkey,
        });
        self
    }
    
    pub fn add_coinbase_utxo(mut self, tx_hash: [u8; 32], value: u64, script_pubkey: Vec<u8>) -> Self {
        self.utxos.insert(OutPoint { hash: tx_hash, index: 0 }, UTXO {
            value,
            script_pubkey,
        });
        self
    }
    
    pub fn build(self) -> HashMap<OutPoint, UTXO> {
        self.utxos
    }
}

/// Network parameter fixtures for testing
pub struct TestNetworkFixtures;

impl TestNetworkFixtures {
    pub fn mainnet_params() -> NetworkParameters {
        NetworkParameters::mainnet().unwrap()
    }
    
    pub fn testnet_params() -> NetworkParameters {
        NetworkParameters::testnet().unwrap()
    }
    
    pub fn regtest_params() -> NetworkParameters {
        NetworkParameters::regtest().unwrap()
    }
    
    pub fn mainnet_constants() -> NetworkConstants {
        NetworkConstants::mainnet().unwrap()
    }
    
    pub fn testnet_constants() -> NetworkConstants {
        NetworkConstants::testnet().unwrap()
    }
    
    pub fn regtest_constants() -> NetworkConstants {
        NetworkConstants::regtest().unwrap()
    }
}

/// Protocol engine fixtures for testing
pub struct TestProtocolFixtures;

impl TestProtocolFixtures {
    pub fn mainnet_engine() -> BitcoinProtocolEngine {
        BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap()
    }
    
    pub fn testnet_engine() -> BitcoinProtocolEngine {
        BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap()
    }
    
    pub fn regtest_engine() -> BitcoinProtocolEngine {
        BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap()
    }
}

/// Helper functions for creating test data
pub mod helpers {
    use super::*;
    
    /// Create a simple P2PKH script
    pub fn p2pkh_script(pubkey_hash: [u8; 20]) -> Vec<u8> {
        let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 20
        script.extend_from_slice(&pubkey_hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        script
    }
    
    /// Create a simple P2SH script
    pub fn p2sh_script(script_hash: [u8; 20]) -> Vec<u8> {
        let mut script = vec![0xa9, 0x14]; // OP_HASH160 20
        script.extend_from_slice(&script_hash);
        script.push(0x87); // OP_EQUAL
        script
    }
    
    /// Create a simple P2WPKH script
    pub fn p2wpkh_script(pubkey_hash: [u8; 20]) -> Vec<u8> {
        let mut script = vec![0x00, 0x14]; // OP_0 20
        script.extend_from_slice(&pubkey_hash);
        script
    }
    
    /// Create a simple P2WSH script
    pub fn p2wsh_script(script_hash: [u8; 32]) -> Vec<u8> {
        let mut script = vec![0x00, 0x20]; // OP_0 32
        script.extend_from_slice(&script_hash);
        script
    }
    
    /// Create a simple P2TR script
    pub fn p2tr_script(taproot_output: [u8; 32]) -> Vec<u8> {
        let mut script = vec![0x51, 0x20]; // OP_1 32
        script.extend_from_slice(&taproot_output);
        script
    }
    
    /// Generate a random 32-byte hash
    pub fn random_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = (i as u8).wrapping_add(42);
        }
        hash
    }
    
    /// Generate a random 20-byte hash
    pub fn random_hash20() -> [u8; 20] {
        let mut hash = [0u8; 20];
        for i in 0..20 {
            hash[i] = (i as u8).wrapping_add(42);
        }
        hash
    }
    
    /// Create a valid block header for testing
    pub fn valid_block_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: random_hash(),
            merkle_root: random_hash(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        }
    }
    
    /// Create a valid transaction for testing
    pub fn valid_transaction() -> Transaction {
        TestTransactionBuilder::new()
            .add_input(
                OutPoint { hash: random_hash(), index: 0 },
                vec![0x41, 0x04], // Simple signature
                0xffffffff,
            )
            .add_output(50_0000_0000, p2pkh_script(random_hash20()))
            .build()
    }
}





