//! Bitcoin Protocol Engine
//! 
//! This crate provides a Bitcoin protocol abstraction layer that enables:
//! - Multiple Bitcoin variants (mainnet, testnet, regtest, educational)
//! - Protocol evolution support (Bitcoin V1, V2, etc.)
//! - Economic model abstraction (PoW, future variants)
//! - Educational and research-friendly interfaces
//! 
//! This is Tier 3 of the 5-tier BTCDecoded architecture:
//! 
//! 1. Orange Paper (mathematical foundation)
//! 2. consensus-proof (pure math implementation)
//! 3. protocol-engine (Bitcoin abstraction) ← THIS CRATE
//! 4. reference-node (full Bitcoin node)
//! 5. developer-sdk (ergonomic API)

use consensus_proof::{ConsensusProof, Result, ValidationResult, Block, Transaction};
use serde::{Deserialize, Serialize};

// Re-export feature and economic modules for convenience
pub use features::{FeatureActivation, FeatureRegistry, ActivationMethod, FeatureContext};
pub use economic::EconomicParameters;

pub mod variants;
pub mod validation;
pub mod network_params;
pub mod genesis;
pub mod features;
pub mod economic;

/// Bitcoin Protocol Engine
/// 
/// Provides protocol abstraction for different Bitcoin variants and evolution.
/// Acts as a bridge between consensus-proof (pure math) and reference-node (implementation).
pub struct BitcoinProtocolEngine {
    consensus: ConsensusProof,
    protocol_version: ProtocolVersion,
    network_params: NetworkParameters,
}

/// Bitcoin protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// Current Bitcoin mainnet protocol
    BitcoinV1,
    /// Bitcoin testnet protocol
    Testnet3,
    /// Regression test network protocol
    Regtest,
}

/// Network parameters for different Bitcoin variants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkParameters {
    /// Network magic bytes for P2P protocol
    pub magic_bytes: [u8; 4],
    /// Default P2P port
    pub default_port: u16,
    /// Genesis block for this network
    pub genesis_block: Block,
    /// Maximum proof-of-work target
    pub max_target: u32,
    /// Block subsidy halving interval
    pub halving_interval: u64,
    /// Network name for identification
    pub network_name: String,
    /// Whether this is a test network
    pub is_testnet: bool,
}

impl BitcoinProtocolEngine {
    /// Create a new protocol engine for the specified variant
    pub fn new(version: ProtocolVersion) -> Result<Self> {
        let consensus = ConsensusProof::new();
        let network_params = NetworkParameters::for_version(version)?;
        
        Ok(BitcoinProtocolEngine {
            consensus,
            protocol_version: version,
            network_params,
        })
    }
    
    /// Get the current protocol version
    pub fn get_protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
    
    /// Get network parameters for this protocol
    pub fn get_network_params(&self) -> &NetworkParameters {
        &self.network_params
    }
    
    /// Validate a block using this protocol's rules
    pub fn validate_block(&self, block: &Block, utxos: &std::collections::HashMap<consensus_proof::types::OutPoint, consensus_proof::types::UTXO>, height: u64) -> Result<ValidationResult> {
        let (result, _) = self.consensus.validate_block(block, utxos.clone(), height)?;
        Ok(result)
    }
    
    /// Validate a transaction using this protocol's rules
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<ValidationResult> {
        self.consensus.validate_transaction(tx)
    }
    
    /// Check if this protocol supports a specific feature
    pub fn supports_feature(&self, feature: &str) -> bool {
        match self.protocol_version {
            ProtocolVersion::BitcoinV1 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Testnet3 => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv")
            }
            ProtocolVersion::Regtest => {
                matches!(feature, "segwit" | "taproot" | "rbf" | "ctv" | "fast_mining")
            }
        }
    }
    
    /// Check if a feature is active at a specific block height and timestamp
    pub fn is_feature_active(&self, feature: &str, height: u64, timestamp: u64) -> bool {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.is_feature_active(feature, height, timestamp)
    }
    
    /// Get economic parameters for this protocol
    pub fn get_economic_parameters(&self) -> economic::EconomicParameters {
        economic::EconomicParameters::for_protocol(self.protocol_version)
    }
    
    /// Get feature activation registry for this protocol
    pub fn get_feature_registry(&self) -> features::FeatureRegistry {
        features::FeatureRegistry::for_protocol(self.protocol_version)
    }
    
    /// Create a feature context for a specific block height and timestamp
    /// This consolidates all feature activation checks into a single context
    pub fn feature_context(&self, height: u64, timestamp: u64) -> features::FeatureContext {
        let registry = features::FeatureRegistry::for_protocol(self.protocol_version);
        registry.create_context(height, timestamp)
    }
}

impl NetworkParameters {
    /// Create network parameters for a specific protocol version
    pub fn for_version(version: ProtocolVersion) -> Result<Self> {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
        }
    }
    
    /// Bitcoin mainnet parameters
    pub fn mainnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xf9, 0xbe, 0xb4, 0xd9], // Bitcoin mainnet magic
            default_port: 8333,
            genesis_block: genesis::mainnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "mainnet".to_string(),
            is_testnet: false,
        })
    }
    
    /// Bitcoin testnet parameters
    pub fn testnet() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0x0b, 0x11, 0x09, 0x07], // Bitcoin testnet magic
            default_port: 18333,
            genesis_block: genesis::testnet_genesis(),
            max_target: 0x1d00ffff,
            halving_interval: 210000,
            network_name: "testnet".to_string(),
            is_testnet: true,
        })
    }
    
    /// Bitcoin regtest parameters
    pub fn regtest() -> Result<Self> {
        Ok(NetworkParameters {
            magic_bytes: [0xfa, 0xbf, 0xb5, 0xda], // Bitcoin regtest magic
            default_port: 18444,
            genesis_block: genesis::regtest_genesis(),
            max_target: 0x207fffff, // Easier difficulty for testing
            halving_interval: 150, // Faster halving for testing
            network_name: "regtest".to_string(),
            is_testnet: true,
        })
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use consensus_proof::types::{BlockHeader, TransactionInput, TransactionOutput, OutPoint};
    
    #[test]
    fn test_protocol_engine_creation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(engine.get_protocol_version(), ProtocolVersion::BitcoinV1);
        assert_eq!(engine.get_network_params().network_name, "mainnet");
    }
    
    #[test]
    fn test_protocol_engine_creation_all_variants() {
        // Test mainnet
        let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert_eq!(mainnet.get_protocol_version(), ProtocolVersion::BitcoinV1);
        assert_eq!(mainnet.get_network_params().network_name, "mainnet");
        assert!(!mainnet.get_network_params().is_testnet);
        
        // Test testnet
        let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
        assert_eq!(testnet.get_protocol_version(), ProtocolVersion::Testnet3);
        assert_eq!(testnet.get_network_params().network_name, "testnet");
        assert!(testnet.get_network_params().is_testnet);
        
        // Test regtest
        let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
        assert_eq!(regtest.get_protocol_version(), ProtocolVersion::Regtest);
        assert_eq!(regtest.get_network_params().network_name, "regtest");
        assert!(regtest.get_network_params().is_testnet);
    }
    
    #[test]
    fn test_network_parameters() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        assert_eq!(mainnet.magic_bytes, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(mainnet.default_port, 8333);
        assert!(!mainnet.is_testnet);
        
        let testnet = NetworkParameters::testnet().unwrap();
        assert_eq!(testnet.magic_bytes, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(testnet.default_port, 18333);
        assert!(testnet.is_testnet);
        
        let regtest = NetworkParameters::regtest().unwrap();
        assert_eq!(regtest.magic_bytes, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!(regtest.default_port, 18444);
        assert!(regtest.is_testnet);
    }
    
    #[test]
    fn test_network_parameters_consistency() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        assert_eq!(mainnet.max_target, 0x1d00ffff);
        assert_eq!(mainnet.halving_interval, 210000);
        
        let testnet = NetworkParameters::testnet().unwrap();
        assert_eq!(testnet.max_target, 0x1d00ffff);
        assert_eq!(testnet.halving_interval, 210000);
        
        let regtest = NetworkParameters::regtest().unwrap();
        assert_eq!(regtest.max_target, 0x207fffff); // Easier difficulty
        assert_eq!(regtest.halving_interval, 150); // Faster halving
    }
    
    #[test]
    fn test_feature_support() {
        let mainnet = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        assert!(mainnet.supports_feature("segwit"));
        assert!(mainnet.supports_feature("taproot"));
        assert!(mainnet.supports_feature("rbf"));
        assert!(mainnet.supports_feature("ctv"));
        assert!(!mainnet.supports_feature("fast_mining"));
        assert!(!mainnet.supports_feature("nonexistent"));
        
        let testnet = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
        assert!(testnet.supports_feature("segwit"));
        assert!(testnet.supports_feature("taproot"));
        assert!(testnet.supports_feature("rbf"));
        assert!(testnet.supports_feature("ctv"));
        assert!(!testnet.supports_feature("fast_mining"));
        
        let regtest = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
        assert!(regtest.supports_feature("segwit"));
        assert!(regtest.supports_feature("taproot"));
        assert!(regtest.supports_feature("rbf"));
        assert!(regtest.supports_feature("ctv"));
        assert!(regtest.supports_feature("fast_mining"));
    }
    
    #[test]
    fn test_block_validation_empty_utxos() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let utxos = HashMap::new();
        
        // Create a simple block with just a coinbase transaction
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
                    prevout: OutPoint { hash: [0u8; 32], index: 0xffffffff },
                    script_sig: vec![0x01, 0x00], // Height 0
                    sequence: 0xffffffff,
                }],
                outputs: vec![TransactionOutput {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // P2PKH
                }],
                lock_time: 0,
            }],
        };
        
        // This should pass validation for a genesis block
        let result = engine.validate_block(&block, &utxos, 0);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_transaction_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        
        // Create a simple transaction
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint { hash: [0u8; 32], index: 0 },
                script_sig: vec![0x41, 0x04], // Simple signature
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // P2PKH
            }],
            lock_time: 0,
        };
        
        let result = engine.validate_transaction(&tx);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_cross_protocol_validation() {
        let mainnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let testnet_engine = BitcoinProtocolEngine::new(ProtocolVersion::Testnet3).unwrap();
        
        // Both engines should support the same features
        assert_eq!(
            mainnet_engine.supports_feature("segwit"),
            testnet_engine.supports_feature("segwit")
        );
        assert_eq!(
            mainnet_engine.supports_feature("taproot"),
            testnet_engine.supports_feature("taproot")
        );
        
        // But they should have different network parameters
        assert_ne!(
            mainnet_engine.get_network_params().magic_bytes,
            testnet_engine.get_network_params().magic_bytes
        );
        assert_ne!(
            mainnet_engine.get_network_params().default_port,
            testnet_engine.get_network_params().default_port
        );
    }
    
    #[test]
    fn test_protocol_version_switching() {
        // Test that we can create engines for different protocol versions
        let versions = vec![
            ProtocolVersion::BitcoinV1,
            ProtocolVersion::Testnet3,
            ProtocolVersion::Regtest,
        ];
        
        for version in versions {
            let engine = BitcoinProtocolEngine::new(version).unwrap();
            assert_eq!(engine.get_protocol_version(), version);
        }
    }
    
    #[test]
    fn test_network_parameters_serialization() {
        let mainnet = NetworkParameters::mainnet().unwrap();
        let testnet = NetworkParameters::testnet().unwrap();
        let regtest = NetworkParameters::regtest().unwrap();
        
        // Test that parameters can be serialized and deserialized
        let mainnet_json = serde_json::to_string(&mainnet).unwrap();
        let mainnet_deserialized: NetworkParameters = serde_json::from_str(&mainnet_json).unwrap();
        assert_eq!(mainnet.magic_bytes, mainnet_deserialized.magic_bytes);
        assert_eq!(mainnet.default_port, mainnet_deserialized.default_port);
        assert_eq!(mainnet.network_name, mainnet_deserialized.network_name);
        assert_eq!(mainnet.is_testnet, mainnet_deserialized.is_testnet);
        
        let testnet_json = serde_json::to_string(&testnet).unwrap();
        let testnet_deserialized: NetworkParameters = serde_json::from_str(&testnet_json).unwrap();
        assert_eq!(testnet.magic_bytes, testnet_deserialized.magic_bytes);
        
        let regtest_json = serde_json::to_string(&regtest).unwrap();
        let regtest_deserialized: NetworkParameters = serde_json::from_str(&regtest_json).unwrap();
        assert_eq!(regtest.magic_bytes, regtest_deserialized.magic_bytes);
    }
    
    #[test]
    fn test_protocol_version_serialization() {
        let versions = vec![
            ProtocolVersion::BitcoinV1,
            ProtocolVersion::Testnet3,
            ProtocolVersion::Regtest,
        ];
        
        for version in versions {
            let json = serde_json::to_string(&version).unwrap();
            let deserialized: ProtocolVersion = serde_json::from_str(&json).unwrap();
            assert_eq!(version, deserialized);
        }
    }
    
    #[test]
    fn test_network_parameters_equality() {
        let mainnet1 = NetworkParameters::mainnet().unwrap();
        let mainnet2 = NetworkParameters::mainnet().unwrap();
        let testnet = NetworkParameters::testnet().unwrap();
        
        assert_eq!(mainnet1, mainnet2);
        assert_ne!(mainnet1, testnet);
    }
    
    #[test]
    fn test_protocol_version_equality() {
        assert_eq!(ProtocolVersion::BitcoinV1, ProtocolVersion::BitcoinV1);
        assert_ne!(ProtocolVersion::BitcoinV1, ProtocolVersion::Testnet3);
        assert_ne!(ProtocolVersion::Testnet3, ProtocolVersion::Regtest);
    }
    
    #[test]
    fn test_feature_activation_by_height() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        
        // SegWit activates at block 481,824
        assert!(!engine.is_feature_active("segwit", 481_823, 1503539000));
        assert!(engine.is_feature_active("segwit", 481_824, 1503539857));
        assert!(engine.is_feature_active("segwit", 500_000, 1504000000));
        
        // Taproot activates at block 709,632
        assert!(!engine.is_feature_active("taproot", 709_631, 1636934000));
        assert!(engine.is_feature_active("taproot", 709_632, 1636934400));
        assert!(engine.is_feature_active("taproot", 800_000, 1640000000));
    }
    
    #[test]
    fn test_economic_parameters_access() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let params = engine.get_economic_parameters();
        
        assert_eq!(params.initial_subsidy, 50_0000_0000);
        assert_eq!(params.halving_interval, 210_000);
        assert_eq!(params.coinbase_maturity, 100);
        
        // Test block subsidy calculation
        assert_eq!(params.get_block_subsidy(0), 50_0000_0000);
        assert_eq!(params.get_block_subsidy(210_000), 25_0000_0000);
    }
    
    #[test]
    fn test_feature_registry_access() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let registry = engine.get_feature_registry();
        
        assert!(registry.get_feature("segwit").is_some());
        assert!(registry.get_feature("taproot").is_some());
        assert!(registry.get_feature("nonexistent").is_none());
        
        let features = registry.list_features();
        assert!(features.contains(&"segwit".to_string()));
        assert!(features.contains(&"taproot".to_string()));
    }
}
