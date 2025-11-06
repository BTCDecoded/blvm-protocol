//! Protocol validation interface
//!
//! This module provides protocol-specific validation that extends
//! the pure mathematical consensus rules with network-specific
//! and protocol-specific validation logic.

use crate::{BitcoinProtocolEngine, NetworkParameters, ProtocolVersion, Result};
use consensus_proof::types::{OutPoint, UTXO};
use consensus_proof::{Block, Transaction, ValidationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol-specific validation rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolValidationRules {
    /// Maximum block size for this protocol
    pub max_block_size: u32,
    /// Maximum transaction size for this protocol
    pub max_tx_size: u32,
    /// Maximum script size for this protocol
    pub max_script_size: u32,
    /// Whether SegWit is enabled
    pub segwit_enabled: bool,
    /// Whether Taproot is enabled
    pub taproot_enabled: bool,
    /// Whether RBF (Replace-By-Fee) is enabled
    pub rbf_enabled: bool,
    /// Minimum transaction fee rate
    pub min_fee_rate: u64,
    /// Maximum transaction fee rate
    pub max_fee_rate: u64,
}

impl ProtocolValidationRules {
    /// Get validation rules for a specific protocol version
    pub fn for_protocol(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::BitcoinV1 => Self::mainnet(),
            ProtocolVersion::Testnet3 => Self::testnet(),
            ProtocolVersion::Regtest => Self::regtest(),
        }
    }

    /// Mainnet validation rules (strict production rules)
    pub fn mainnet() -> Self {
        Self {
            max_block_size: 4_000_000, // 4MB block size limit
            max_tx_size: 1_000_000,    // 1MB transaction size limit
            max_script_size: 10_000,   // 10KB script size limit
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 1,         // 1 sat/vB minimum
            max_fee_rate: 1_000_000, // 1M sat/vB maximum
        }
    }

    /// Testnet validation rules (same as mainnet but with testnet parameters)
    pub fn testnet() -> Self {
        Self {
            max_block_size: 4_000_000,
            max_tx_size: 1_000_000,
            max_script_size: 10_000,
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 1,
            max_fee_rate: 1_000_000,
        }
    }

    /// Regtest validation rules (relaxed for testing)
    pub fn regtest() -> Self {
        Self {
            max_block_size: 4_000_000,
            max_tx_size: 1_000_000,
            max_script_size: 10_000,
            segwit_enabled: true,
            taproot_enabled: true,
            rbf_enabled: true,
            min_fee_rate: 0, // No minimum fee for testing
            max_fee_rate: 1_000_000,
        }
    }
}

/// Protocol-specific validation context
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolValidationContext {
    /// Current block height
    pub block_height: u64,
    /// Current network parameters
    pub network_params: NetworkParameters,
    /// Protocol validation rules
    pub validation_rules: ProtocolValidationRules,
    /// Additional context data
    pub context_data: HashMap<String, String>,
}

impl ProtocolValidationContext {
    /// Create validation context for a protocol version
    pub fn new(version: ProtocolVersion, block_height: u64) -> Result<Self> {
        let network_params = NetworkParameters::for_version(version)?;
        let validation_rules = ProtocolValidationRules::for_protocol(version);

        Ok(Self {
            block_height,
            network_params,
            validation_rules,
            context_data: HashMap::new(),
        })
    }

    /// Check if a feature is enabled at current block height
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "segwit" => self.validation_rules.segwit_enabled,
            "taproot" => self.validation_rules.taproot_enabled,
            "rbf" => self.validation_rules.rbf_enabled,
            _ => false,
        }
    }

    /// Get maximum allowed size for a component
    pub fn get_max_size(&self, component: &str) -> u32 {
        match component {
            "block" => self.validation_rules.max_block_size,
            "transaction" => self.validation_rules.max_tx_size,
            "script" => self.validation_rules.max_script_size,
            _ => 0,
        }
    }
}

impl BitcoinProtocolEngine {
    /// Validate a block with protocol-specific rules
    pub fn validate_block_with_protocol(
        &self,
        block: &Block,
        utxos: &HashMap<OutPoint, UTXO>,
        height: u64,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        // First, run consensus validation
        let (consensus_result, _) = self
            .consensus
            .validate_block(block, utxos.clone(), height)?;

        // Then, apply protocol-specific validation
        self.apply_protocol_validation(block, context)?;

        Ok(consensus_result)
    }

    /// Validate a transaction with protocol-specific rules
    pub fn validate_transaction_with_protocol(
        &self,
        tx: &Transaction,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        // First, run consensus validation
        let consensus_result = self.consensus.validate_transaction(tx)?;

        // Then, apply protocol-specific validation
        self.apply_transaction_protocol_validation(tx, context)?;

        Ok(consensus_result)
    }

    /// Apply protocol-specific validation rules
    fn apply_protocol_validation(
        &self,
        block: &Block,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        // Check block size limits
        let block_size = self.calculate_block_size(block);
        if block_size > context.validation_rules.max_block_size {
            return Err(consensus_proof::error::ConsensusError::BlockValidation(
                "Block size exceeds maximum".to_string(),
            ));
        }

        // Check transaction count limits
        if block.transactions.len() > 10000 {
            // Reasonable limit
            return Err(consensus_proof::error::ConsensusError::BlockValidation(
                "Too many transactions in block".to_string(),
            ));
        }

        // Validate each transaction with protocol rules
        for tx in &block.transactions {
            self.apply_transaction_protocol_validation(tx, context)?;
        }

        Ok(())
    }

    /// Apply protocol-specific transaction validation
    fn apply_transaction_protocol_validation(
        &self,
        tx: &Transaction,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        // Check transaction size limits
        let tx_size = self.calculate_transaction_size(tx);
        if tx_size > context.validation_rules.max_tx_size {
            return Err(
                consensus_proof::error::ConsensusError::TransactionValidation(
                    "Transaction size exceeds maximum".to_string(),
                ),
            );
        }

        // Check script size limits
        for input in &tx.inputs {
            if input.script_sig.len() > context.validation_rules.max_script_size as usize {
                return Err(
                    consensus_proof::error::ConsensusError::TransactionValidation(
                        "Script size exceeds maximum".to_string(),
                    ),
                );
            }
        }

        for output in &tx.outputs {
            if output.script_pubkey.len() > context.validation_rules.max_script_size as usize {
                return Err(
                    consensus_proof::error::ConsensusError::TransactionValidation(
                        "Script size exceeds maximum".to_string(),
                    ),
                );
            }
        }

        Ok(())
    }

    /// Calculate block size in bytes
    fn calculate_block_size(&self, block: &Block) -> u32 {
        // Simplified size calculation
        // In reality, this would include proper serialization
        let header_size = 80; // Block header is always 80 bytes
        let tx_count_size = 4; // Varint for transaction count
        let tx_sizes: u32 = block
            .transactions
            .iter()
            .map(|tx| self.calculate_transaction_size(tx))
            .sum();

        header_size + tx_count_size + tx_sizes
    }

    /// Calculate transaction size in bytes
    fn calculate_transaction_size(&self, tx: &Transaction) -> u32 {
        // Simplified size calculation
        let version_size = 4;
        let input_count_size = 4;
        let output_count_size = 4;
        let locktime_size = 4;

        let input_sizes: u32 = tx
            .inputs
            .iter()
            .map(|input| {
                32 + // prevout hash
                4 +  // prevout index
                input.script_sig.len() as u32 +
                4 // sequence
            })
            .sum();

        let output_sizes: u32 = tx
            .outputs
            .iter()
            .map(|output| {
                8 + // value
                output.script_pubkey.len() as u32
            })
            .sum();

        version_size
            + input_count_size
            + input_sizes
            + output_count_size
            + output_sizes
            + locktime_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_proof::types::{OutPoint, TransactionInput, TransactionOutput};
    use consensus_proof::{Block, BlockHeader, Transaction};
    use std::collections::HashMap;

    #[test]
    fn test_validation_rules() {
        let mainnet_rules = ProtocolValidationRules::mainnet();
        assert_eq!(mainnet_rules.max_block_size, 4_000_000);
        assert!(mainnet_rules.segwit_enabled);
        assert!(mainnet_rules.taproot_enabled);

        let regtest_rules = ProtocolValidationRules::regtest();
        assert_eq!(regtest_rules.max_block_size, 4_000_000);
        assert!(regtest_rules.segwit_enabled);
        assert_eq!(regtest_rules.min_fee_rate, 0); // No minimum fee for testing
    }

    #[test]
    fn test_validation_rules_all_protocols() {
        let mainnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::BitcoinV1);
        let testnet_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Testnet3);
        let regtest_rules = ProtocolValidationRules::for_protocol(ProtocolVersion::Regtest);

        // Mainnet and testnet should have same rules
        assert_eq!(mainnet_rules.max_block_size, testnet_rules.max_block_size);
        assert_eq!(mainnet_rules.max_tx_size, testnet_rules.max_tx_size);
        assert_eq!(mainnet_rules.max_script_size, testnet_rules.max_script_size);
        assert_eq!(mainnet_rules.segwit_enabled, testnet_rules.segwit_enabled);
        assert_eq!(mainnet_rules.taproot_enabled, testnet_rules.taproot_enabled);
        assert_eq!(mainnet_rules.rbf_enabled, testnet_rules.rbf_enabled);
        assert_eq!(mainnet_rules.min_fee_rate, testnet_rules.min_fee_rate);
        assert_eq!(mainnet_rules.max_fee_rate, testnet_rules.max_fee_rate);

        // Regtest should have relaxed fee rules
        assert_eq!(regtest_rules.min_fee_rate, 0);
        assert_eq!(regtest_rules.max_fee_rate, mainnet_rules.max_fee_rate);
    }

    #[test]
    fn test_validation_rules_serialization() {
        let mainnet_rules = ProtocolValidationRules::mainnet();
        let json = serde_json::to_string(&mainnet_rules).unwrap();
        let deserialized: ProtocolValidationRules = serde_json::from_str(&json).unwrap();

        assert_eq!(mainnet_rules.max_block_size, deserialized.max_block_size);
        assert_eq!(mainnet_rules.max_tx_size, deserialized.max_tx_size);
        assert_eq!(mainnet_rules.max_script_size, deserialized.max_script_size);
        assert_eq!(mainnet_rules.segwit_enabled, deserialized.segwit_enabled);
        assert_eq!(mainnet_rules.taproot_enabled, deserialized.taproot_enabled);
        assert_eq!(mainnet_rules.rbf_enabled, deserialized.rbf_enabled);
        assert_eq!(mainnet_rules.min_fee_rate, deserialized.min_fee_rate);
        assert_eq!(mainnet_rules.max_fee_rate, deserialized.max_fee_rate);
    }

    #[test]
    fn test_validation_rules_equality() {
        let mainnet1 = ProtocolValidationRules::mainnet();
        let mainnet2 = ProtocolValidationRules::mainnet();
        let testnet = ProtocolValidationRules::testnet();

        assert_eq!(mainnet1, mainnet2);
        assert_eq!(mainnet1, testnet); // Mainnet and testnet should be identical
    }

    #[test]
    fn test_validation_context() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        assert_eq!(context.block_height, 1000);
        assert!(context.is_feature_enabled("segwit"));
        assert!(!context.is_feature_enabled("nonexistent"));
        assert_eq!(context.get_max_size("block"), 4_000_000);
    }

    #[test]
    fn test_validation_context_all_protocols() {
        let mainnet_context =
            ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let testnet_context =
            ProtocolValidationContext::new(ProtocolVersion::Testnet3, 1000).unwrap();
        let regtest_context =
            ProtocolValidationContext::new(ProtocolVersion::Regtest, 1000).unwrap();

        // All should have same block height
        assert_eq!(mainnet_context.block_height, 1000);
        assert_eq!(testnet_context.block_height, 1000);
        assert_eq!(regtest_context.block_height, 1000);

        // All should support same features
        assert!(mainnet_context.is_feature_enabled("segwit"));
        assert!(testnet_context.is_feature_enabled("segwit"));
        assert!(regtest_context.is_feature_enabled("segwit"));

        assert!(mainnet_context.is_feature_enabled("taproot"));
        assert!(testnet_context.is_feature_enabled("taproot"));
        assert!(regtest_context.is_feature_enabled("taproot"));

        assert!(mainnet_context.is_feature_enabled("rbf"));
        assert!(testnet_context.is_feature_enabled("rbf"));
        assert!(regtest_context.is_feature_enabled("rbf"));
    }

    #[test]
    fn test_validation_context_feature_queries() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Test all supported features
        assert!(context.is_feature_enabled("segwit"));
        assert!(context.is_feature_enabled("taproot"));
        assert!(context.is_feature_enabled("rbf"));

        // Test unsupported features
        assert!(!context.is_feature_enabled("nonexistent"));
        assert!(!context.is_feature_enabled(""));
        assert!(!context.is_feature_enabled("fast_mining"));
    }

    #[test]
    fn test_validation_context_size_queries() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        assert_eq!(context.get_max_size("block"), 4_000_000);
        assert_eq!(context.get_max_size("transaction"), 1_000_000);
        assert_eq!(context.get_max_size("script"), 10_000);

        // Test unknown component
        assert_eq!(context.get_max_size("unknown"), 0);
    }

    #[test]
    fn test_validation_context_serialization() {
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let json = serde_json::to_string(&context).unwrap();
        let deserialized: ProtocolValidationContext = serde_json::from_str(&json).unwrap();

        assert_eq!(context.block_height, deserialized.block_height);
        assert_eq!(
            context.network_params.network_name,
            deserialized.network_params.network_name
        );
        assert_eq!(
            context.validation_rules.max_block_size,
            deserialized.validation_rules.max_block_size
        );
    }

    #[test]
    fn test_validation_context_equality() {
        let context1 = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let context2 = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();
        let context3 = ProtocolValidationContext::new(ProtocolVersion::Testnet3, 1000).unwrap();

        assert_eq!(context1, context2);
        assert_ne!(context1, context3); // Different network parameters
    }

    #[test]
    fn test_block_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a block that's within size limits
        let small_block = Block {
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
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            }],
        };

        // This should pass validation
        let result =
            engine.validate_block_with_protocol(&small_block, &HashMap::new(), 1000, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a small transaction
        let small_tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![0x41, 0x04], // Small signature
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
        };

        // This should pass validation
        let result = engine.validate_transaction_with_protocol(&small_tx, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_script_size_validation() {
        let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
        let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Create a transaction with small scripts
        let tx = Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prevout: OutPoint {
                    hash: [0u8; 32],
                    index: 0,
                },
                script_sig: vec![0x41, 0x04], // Small script sig
                sequence: 0xffffffff,
            }],
            outputs: vec![TransactionOutput {
                value: 50_0000_0000,
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ], // Small script pubkey
            }],
            lock_time: 0,
        };

        // This should pass validation
        let result = engine.validate_transaction_with_protocol(&tx, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_context_data() {
        let mut context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 1000).unwrap();

        // Add some context data
        context
            .context_data
            .insert("test_key".to_string(), "test_value".to_string());

        assert_eq!(
            context.context_data.get("test_key"),
            Some(&"test_value".to_string())
        );
        assert_eq!(context.context_data.get("nonexistent"), None);
    }

    #[test]
    fn test_validation_rules_boundary_values() {
        let rules = ProtocolValidationRules::mainnet();

        // Test boundary values
        assert!(rules.max_block_size > 0);
        assert!(rules.max_tx_size > 0);
        assert!(rules.max_script_size > 0);
        assert!(rules.max_fee_rate > rules.min_fee_rate);

        // Test that limits are reasonable
        assert!(rules.max_block_size <= 10_000_000); // Not unreasonably large
        assert!(rules.max_tx_size <= 5_000_000); // Not unreasonably large
        assert!(rules.max_script_size <= 50_000); // Not unreasonably large
    }
}
