//! Protocol validation interface
//!
//! This module provides protocol-specific validation that extends
//! the pure mathematical consensus rules with network-specific
//! and protocol-specific validation logic.

use crate::error::ProtocolError;
use crate::features::FeatureRegistry;
use crate::{BitcoinProtocolEngine, NetworkParameters, ProtocolVersion};
use crate::{Block, Transaction, ValidationResult};
use blvm_consensus::types::UtxoSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Protocol-specific Result type
type Result<T> = std::result::Result<T, ProtocolError>;

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
            ProtocolVersion::Signet => Self::signet(),
            ProtocolVersion::Testnet4 => Self::testnet4(),
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

    /// Testnet4 validation rules (same limits as testnet3).
    pub fn testnet4() -> Self {
        Self::testnet()
    }

    /// Signet validation rules (production-like test network)
    pub fn signet() -> Self {
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
    /// Feature activation registry for this protocol version.
    ///
    /// Used by `is_feature_enabled` to derive activation status from
    /// `block_height` / `network_time` rather than static booleans.
    pub feature_registry: FeatureRegistry,
    /// Median time-past used for time-based validation (BIP113)
    ///
    /// This is populated by the node using recent headers and is threaded down
    /// to consensus for timestamp validation.
    pub median_time_past: u64,
    /// Current adjusted network time (Unix timestamp)
    ///
    /// This is populated by the node from its time source and used by consensus
    /// to enforce future timestamp limits.
    pub network_time: u64,
    /// Additional context data
    pub context_data: HashMap<String, String>,
}

impl ProtocolValidationContext {
    /// Create validation context for a protocol version
    pub fn new(version: ProtocolVersion, block_height: u64) -> Result<Self> {
        let network_params = NetworkParameters::for_version(version)?;
        let validation_rules = ProtocolValidationRules::for_protocol(version);

        let feature_registry = FeatureRegistry::for_protocol(version);
        Ok(Self {
            block_height,
            network_params,
            validation_rules,
            feature_registry,
            // Default to zero; callers that care about time must set these explicitly.
            median_time_past: 0,
            network_time: 0,
            context_data: HashMap::new(),
        })
    }

    /// Check if a feature is enabled at the current block height and network time.
    ///
    /// Queries the `FeatureRegistry` so activation reflects the actual deployment
    /// height/timestamp rather than static booleans that ignore `block_height`.
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        self.feature_registry
            .is_feature_active(feature, self.block_height, self.network_time)
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
    /// Validate a block with protocol-specific rules (witness-blind).
    ///
    /// The block weight check is a lower bound only.  Use
    /// [`validate_block_with_protocol_and_witnesses`] for accurate BIP141 weight enforcement.
    pub fn validate_block_with_protocol(
        &self,
        block: &Block,
        _utxos: &UtxoSet,
        _height: u64,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        self.apply_protocol_validation(block, context)?;
        Ok(ValidationResult::Valid)
    }

    /// Validate a block with protocol-specific rules and witness data.
    ///
    /// Performs a full BIP141 weight check using the provided witnesses.
    pub fn validate_block_with_protocol_and_witnesses(
        &self,
        block: &Block,
        witnesses: &[Vec<blvm_consensus::segwit::Witness>],
        _utxos: &UtxoSet,
        _height: u64,
        context: &ProtocolValidationContext,
    ) -> Result<ValidationResult> {
        self.apply_protocol_validation_with_witnesses(block, Some(witnesses), context)?;
        Ok(ValidationResult::Valid)
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

    /// Apply protocol-specific validation rules (witness-blind; lower-bound weight only).
    ///
    /// This variant does not have witness data available, so the block weight check is the
    /// stripped block: non-witness bytes at ×4. It cannot catch a block that exceeds the
    /// limit only because of witness data. Prefer
    /// [`apply_protocol_validation_with_witnesses`] when witness data is available.
    fn apply_protocol_validation(
        &self,
        block: &Block,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        self.apply_protocol_validation_with_witnesses(block, None, context)
    }

    /// Apply protocol-specific validation rules with optional witness data.
    ///
    /// Block weight is [`blvm_consensus::segwit::calculate_block_weight_from_nested`]:
    /// non-witness bytes at ×4, and the marker, flag, stack counts, and witness
    /// elements at ×1. A missing witness list is the stripped block.
    fn apply_protocol_validation_with_witnesses(
        &self,
        block: &Block,
        witnesses: Option<&[Vec<blvm_consensus::segwit::Witness>]>,
        context: &ProtocolValidationContext,
    ) -> Result<()> {
        let witness_list = witnesses.unwrap_or(&[]);
        let weight =
            blvm_consensus::segwit::calculate_block_weight_from_nested(block, witness_list)?;
        if weight > context.validation_rules.max_block_size as u64 {
            return Err(ProtocolError::Validation(
                format!(
                    "Block weight exceeds maximum: {} WU (max {} WU)",
                    weight, context.validation_rules.max_block_size
                )
                .into(),
            ));
        }

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
            return Err(ProtocolError::Validation(
                format!(
                    "Transaction size exceeds maximum: {} bytes (max {} bytes)",
                    tx_size, context.validation_rules.max_tx_size
                )
                .into(),
            ));
        }

        // Check script size limits
        for input in &tx.inputs {
            if input.script_sig.len() > context.validation_rules.max_script_size as usize {
                return Err(ProtocolError::Validation(
                    format!(
                        "Script size exceeds maximum: {} bytes (max {} bytes)",
                        input.script_sig.len(),
                        context.validation_rules.max_script_size
                    )
                    .into(),
                ));
            }
        }

        Ok(())
    }

    /// Calculate block size in bytes
    /// Calculate transaction size in bytes
    fn calculate_transaction_size(&self, tx: &Transaction) -> u32 {
        // Use canonical serialization-based size from consensus layer (TX_NO_WITNESS size).
        //
        // This keeps protocol-level size limits aligned with the exact serialization
        // used for consensus checks and transaction size tests.
        blvm_consensus::transaction::calculate_transaction_size(tx) as u32
    }
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;
