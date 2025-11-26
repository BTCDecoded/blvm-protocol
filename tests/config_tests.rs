//! Configuration Tests
//!
//! Tests for protocol configuration system.

use bllvm_protocol::config::{
    ProtocolConfig, ProtocolValidationConfig, ServiceFlagsConfig, ProtocolFeaturesConfig,
    FeeRateConfig, CompactBlockConfig, CommonsExtensionsConfig,
};
use bllvm_protocol::{ProtocolVersion, service_flags};

#[test]
fn test_protocol_config_default() {
    let config = ProtocolConfig::default();
    assert_eq!(config.protocol_version, ProtocolVersion::BitcoinV1);
    assert_eq!(config.validation.max_block_size, 4_000_000);
    assert_eq!(config.validation.max_tx_size, 1_000_000);
    assert_eq!(config.validation.max_script_size, 10_000);
    assert_eq!(config.validation.max_txs_per_block, 10_000);
    assert_eq!(config.validation.max_locator_hashes, 100);
}

#[test]
fn test_service_flags_config() {
    let mut config = ServiceFlagsConfig::default();
    assert!(config.node_network);
    assert!(config.node_witness);
    assert!(!config.node_fibre);
    assert!(!config.node_utxo_commitments);

    config.node_fibre = true;
    config.node_utxo_commitments = true;

    let protocol_config = ProtocolConfig {
        service_flags: config,
        ..Default::default()
    };

    let flags = protocol_config.get_service_flags();
    assert!(service_flags::has_flag(flags, service_flags::standard::NODE_NETWORK));
    assert!(service_flags::has_flag(flags, service_flags::standard::NODE_WITNESS));
    assert!(service_flags::has_flag(flags, service_flags::commons::NODE_FIBRE));
}

#[test]
fn test_protocol_features_config() {
    let config = ProtocolFeaturesConfig::default();
    assert!(config.segwit);
    assert!(config.taproot);
    assert!(config.rbf);
    assert!(config.compact_blocks);
    assert!(!config.ctv);
    assert!(!config.compact_filters);
}

#[test]
fn test_fee_rate_config() {
    let config = FeeRateConfig::default();
    assert_eq!(config.min_fee_rate, 1);
    assert_eq!(config.max_fee_rate, 1_000_000);
}

#[test]
fn test_compact_block_config() {
    let config = CompactBlockConfig::default();
    assert!(config.enabled);
    assert_eq!(config.preferred_version, 2);
    assert_eq!(config.max_blocktxn_indices, 10_000);
}

#[test]
fn test_commons_extensions_config() {
    let config = CommonsExtensionsConfig::default();
    assert!(!config.utxo_commitments);
    assert!(!config.filtered_blocks);
    assert!(!config.ban_list_sharing);
}

#[test]
fn test_protocol_validation_config() {
    let mut config = ProtocolValidationConfig::default();
    assert_eq!(config.max_block_size, 4_000_000);
    assert_eq!(config.max_tx_size, 1_000_000);
    assert_eq!(config.max_script_size, 10_000);
    assert_eq!(config.max_txs_per_block, 10_000);
    assert_eq!(config.max_locator_hashes, 100);

    // Test custom values
    config.max_block_size = 8_000_000;
    config.max_txs_per_block = 20_000;
    assert_eq!(config.max_block_size, 8_000_000);
    assert_eq!(config.max_txs_per_block, 20_000);
}

