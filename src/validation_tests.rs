use super::*;
use blvm_consensus::types::{OutPoint, TransactionInput, TransactionOutput};
use blvm_consensus::{Block, BlockHeader, Transaction};

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
    // Use a height past both segwit (481824) and taproot (709632) activation.
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();
    assert_eq!(context.block_height, 800_000);
    assert!(context.is_feature_enabled("segwit"));
    assert!(!context.is_feature_enabled("nonexistent"));
    assert_eq!(context.get_max_size("block"), 4_000_000);
}

#[test]
fn test_validation_context_all_protocols() {
    // Per-network heights past segwit+taproot activation:
    //   mainnet: taproot at 709_632   → use 800_000
    //   testnet3: taproot at 2_016_000 → use 2_100_000
    //   regtest: all features AlwaysActive → any height works
    let mainnet_context =
        ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();
    let testnet_context =
        ProtocolValidationContext::new(ProtocolVersion::Testnet3, 2_100_000).unwrap();
    let regtest_context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 1).unwrap();

    assert_eq!(mainnet_context.block_height, 800_000);
    assert_eq!(testnet_context.block_height, 2_100_000);
    assert_eq!(regtest_context.block_height, 1);

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
    // Height past both segwit (481824) and taproot (709632) so all features are active.
    let context = ProtocolValidationContext::new(ProtocolVersion::BitcoinV1, 800_000).unwrap();

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

    // Create a block that's within size limits with a valid coinbase transaction
    let coinbase_tx = Transaction {
        version: 1,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x01, 0x00], // Height 0
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![blvm_consensus::opcodes::OP_1],
        }],
        lock_time: 0,
    };

    // Calculate proper merkle root
    let merkle_root = blvm_consensus::mining::calculate_merkle_root(&[coinbase_tx.clone()])
        .expect("Should calculate merkle root");

    let small_block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root,
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    // This should pass validation
    let result =
        engine.validate_block_with_protocol(&small_block, &UtxoSet::default(), 1000, &context);
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
            script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![
                blvm_consensus::opcodes::OP_DUP,
                blvm_consensus::opcodes::OP_HASH160,
                blvm_consensus::opcodes::PUSH_20_BYTES,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                blvm_consensus::opcodes::OP_EQUALVERIFY,
                blvm_consensus::opcodes::OP_CHECKSIG,
            ],
        }]
        .into(),
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
            script_sig: vec![blvm_consensus::opcodes::PUSH_65_BYTES, 0x04],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![
                blvm_consensus::opcodes::OP_DUP,
                blvm_consensus::opcodes::OP_HASH160,
                blvm_consensus::opcodes::PUSH_20_BYTES,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                blvm_consensus::opcodes::OP_EQUALVERIFY,
                blvm_consensus::opcodes::OP_CHECKSIG,
            ],
        }]
        .into(),
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

#[test]
fn test_block_weight_counts_witness_element_bytes() {
    use blvm_consensus::opcodes::OP_1;
    use blvm_consensus::{
        Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput,
    };

    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 1).unwrap();
    context.validation_rules.max_block_size = 5_000;

    let coinbase = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1u8; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase, tx].into(),
    };
    // One heavy witness element (9000 bytes) — stack depth alone would be 1 WU (REV-P-07).
    let heavy_elem = vec![0u8; 9000];
    let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> =
        vec![vec![vec![]], vec![vec![heavy_elem]]];

    let result = engine.validate_block_with_protocol_and_witnesses(
        &block,
        &witnesses,
        &UtxoSet::default(),
        1,
        &context,
    );
    assert!(
        result.is_err(),
        "heavy witness bytes must exceed reduced max_block_size weight limit"
    );
}

#[test]
fn protocol_block_weight_matches_consensus_including_witness_framing() {
    use blvm_consensus::opcodes::OP_1;
    use blvm_consensus::{
        Block, BlockHeader, OutPoint, Transaction, TransactionInput, TransactionOutput,
    };

    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 1).unwrap();
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 50_0000_0000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let tx = Transaction {
        version: 2,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [1u8; 32],
                index: 0,
            },
            script_sig: vec![OP_1].into(),
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 1_000,
            script_pubkey: vec![OP_1].into(),
        }]
        .into(),
        lock_time: 0,
    };
    let block = Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1_700_000_000,
            bits: 0x207fffff,
            nonce: 0,
        },
        transactions: vec![coinbase, tx].into(),
    };
    let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> =
        vec![vec![vec![]], vec![vec![vec![0x11]]]];
    let weight = blvm_consensus::segwit::calculate_block_weight_from_nested(&block, &witnesses)
        .expect("witness stacks match the inputs");
    context.validation_rules.max_block_size = weight as u32;
    assert!(
        engine
            .validate_block_with_protocol_and_witnesses(
                &block,
                &witnesses,
                &UtxoSet::default(),
                1,
                &context,
            )
            .is_ok(),
        "weight equal to the consensus weight is accepted"
    );
    context.validation_rules.max_block_size = (weight - 1) as u32;
    assert!(
        engine
            .validate_block_with_protocol_and_witnesses(
                &block,
                &witnesses,
                &UtxoSet::default(),
                1,
                &context,
            )
            .is_err(),
        "one weight unit under the consensus weight is rejected"
    );
}
