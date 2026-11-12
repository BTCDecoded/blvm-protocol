use super::*;
use blvm_consensus::types::{BlockHeader, OutPoint, TransactionInput, TransactionOutput};

/// Grind the nonce until the header meets its regtest target (about two tries).
/// Connect checks proof of work, so block fixtures need real headers.
fn mine_regtest(mut header: BlockHeader) -> BlockHeader {
    header.bits = 0x207fffff;
    while !blvm_consensus::pow::check_proof_of_work(&header).unwrap() {
        header.nonce += 1;
    }
    header
}

#[test]
fn test_blvm_protocol_creation() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();
    assert_eq!(engine.get_protocol_version(), ProtocolVersion::BitcoinV1);
    assert_eq!(engine.get_network_params().network_name, "mainnet");
}

#[test]
fn test_blvm_protocol_creation_all_variants() {
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

    // Test signet
    let signet = BitcoinProtocolEngine::new(ProtocolVersion::Signet).unwrap();
    assert_eq!(signet.get_protocol_version(), ProtocolVersion::Signet);
    assert_eq!(signet.get_network_params().network_name, "signet");
    assert!(signet.get_network_params().is_testnet);
    assert_eq!(signet.get_network_params().default_port, 38333);
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
fn test_signet_magic_matches_bitcoin_core_default_signet() {
    use sha2::{Digest, Sha256};
    // Bitcoin Core default signet challenge (1-of-2 multisig), chainparams.cpp.
    let challenge = hex::decode(
        "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
    )
    .unwrap();
    // Core: pchMessageStart = first 4 bytes of SHA256d(serialized challenge script).
    let mut ser = vec![challenge.len() as u8];
    ser.extend_from_slice(&challenge);
    let digest = Sha256::digest(Sha256::digest(&ser));
    let expected = [0x0a, 0x03, 0xcf, 0x40];
    assert_eq!(&digest[..4], &expected);

    let params = NetworkParameters::signet().unwrap();
    assert_eq!(params.magic_bytes, expected);
    let constants = crate::network_params::NetworkConstants::signet().unwrap();
    assert_eq!(constants.magic_bytes, expected);
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Signet).unwrap();
    assert_eq!(engine.get_network_params().magic_bytes, expected);
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

    let signet = BitcoinProtocolEngine::new(ProtocolVersion::Signet).unwrap();
    assert!(signet.supports_feature("segwit"));
    assert!(signet.supports_feature("taproot"));
    assert!(signet.supports_feature("signet"));
    assert!(!signet.supports_feature("fast_mining"));
}

#[test]
fn test_signet_challenge_override_on_engine() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Signet)
        .unwrap()
        .with_signet_challenge(Some(vec![0x51]));
    assert_eq!(
        engine
            .get_network_params()
            .signet_challenge
            .as_ref()
            .map(|b| b.as_ref()),
        Some([0x51].as_slice())
    );
    let ctx = engine.connect_block_validation_context(None::<&[BlockHeader]>, 0);
    assert_eq!(
        ctx.signet_challenge.as_ref().map(|b| b.as_ref()),
        Some([0x51].as_slice())
    );
}

#[test]
fn test_block_validation_empty_utxos() {
    use crate::validation::ProtocolValidationContext;
    use blvm_consensus::opcodes::OP_1;

    let engine = BitcoinProtocolEngine::new(ProtocolVersion::Regtest).unwrap();
    let utxos = UtxoSet::default();

    let coinbase_tx = Transaction {
        version: 2,
        inputs: blvm_consensus::tx_inputs![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0xffffffff,
            },
            script_sig: vec![0x00, 0xff],
            sequence: 0xffffffff,
        }],
        outputs: blvm_consensus::tx_outputs![TransactionOutput {
            value: 5_000_000_000,
            script_pubkey: vec![OP_1],
        }],
        lock_time: 0,
    };

    let merkle_root =
        blvm_consensus::mining::calculate_merkle_root(&[coinbase_tx.clone()]).expect("merkle root");

    let block = Block {
        header: mine_regtest(BlockHeader {
            version: 4,
            prev_block_hash: [0u8; 32],
            merkle_root,
            timestamp: 1_231_006_505,
            bits: 0x207fffff,
            nonce: 0,
        }),
        transactions: vec![coinbase_tx].into_boxed_slice(),
    };

    let witnesses: Vec<Vec<blvm_consensus::segwit::Witness>> = block
        .transactions
        .iter()
        .map(|tx| tx.inputs.iter().map(|_| Vec::new()).collect())
        .collect();
    let mut context = ProtocolValidationContext::new(ProtocolVersion::Regtest, 0).unwrap();
    context.network_time = block.header.timestamp;
    context.median_time_past = block.header.timestamp - 1;

    let (result, new_utxos) = engine
        .validate_and_connect_block(&block, &witnesses, &utxos, 0, None, &context)
        .unwrap();
    assert_eq!(result, ValidationResult::Valid);
    assert!(!new_utxos.is_empty());
}

#[test]
fn test_transaction_validation() {
    let engine = BitcoinProtocolEngine::new(ProtocolVersion::BitcoinV1).unwrap();

    // Create a simple transaction
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
            ], // P2PKH
        }]
        .into(),
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
        ProtocolVersion::Signet,
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
        ProtocolVersion::Signet,
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
