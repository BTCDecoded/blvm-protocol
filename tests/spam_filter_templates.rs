//! Filter labels: UnexecIf + Witness, NullDataOp13 + OpReturn, DataLikeMs + Witness.

use blvm_consensus::opcodes::{
    OP_0, OP_1, OP_2, OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN, OP_13,
    PUSH_32_BYTES,
};
use blvm_consensus::types::{OutPoint, Transaction, TransactionInput, TransactionOutput};
use blvm_protocol::spam_filter::{SpamFilter, SpamFilterPreset, SpamType};

fn tx_with_spk(script_pubkey: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TransactionInput {
            prevout: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
        }]
        .into(),
        outputs: vec![TransactionOutput {
            value: 10_000,
            script_pubkey: script_pubkey.into(),
        }]
        .into(),
        lock_time: 0,
    }
}

fn unexec_if_tapscript() -> Vec<u8> {
    let mut s = vec![OP_0, OP_IF, 0x03, b'o', b'r', b'd', OP_ENDIF, PUSH_32_BYTES];
    s.extend_from_slice(&[0x11; 32]);
    s.push(OP_CHECKSIG);
    s
}

#[test]
fn filter_unexec_if_witness() {
    let filter = SpamFilter::with_preset(SpamFilterPreset::Moderate);
    let tx = tx_with_spk(vec![0x51]);
    let witnesses = vec![vec![unexec_if_tapscript()]];
    let result = filter.is_spam_with_witness(&tx, Some(&witnesses), None);
    assert!(result.is_spam);
    assert!(result.detected_types.contains(&SpamType::UnexecIf));
}

#[test]
fn filter_null_data_op13() {
    let filter = SpamFilter::with_preset(SpamFilterPreset::Moderate);
    let tx = tx_with_spk(vec![OP_RETURN, OP_13, 0x01, 0xff]);
    let result = filter.is_spam(&tx);
    assert!(result.is_spam);
    assert!(result.detected_types.contains(&SpamType::NullDataOp13));
}

#[test]
fn filter_data_like_ms() {
    let filter = SpamFilter::with_preset(SpamFilterPreset::Moderate);
    let mut script = vec![OP_1, 0x08];
    script.extend_from_slice(&[0x11; 8]);
    script.push(0x08);
    script.extend_from_slice(&[0x22; 8]);
    script.push(OP_2);
    script.push(OP_CHECKMULTISIG);
    let tx = tx_with_spk(script);
    let result = filter.is_spam(&tx);
    assert!(result.is_spam);
    assert!(result.detected_types.contains(&SpamType::DataLikeMs));
}

#[test]
fn unexec_if_strict_large_witness_separate() {
    let filter = SpamFilter::new();
    let tx = tx_with_spk(vec![0x76, 0xa9]);
    let large_witness = vec![vec![0x30; 600], vec![0x01; 600]];
    let witnesses = vec![large_witness];
    let result = filter.is_spam_with_witness(&tx, Some(&witnesses), None);
    assert!(result.is_spam);
    assert!(result.detected_types.contains(&SpamType::LargeWitness));
    assert!(!result.detected_types.contains(&SpamType::UnexecIf));
}
