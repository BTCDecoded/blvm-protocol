//! Payment Protocol Edge Cases Tests
//!
//! Additional edge cases and error scenarios for BIP70 payment protocol.

use blvm_protocol::payment::{
    Bip70Error, Payment, PaymentACK, PaymentOutput, PaymentRequest, SignedRefundAddress,
};
use secp256k1::{Message, Secp256k1, SecretKey};

fn generate_test_keypair() -> (SecretKey, secp256k1::PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

#[test]
fn test_payment_request_invalid_network() {
    // Test payment request with invalid network identifier
    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let request = PaymentRequest::new("invalid_network".to_string(), outputs, 1234567890);

    // Should accept any network string (validation happens at protocol level)
    assert_eq!(request.payment_details.network, "invalid_network");
}

#[test]
fn test_payment_request_expired() {
    // Test payment request that has already expired
    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let past_time = 1000;
    let request =
        PaymentRequest::new("main".to_string(), outputs, past_time).with_expires(past_time - 1); // Expired before creation

    assert_eq!(request.payment_details.expires, Some(past_time - 1));
    assert!(request.payment_details.expires.unwrap() < request.payment_details.time);
}

#[test]
fn test_payment_request_empty_outputs() {
    // Test payment request with no outputs
    let outputs = vec![];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890);

    assert_eq!(request.payment_details.outputs.len(), 0);
}

#[test]
fn test_payment_request_invalid_signature() {
    // Test payment request with invalid signature
    let (secret_key, _) = generate_test_keypair();
    let secp = Secp256k1::new();
    let pubkey_bytes = secp256k1::PublicKey::from_secret_key(&secp, &secret_key).serialize();

    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let mut request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_merchant_key(pubkey_bytes);

    // Corrupt the signature
    request.signature = Some(vec![0xFF; 64]); // Invalid signature

    // Verification should fail
    let result = request.verify_signature();
    assert!(result.is_err());
    if let Err(Bip70Error::SignatureError(_)) = result {
        // Expected error type
    } else {
        panic!("Expected SignatureError");
    }
}

#[test]
fn test_payment_request_missing_signature() {
    // Test payment request with merchant key but no signature
    let (_, pubkey) = generate_test_keypair();
    let pubkey_bytes = pubkey.serialize();

    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_merchant_key(pubkey_bytes);

    // Should fail verification if key is present but signature is missing
    let result = request.verify_signature();
    assert!(result.is_err());
}

#[test]
fn test_payment_request_malformed_output() {
    // Test payment request with malformed output script
    let outputs = vec![PaymentOutput {
        script: vec![], // Empty script
        amount: Some(1000),
    }];

    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890);

    // Should accept empty script (validation happens at consensus level)
    assert_eq!(request.payment_details.outputs[0].script.len(), 0);
}

#[test]
fn test_payment_request_negative_amount() {
    // Test payment request with invalid amount (should use Option<u64> so None is valid)
    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: None, // All available funds
    }];

    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890);

    assert_eq!(request.payment_details.outputs[0].amount, None);
}

#[test]
fn test_payment_invalid_transaction() {
    // Test payment with invalid transaction data
    let payment = Payment {
        transactions: vec![vec![0xFF; 10]], // Invalid transaction data
        refund_to: None,
        merchant_data: None,
        memo: None,
    };

    // Payment structure is valid, transaction validation happens at consensus level
    assert_eq!(payment.transactions.len(), 1);
}

#[test]
fn test_payment_ack_mismatched_payment() {
    // Test PaymentACK with mismatched payment
    let payment1 = Payment {
        transactions: vec![vec![1, 2, 3]],
        refund_to: None,
        merchant_data: None,
        memo: None,
    };

    let payment2 = Payment {
        transactions: vec![vec![4, 5, 6]],
        refund_to: None,
        merchant_data: None,
        memo: None,
    };

    // Create ACK with different payment
    let ack = PaymentACK {
        payment: payment2.clone(),
        memo: None,
        signature: None,
    };

    // ACK should contain the payment it was created with
    assert_ne!(ack.payment.transactions, payment1.transactions);
    assert_eq!(ack.payment.transactions, payment2.transactions);
}

#[test]
fn test_signed_refund_address_invalid_signature() {
    // Test signed refund address with invalid signature
    let (_, pubkey) = generate_test_keypair();
    let secp = Secp256k1::new();

    let address = PaymentOutput {
        script: vec![0x51],
        amount: None,
    };

    // Create invalid signature
    let invalid_signature = vec![0xFF; 64];

    let signed_refund = SignedRefundAddress {
        address,
        signature: invalid_signature,
    };

    // Verification should fail - from_compact will fail for invalid signature
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&[0x42; 32]);
    let message = Message::from_digest_slice(&hash).unwrap();
    let sig_result = secp256k1::ecdsa::Signature::from_compact(&signed_refund.signature);
    // Invalid signature should fail to parse
    assert!(sig_result.is_err());
}

#[test]
fn test_payment_request_very_large_memo() {
    // Test payment request with very large memo
    let large_memo = "x".repeat(10000);
    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let request =
        PaymentRequest::new("main".to_string(), outputs, 1234567890).with_memo(large_memo.clone());

    assert_eq!(request.payment_details.memo, Some(large_memo));
}

#[test]
fn test_payment_request_multiple_refund_addresses() {
    // Test payment request with multiple refund addresses
    let (secret_key, pubkey) = generate_test_keypair();
    let secp = Secp256k1::new();
    let pubkey_bytes = pubkey.serialize();

    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    // Create multiple refund addresses
    let refund1 = PaymentOutput {
        script: vec![0x51],
        amount: None,
    };
    let refund2 = PaymentOutput {
        script: vec![0x52], // OP_2
        amount: None,
    };

    // Sign refund addresses
    use sha2::{Digest, Sha256};
    let hash1 = Sha256::digest(&refund1.script);
    let message1 = Message::from_digest_slice(&hash1).unwrap();
    let sig1 = secp.sign_ecdsa(&message1, &secret_key);
    let signed_refund1 = SignedRefundAddress {
        address: refund1,
        signature: sig1.serialize_compact().to_vec(),
    };

    let hash2 = Sha256::digest(&refund2.script);
    let message2 = Message::from_digest_slice(&hash2).unwrap();
    let sig2 = secp.sign_ecdsa(&message2, &secret_key);
    let signed_refund2 = SignedRefundAddress {
        address: refund2,
        signature: sig2.serialize_compact().to_vec(),
    };

    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_merchant_key(pubkey_bytes)
        .with_authorized_refund(signed_refund1)
        .with_authorized_refund(signed_refund2);

    assert_eq!(
        request.authorized_refund_addresses.as_ref().unwrap().len(),
        2
    );
}

#[test]
fn test_payment_request_network_timeout_scenario() {
    // Test payment request expiration handling (simulated timeout)
    let outputs = vec![PaymentOutput {
        script: vec![0x51],
        amount: Some(1000),
    }];

    let current_time = 1234567890;
    let short_expiry = current_time + 1; // Expires in 1 second

    let request =
        PaymentRequest::new("main".to_string(), outputs, current_time).with_expires(short_expiry);

    // Simulate time passing
    let future_time = current_time + 2;
    assert!(future_time > request.payment_details.expires.unwrap());
}
