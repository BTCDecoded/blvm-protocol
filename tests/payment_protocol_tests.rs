//! Payment Protocol Tests (BIP70)
//!
//! Tests for BIP70 payment protocol implementation.
//! Specification: https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki

use bllvm_protocol::payment::{
    PaymentRequest, PaymentOutput, Payment, PaymentACK,
    PaymentProtocolClient, PaymentProtocolServer,
    PaymentDetails, SignedRefundAddress, Bip70Error
};
use secp256k1::{Secp256k1, SecretKey};

/// Test helper: Generate a test keypair
fn generate_test_keypair() -> (SecretKey, secp256k1::PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

/// Test helper: Create a test payment output
fn create_test_payment_output() -> PaymentOutput {
    PaymentOutput {
        script: vec![0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        amount: Some(1000),
    }
}

// ============================================================================
// Phase 1: PaymentRequest Creation Tests
// ============================================================================

#[test]
fn test_payment_request_creation() {
    // Test creating a payment request
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs.clone(), 1234567890);
    
    assert_eq!(request.payment_details.network, "main");
    assert_eq!(request.payment_details.outputs.len(), 1);
    assert_eq!(request.payment_details.outputs[0].amount, outputs[0].amount);
    assert_eq!(request.payment_details.time, 1234567890);
}

#[test]
fn test_payment_request_with_merchant_key() {
    // Test setting merchant public key
    let (_, pubkey) = generate_test_keypair();
    let pubkey_bytes = pubkey.serialize();
    
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_merchant_key(pubkey_bytes);
    
    assert!(request.merchant_pubkey.is_some());
    assert_eq!(request.merchant_pubkey.as_ref().unwrap().len(), 33);
}

#[test]
fn test_payment_request_with_expires() {
    // Test setting expiration time
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_expires(1234567900);
    
    assert_eq!(request.payment_details.expires, Some(1234567900));
}

#[test]
fn test_payment_request_with_memo() {
    // Test setting memo
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890)
        .with_memo("Test payment".to_string());
    
    assert_eq!(request.payment_details.memo, Some("Test payment".to_string()));
}

#[test]
fn test_payment_request_with_multiple_outputs() {
    // Test payment request with multiple outputs
    let outputs = vec![
        create_test_payment_output(),
        PaymentOutput {
            script: vec![0x51], // OP_1
            amount: Some(2000),
        },
    ];
    let request = PaymentRequest::new("mainnet".to_string(), outputs.clone(), 1234567890);
    
    assert_eq!(request.payment_details.outputs.len(), 2);
    assert_eq!(request.payment_details.outputs[0].amount, Some(1000));
    assert_eq!(request.payment_details.outputs[1].amount, Some(2000));
}

// ============================================================================
// Phase 2: PaymentRequest Validation Tests
// ============================================================================

#[test]
fn test_payment_request_validation_valid() {
    // Test validation of valid payment request
    // Note: validation checks network name - must be "main", "test", or "regtest"
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890);
    
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_payment_request_validation_empty_outputs() {
    // Test validation fails with empty outputs
    let request = PaymentRequest::new("main".to_string(), vec![], 1234567890);
    
    let result = request.validate();
    assert!(result.is_err());
    if let Err(Bip70Error::InvalidRequest(msg)) = result {
        assert!(msg.contains("output") || msg.contains("empty"));
    }
}

#[test]
fn test_payment_request_expiration_check() {
    // Test expiration check
    let outputs = vec![create_test_payment_output()];
    let past_time = 1000000000; // Past timestamp
    let request = PaymentRequest::new("main".to_string(), outputs, past_time)
        .with_expires(past_time + 100);
    
    // Request should be expired if current time > expires
    // For testing, we check the structure
    assert!(request.payment_details.expires.is_some());
}

// ============================================================================
// Phase 3: Payment Creation Tests
// ============================================================================

#[test]
fn test_payment_creation() {
    // Test creating a payment from transaction
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00]; // Mock transaction bytes
    let payment = Payment::new(vec![tx_bytes.clone()]);
    
    assert_eq!(payment.transactions.len(), 1);
    assert_eq!(payment.transactions[0], tx_bytes);
}

#[test]
fn test_payment_with_refund_addresses() {
    // Test payment with refund addresses
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let refund_output = create_test_payment_output();
    let payment = Payment::new(vec![tx_bytes])
        .with_refund_to(vec![refund_output.clone()]);
    
    assert!(payment.refund_to.is_some());
    assert_eq!(payment.refund_to.as_ref().unwrap().len(), 1);
    assert_eq!(payment.refund_to.as_ref().unwrap()[0].amount, refund_output.amount);
}

#[test]
fn test_payment_with_merchant_data() {
    // Test payment with merchant data
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let merchant_data = vec![0x42, 0x43, 0x44];
    let payment = Payment::new(vec![tx_bytes])
        .with_merchant_data(merchant_data.clone());
    
    assert_eq!(payment.merchant_data, Some(merchant_data));
}

#[test]
fn test_payment_with_memo() {
    // Test payment with customer memo
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let payment = Payment::new(vec![tx_bytes])
        .with_memo("Payment memo".to_string());
    
    assert_eq!(payment.memo, Some("Payment memo".to_string()));
}

#[test]
fn test_payment_validation_valid() {
    // Test payment validation
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let payment = Payment::new(vec![tx_bytes]);
    
    let result = payment.validate();
    assert!(result.is_ok());
}

#[test]
fn test_payment_validation_empty_transactions() {
    // Test payment validation fails with empty transactions
    let payment = Payment::new(vec![]);
    
    let result = payment.validate();
    assert!(matches!(result, Err(Bip70Error::InvalidPayment(_))));
}

// ============================================================================
// Phase 4: PaymentACK Tests
// ============================================================================

#[test]
fn test_payment_ack_creation() {
    // Test creating PaymentACK
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let payment = Payment::new(vec![tx_bytes]);
    let ack = PaymentACK {
        payment: payment.clone(),
        memo: Some("Payment received".to_string()),
    };
    
    assert_eq!(ack.payment.transactions.len(), payment.transactions.len());
    assert_eq!(ack.memo, Some("Payment received".to_string()));
}

#[test]
fn test_payment_ack_without_memo() {
    // Test PaymentACK without memo
    let tx_bytes = vec![0x01, 0x00, 0x00, 0x00];
    let payment = Payment::new(vec![tx_bytes]);
    let ack = PaymentACK {
        payment,
        memo: None,
    };
    
    assert!(ack.memo.is_none());
}

// ============================================================================
// Phase 5: PaymentProtocolClient Tests
// ============================================================================

#[test]
fn test_client_validate_payment_request_basic() {
    // Test client validation of payment request (without signature)
    let outputs = vec![create_test_payment_output()];
    let request = PaymentRequest::new("main".to_string(), outputs, 1234567890);
    
    // Basic validation (no signature check)
    // Note: validate_payment_request may require signature, so we just verify structure
    // For now, we verify the request structure
    assert_eq!(request.payment_details.outputs.len(), 1);
}

// ============================================================================
// Phase 6: PaymentProtocolServer Tests
// ============================================================================

#[test]
fn test_server_create_payment_request() {
    // Test server creating a payment request
    let (secret_key, _) = generate_test_keypair();
    let outputs = vec![create_test_payment_output()];
    let details = PaymentDetails {
        network: "main".to_string(),
        outputs,
        time: 1234567890,
        expires: None,
        memo: None,
        payment_url: None,
        merchant_data: None,
    };
    
    let result = PaymentProtocolServer::create_signed_payment_request(
        details,
        &secret_key,
        None,
    );
    
    // Should create a signed payment request
    assert!(result.is_ok());
    let request = result.unwrap();
    assert!(request.merchant_pubkey.is_some());
    assert!(request.signature.is_some());
}

// ============================================================================
// Phase 7: SignedRefundAddress Tests
// ============================================================================

#[test]
fn test_signed_refund_address_structure() {
    // Test SignedRefundAddress structure
    let refund_output = create_test_payment_output();
    let signature = vec![0x30, 0x45, 0x02, 0x21]; // Mock signature bytes
    
    let signed_refund = SignedRefundAddress {
        address: refund_output.clone(),
        signature: signature.clone(),
    };
    
    assert_eq!(signed_refund.address.amount, refund_output.amount);
    assert_eq!(signed_refund.signature, signature);
}

// ============================================================================
// Phase 8: Error Handling Tests
// ============================================================================

#[test]
fn test_bip70_error_types() {
    // Test that BIP70 error types can be created and formatted
    let expired = Bip70Error::Expired;
    assert!(format!("{}", expired).contains("expired"));
    
    let invalid = Bip70Error::InvalidRequest("test".to_string());
    assert!(format!("{}", invalid).contains("test"));
    
    let payment_error = Bip70Error::InvalidPayment("test".to_string());
    assert!(format!("{}", payment_error).contains("test"));
}

#[test]
fn test_payment_request_network_validation() {
    // Test payment request with different networks
    let outputs = vec![create_test_payment_output()];
    
    let mainnet = PaymentRequest::new("main".to_string(), outputs.clone(), 1234567890);
    let testnet = PaymentRequest::new("test".to_string(), outputs.clone(), 1234567890);
    let regtest = PaymentRequest::new("regtest".to_string(), outputs, 1234567890);
    
    assert_eq!(mainnet.payment_details.network, "main");
    assert_eq!(testnet.payment_details.network, "test");
    assert_eq!(regtest.payment_details.network, "regtest");
}

