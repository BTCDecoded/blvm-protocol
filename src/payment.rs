//! BIP70: Payment Protocol (P2P Variant)
//!
//! Specification: https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki
//!
//! This is a P2P-based variant of BIP70 that addresses security concerns:
//! - Uses Bitcoin P2P network instead of HTTP/HTTPS (privacy-preserving)
//! - Uses Bitcoin public key signatures instead of X.509 certificates (decentralized)
//! - Supports signed refund addresses (prevents refund attacks)
//! - Works with TCP, Iroh, and QUIC transports
//!
//! Core messages:
//! - PaymentRequest: Merchant payment details signed with Bitcoin key
//! - Payment: Customer payment transaction(s)
//! - PaymentACK: Merchant confirmation of payment
//!
//! Security enhancements:
//! - Merchant authentication via Bitcoin public keys (on-chain verifiable)
//! - Signed refund addresses prevent refund attacks
//! - P2P routing preserves customer privacy (no direct merchant connection)

use crate::Hash;
use blvm_secp256k1::ecdsa::{
    ecdsa_sig_parse_compact, ecdsa_sig_verify, ecdsa_sign_compact_rfc6979, ge_from_pubkey_bytes,
    ge_to_compressed, pubkey_from_secret, verify_ecdsa_direct,
};
use blvm_secp256k1::scalar::Scalar;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Internal helpers: sign / verify using blvm-secp256k1
// ---------------------------------------------------------------------------

/// SHA-256 hash → compact ECDSA signature (64 bytes, low-S, RFC 6979 nonce).
fn sign_compact(hash: &[u8; 32], seckey: &[u8; 32]) -> Result<Vec<u8>, Bip70Error> {
    ecdsa_sign_compact_rfc6979(hash, seckey)
        .map(|s| s.to_vec())
        .ok_or_else(|| Bip70Error::SignatureError("ECDSA signing failed".to_string()))
}

/// Verify compact (64-byte) or DER signature against `hash` and `pubkey`.
fn verify_sig(sig_bytes: &[u8], pubkey: &[u8], hash: &[u8; 32]) -> Result<(), Bip70Error> {
    let valid = if sig_bytes.len() == 64 {
        let compact: &[u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| Bip70Error::SignatureError("Invalid signature length".to_string()))?;
        let (sigr, sigs) = ecdsa_sig_parse_compact(compact)
            .ok_or_else(|| Bip70Error::SignatureError("Invalid compact signature".to_string()))?;
        let pk = ge_from_pubkey_bytes(pubkey)
            .ok_or_else(|| Bip70Error::SignatureError("Invalid public key".to_string()))?;
        let mut msg = Scalar::zero();
        let _ = msg.set_b32(hash);
        ecdsa_sig_verify(&sigr, &sigs, &pk, &msg)
    } else {
        verify_ecdsa_direct(sig_bytes, pubkey, hash, false, false)
            .ok_or_else(|| Bip70Error::SignatureError("Signature parse error".to_string()))?
    };
    if valid {
        Ok(())
    } else {
        Err(Bip70Error::SignatureError(
            "Signature verification failed".to_string(),
        ))
    }
}

/// Derive compressed public key bytes (33 bytes) from a raw secret key scalar.
fn pubkey_bytes_from_secret(seckey: &[u8; 32]) -> Result<[u8; 33], Bip70Error> {
    let mut sec = Scalar::zero();
    if sec.set_b32(seckey) || sec.is_zero() {
        return Err(Bip70Error::SignatureError("Invalid secret key".to_string()));
    }
    let ge = pubkey_from_secret(&sec);
    Ok(ge_to_compressed(&ge))
}

/// BIP70 Payment Protocol version
pub const PAYMENT_PROTOCOL_VERSION: u32 = 1;

/// Payment Details - Core payment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    /// Network identifier (mainnet, testnet, regtest)
    pub network: String,
    /// Payment outputs (address, amount)
    pub outputs: Vec<PaymentOutput>,
    /// Payment expiration time (Unix timestamp)
    pub time: u64,
    /// Payment expiration time
    pub expires: Option<u64>,
    /// Memo for merchant
    pub memo: Option<String>,
    /// Memo for customer
    pub payment_url: Option<String>,
    /// Merchant data (opaque to customer)
    pub merchant_data: Option<Vec<u8>>,
}

/// Payment Output - Address and amount
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentOutput {
    /// Bitcoin address or script
    pub script: Vec<u8>,
    /// Amount in satoshis (None = all available)
    pub amount: Option<u64>,
}

/// Signed refund address - Pre-authorized refund address with merchant signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRefundAddress {
    /// Refund address/script
    pub address: PaymentOutput,
    /// Merchant signature over address (prevents refund attacks)
    pub signature: Vec<u8>,
}

/// Payment Request - Main payment protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    /// Payment details
    pub payment_details: PaymentDetails,
    /// Merchant's Bitcoin public key (compressed, 33 bytes)
    /// Replaces X.509 certificates with on-chain verifiable keys
    pub merchant_pubkey: Option<Vec<u8>>,
    /// Signature over payment_details by merchant's Bitcoin key
    pub signature: Option<Vec<u8>>,
    /// Pre-authorized refund addresses (signed by merchant)
    /// Prevents refund address attacks by requiring merchant signature
    pub authorized_refund_addresses: Option<Vec<SignedRefundAddress>>,
}

/// Payment - Customer payment transaction(s)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// Serialized transaction(s)
    pub transactions: Vec<Vec<u8>>,
    /// Refund addresses (if change needed)
    pub refund_to: Option<Vec<PaymentOutput>>,
    /// Merchant data (echo back from PaymentRequest)
    pub merchant_data: Option<Vec<u8>>,
    /// Memo from customer
    pub memo: Option<String>,
}

/// Payment ACK - Merchant confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentACK {
    /// Original payment message
    pub payment: Payment,
    /// Confirmation memo from merchant
    pub memo: Option<String>,
    /// Merchant signature over PaymentACK (optional)
    pub signature: Option<Vec<u8>>,
}

impl PaymentACK {
    /// Sign PaymentACK with merchant's private key (raw 32-byte scalar).
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), Bip70Error> {
        let mut ack_for_signing = self.clone();
        ack_for_signing.signature = None;
        let serialized = bincode::serialize(&ack_for_signing)
            .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        self.signature = Some(sign_compact(&hash, private_key)?);
        Ok(())
    }

    /// Verify PaymentACK signature.
    pub fn verify_signature(&self, merchant_pubkey: &[u8]) -> Result<(), Bip70Error> {
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| Bip70Error::SignatureError("No signature".to_string()))?;
        let mut ack = self.clone();
        ack.signature = None;
        let serialized =
            bincode::serialize(&ack).map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        verify_sig(sig, merchant_pubkey, &hash).map_err(|_| {
            Bip70Error::SignatureError("PaymentACK signature verification failed".to_string())
        })
    }
}

impl PaymentRequest {
    /// Create a new payment request
    pub fn new(network: String, outputs: Vec<PaymentOutput>, time: u64) -> Self {
        Self {
            payment_details: PaymentDetails {
                network,
                outputs,
                time,
                expires: None,
                memo: None,
                payment_url: None,
                merchant_data: None,
            },
            merchant_pubkey: None,
            signature: None,
            authorized_refund_addresses: None,
        }
    }

    /// Set merchant public key
    pub fn with_merchant_key(mut self, pubkey: [u8; 33]) -> Self {
        self.merchant_pubkey = Some(pubkey.to_vec());
        self
    }

    /// Add authorized refund address (signed by merchant)
    pub fn with_authorized_refund(mut self, signed_refund: SignedRefundAddress) -> Self {
        if self.authorized_refund_addresses.is_none() {
            self.authorized_refund_addresses = Some(Vec::new());
        }
        self.authorized_refund_addresses
            .as_mut()
            .unwrap()
            .push(signed_refund);
        self
    }

    /// Set expiration time
    pub fn with_expires(mut self, expires: u64) -> Self {
        self.payment_details.expires = Some(expires);
        self
    }

    /// Set memo for merchant
    pub fn with_memo(mut self, memo: String) -> Self {
        self.payment_details.memo = Some(memo);
        self
    }

    /// Set payment URL (where to send Payment message)
    pub fn with_payment_url(mut self, url: String) -> Self {
        self.payment_details.payment_url = Some(url);
        self
    }

    /// Set merchant data (opaque customer data)
    pub fn with_merchant_data(mut self, data: Vec<u8>) -> Self {
        self.payment_details.merchant_data = Some(data);
        self
    }

    /// Sign payment request with merchant's private key (raw 32-byte scalar).
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), Bip70Error> {
        let serialized = bincode::serialize(&self.payment_details)
            .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        let pubkey = pubkey_bytes_from_secret(private_key)?;
        self.signature = Some(sign_compact(&hash, private_key)?);
        self.merchant_pubkey = Some(pubkey.to_vec());
        Ok(())
    }

    /// Verify payment request signature.
    pub fn verify_signature(&self) -> Result<(), Bip70Error> {
        let pubkey = self
            .merchant_pubkey
            .as_ref()
            .ok_or_else(|| Bip70Error::SignatureError("No merchant public key".to_string()))?;
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| Bip70Error::SignatureError("No signature".to_string()))?;
        let serialized = bincode::serialize(&self.payment_details)
            .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        verify_sig(sig, pubkey, &hash)
            .map_err(|_| Bip70Error::SignatureError("Signature verification failed".to_string()))
    }

    /// Validate payment request
    pub fn validate(&self) -> Result<(), Bip70Error> {
        // Check expiration
        if let Some(expires) = self.payment_details.expires {
            let now = crate::time::current_timestamp();
            if now > expires {
                return Err(Bip70Error::Expired);
            }
        }

        // Validate outputs
        if self.payment_details.outputs.is_empty() {
            return Err(Bip70Error::InvalidRequest("No payment outputs".to_string()));
        }

        // Validate network
        let valid_networks = ["main", "test", "regtest"];
        if !valid_networks.contains(&self.payment_details.network.as_str()) {
            return Err(Bip70Error::InvalidRequest(format!(
                "Invalid network: {}",
                self.payment_details.network
            )));
        }

        Ok(())
    }
}

impl Payment {
    /// Create a new payment
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        Self {
            transactions,
            refund_to: None,
            merchant_data: None,
            memo: None,
        }
    }

    /// Add refund address (must be pre-authorized in PaymentRequest)
    pub fn with_refund_to(mut self, outputs: Vec<PaymentOutput>) -> Self {
        self.refund_to = Some(outputs);
        self
    }

    /// Validate refund addresses against PaymentRequest authorized list
    pub fn validate_refund_addresses(
        &self,
        authorized_refunds: &[SignedRefundAddress],
    ) -> Result<(), Bip70Error> {
        if let Some(ref refund_to) = self.refund_to {
            for refund_addr in refund_to {
                // Check if refund address is in authorized list
                let is_authorized = authorized_refunds.iter().any(|auth| {
                    auth.address.script == refund_addr.script
                        && auth.address.amount == refund_addr.amount
                });

                if !is_authorized {
                    return Err(Bip70Error::InvalidPayment(format!(
                        "Refund address not authorized: {:?}",
                        refund_addr.script
                    )));
                }
            }
        }
        Ok(())
    }

    /// Set merchant data (echo from PaymentRequest)
    pub fn with_merchant_data(mut self, data: Vec<u8>) -> Self {
        self.merchant_data = Some(data);
        self
    }

    /// Set customer memo
    pub fn with_memo(mut self, memo: String) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Validate payment
    pub fn validate(&self) -> Result<(), Bip70Error> {
        if self.transactions.is_empty() {
            return Err(Bip70Error::InvalidPayment("No transactions".to_string()));
        }

        Ok(())
    }
}

/// BIP70 Error types
#[derive(Debug, thiserror::Error)]
pub enum Bip70Error {
    #[error("Payment request expired")]
    Expired,

    #[error("Invalid payment request: {0}")]
    InvalidRequest(String),

    #[error("Invalid payment: {0}")]
    InvalidPayment(String),

    #[error("Certificate validation failed: {0}")]
    CertificateError(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// BIP70 Payment Protocol client (for making payments via P2P)
///
/// Note: Node-specific message creation functions are in blvm-node.
/// This struct provides protocol-level validation only.
pub struct PaymentProtocolClient;

impl PaymentProtocolClient {
    /// Validate a PaymentRequest (protocol-level validation)
    pub fn validate_payment_request(
        payment_request: &PaymentRequest,
        expected_merchant_pubkey: Option<&[u8]>,
    ) -> Result<(), Bip70Error> {
        // Verify signature
        payment_request.verify_signature()?;

        // Validate payment request
        payment_request.validate()?;

        // Verify merchant pubkey matches if provided
        if let Some(expected_pubkey) = expected_merchant_pubkey {
            if let Some(ref req_pubkey) = payment_request.merchant_pubkey {
                if req_pubkey.as_slice() != expected_pubkey {
                    return Err(Bip70Error::SignatureError(
                        "PaymentRequest pubkey mismatch".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate PaymentACK from merchant (protocol-level validation)
    pub fn validate_payment_ack(
        payment_ack: &PaymentACK,
        merchant_signature: &[u8],
        merchant_pubkey: &[u8],
    ) -> Result<(), Bip70Error> {
        if let Some(ref sig) = payment_ack.signature {
            if !sig.is_empty() {
                return payment_ack.verify_signature(merchant_pubkey);
            }
        }
        // Legacy: external signature
        if !merchant_signature.is_empty() {
            let mut ack = payment_ack.clone();
            ack.signature = None;
            let serialized = bincode::serialize(&ack)
                .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
            let hash: [u8; 32] = Sha256::digest(&serialized).into();
            verify_sig(merchant_signature, merchant_pubkey, &hash)?;
        }
        Ok(())
    }
}

/// BIP70 Payment Protocol server (for receiving payments via P2P)
///
/// Note: Node-specific message creation functions are in blvm-node.
/// This struct provides protocol-level processing only.
pub struct PaymentProtocolServer;

impl PaymentProtocolServer {
    /// Create signed payment request (protocol-level).
    pub fn create_signed_payment_request(
        details: PaymentDetails,
        merchant_private_key: &[u8; 32],
        authorized_refunds: Option<Vec<SignedRefundAddress>>,
    ) -> Result<PaymentRequest, Bip70Error> {
        let mut payment_request = PaymentRequest {
            payment_details: details,
            merchant_pubkey: None,
            signature: None,
            authorized_refund_addresses: authorized_refunds,
        };
        payment_request.sign(merchant_private_key)?;
        Ok(payment_request)
    }

    /// Process incoming payment (protocol-level validation and ACK creation).
    pub fn process_payment(
        payment: &Payment,
        original_request: &PaymentRequest,
        merchant_private_key: Option<&[u8; 32]>,
    ) -> Result<PaymentACK, Bip70Error> {
        payment.validate()?;
        if let Some(ref authorized_refunds) = original_request.authorized_refund_addresses {
            payment.validate_refund_addresses(authorized_refunds)?;
        }
        if let Some(ref pm_data) = payment.merchant_data {
            if let Some(ref req_data) = original_request.payment_details.merchant_data {
                if pm_data != req_data {
                    return Err(Bip70Error::ValidationError(
                        "Merchant data mismatch".to_string(),
                    ));
                }
            }
        } else if original_request.payment_details.merchant_data.is_some() {
            return Err(Bip70Error::ValidationError(
                "Payment missing merchant data".to_string(),
            ));
        }
        Self::verify_payment_transactions(payment, original_request)?;
        let mut payment_ack = PaymentACK {
            payment: payment.clone(),
            memo: Some("Payment received".to_string()),
            signature: None,
        };
        if let Some(private_key) = merchant_private_key {
            payment_ack.sign(private_key)?;
        }
        Ok(payment_ack)
    }

    /// Verify that payment transactions match PaymentRequest outputs.
    fn verify_payment_transactions(
        payment: &Payment,
        original_request: &PaymentRequest,
    ) -> Result<(), Bip70Error> {
        use crate::Transaction;

        // Deserialize all transactions
        let mut all_outputs = Vec::new();
        for tx_bytes in &payment.transactions {
            let tx: Transaction = bincode::deserialize(tx_bytes)
                .map_err(|e| Bip70Error::SerializationError(format!("Invalid transaction: {e}")))?;

            // Collect all outputs from this transaction
            for output in &tx.outputs {
                all_outputs.push(PaymentOutput {
                    script: output.script_pubkey.clone(),
                    amount: Some(output.value as u64), // Convert i64 to u64
                });
            }
        }

        // Check that all requested outputs are present
        // Note: Payment may include additional outputs (change, refunds), but must include all requested
        for requested_output in &original_request.payment_details.outputs {
            let found = all_outputs.iter().any(|output| {
                output.script == requested_output.script
                    && match (output.amount, requested_output.amount) {
                        (Some(amt), Some(req_amt)) => amt >= req_amt, // Allow overpayment
                        (Some(_), None) => true,                      // Requested "all available"
                        (None, Some(_)) => false, // Output has no amount but request requires one
                        (None, None) => true,     // Both "all available"
                    }
            });

            if !found {
                return Err(Bip70Error::ValidationError(format!(
                    "Payment missing required output: script={}, amount={:?}",
                    hex::encode(&requested_output.script),
                    requested_output.amount
                )));
            }
        }

        Ok(())
    }

    /// Sign a refund address for inclusion in PaymentRequest.
    pub fn sign_refund_address(
        address: PaymentOutput,
        merchant_private_key: &[u8; 32],
    ) -> Result<SignedRefundAddress, Bip70Error> {
        let serialized = bincode::serialize(&address)
            .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        Ok(SignedRefundAddress {
            address,
            signature: sign_compact(&hash, merchant_private_key)?,
        })
    }

    /// Verify signed refund address.
    pub fn verify_refund_address(
        signed_refund: &SignedRefundAddress,
        merchant_pubkey: &[u8],
    ) -> Result<(), Bip70Error> {
        let serialized = bincode::serialize(&signed_refund.address)
            .map_err(|e| Bip70Error::SerializationError(e.to_string()))?;
        let hash: [u8; 32] = Sha256::digest(&serialized).into();
        verify_sig(&signed_refund.signature, merchant_pubkey, &hash).map_err(|_| {
            Bip70Error::SignatureError("Refund address signature verification failed".to_string())
        })
    }
}

// --- CTV covenant types (shared by P2P payment messages and node covenant engine; serde-stable) ---

/// CTV covenant proof for payment commitment
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CovenantProof {
    /// CTV template hash (32 bytes)
    pub template_hash: Hash,
    /// Transaction template structure (without signatures)
    pub transaction_template: TransactionTemplate,
    /// Payment request ID this proof commits to
    pub payment_request_id: String,
    /// Timestamp when proof was created
    pub created_at: u64,
    /// Optional cryptographic signature of the proof
    pub signature: Option<Vec<u8>>,
}

/// Transaction template for CTV (without scriptSig)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionTemplate {
    pub version: u32,
    pub inputs: Vec<TemplateInput>,
    pub outputs: Vec<TemplateOutput>,
    pub lock_time: u32,
}

/// Template input (CTV format: no scriptSig)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateInput {
    pub prevout_hash: Hash,
    pub prevout_index: u32,
    pub sequence: u32,
}

/// Template output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Settlement status for payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettlementStatus {
    /// Payment proof created, not yet broadcast
    ProofCreated,
    /// Payment proof broadcast, transaction not yet in mempool
    ProofBroadcast,
    /// Transaction in mempool, waiting for confirmation
    InMempool { tx_hash: Hash },
    /// Settlement confirmed on-chain
    Settled {
        tx_hash: Hash,
        block_hash: Hash,
        confirmation_count: u32,
    },
    /// Payment failed or rejected
    Failed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_request_creation() {
        let output = PaymentOutput {
            script: vec![blvm_consensus::opcodes::OP_1],
            amount: Some(100000), // 0.001 BTC
        };

        let request = PaymentRequest::new("main".to_string(), vec![output], 1234567890);

        assert_eq!(request.payment_details.network, "main");
        assert_eq!(request.payment_details.outputs.len(), 1);
        assert_eq!(request.payment_details.time, 1234567890);
    }

    #[test]
    fn test_payment_request_validation() {
        let request = PaymentRequest::new(
            "main".to_string(),
            vec![PaymentOutput {
                script: vec![blvm_consensus::opcodes::OP_1],
                amount: Some(100000),
            }],
            1234567890,
        );

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_payment_request_expired() {
        let expired_time = 1000;
        let request = PaymentRequest::new(
            "main".to_string(),
            vec![PaymentOutput {
                script: vec![blvm_consensus::opcodes::OP_1],
                amount: Some(100000),
            }],
            expired_time,
        )
        .with_expires(1001);

        // Should fail validation (expired)
        let result = request.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_payment_creation() {
        let tx = vec![0x01, 0x00, 0x00, 0x00]; // Arbitrary bytes for Payment::new structure test (not a valid tx)
        let payment = Payment::new(vec![tx.clone()]);

        assert_eq!(payment.transactions.len(), 1);
        assert_eq!(payment.transactions[0], tx);
    }

    #[test]
    fn test_payment_validation() {
        let payment = Payment::new(vec![vec![0x01, 0x02, 0x03]]);
        assert!(payment.validate().is_ok());

        let empty_payment = Payment::new(vec![]);
        assert!(empty_payment.validate().is_err());
    }
}
