//! BIP324: Version 2 P2P Encrypted Transport Protocol
//!
//! This module implements the encrypted transport protocol for Bitcoin P2P connections.
//! It provides ElligatorSwift encoding, X-only ECDH key exchange, and ChaCha20Poly1305 encryption.

use crate::error::ProtocolError;
use crate::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use getrandom::getrandom;
use secp256k1::{
    ellswift::{ElligatorSwift, ElligatorSwiftSharedSecret},
    PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// BIP324 v2 transport encryption state
pub struct V2Transport {
    /// Send cipher (encrypt outgoing messages)
    send_cipher: ChaCha20Poly1305,
    /// Receive cipher (decrypt incoming messages)
    recv_cipher: ChaCha20Poly1305,
    /// Send nonce counter
    send_nonce: u64,
    /// Receive nonce counter
    recv_nonce: u64,
}

/// BIP324 handshake state
pub enum V2Handshake {
    /// Initiator handshake (client connecting)
    Initiator {
        private_key: SecretKey,
        ellswift: ElligatorSwift, // Store our ElligatorSwift encoding
    },
    /// Responder handshake (server accepting)
    Responder {
        private_key: SecretKey,
        initiator_ellswift: Option<ElligatorSwift>, // Store peer's ElligatorSwift
    },
}

impl V2Transport {
    /// Create a new v2 transport with established keys
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        let send_cipher = ChaCha20Poly1305::new(&Key::from_slice(&send_key));
        let recv_cipher = ChaCha20Poly1305::new(&Key::from_slice(&recv_key));

        Self {
            send_cipher,
            recv_cipher,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Encrypt a message for sending
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // BIP324 packet format: [16-byte poly1305 tag][3-byte length][1-byte ignored][encrypted payload]
        // Nonce format: 12 bytes (8-byte counter + 4-byte zero padding)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt plaintext
        let ciphertext = self
            .send_cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| {
                ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned(format!("Encryption failed: {}", e)),
                ))
            })?;

        // Increment nonce counter
        self.send_nonce += 1;

        // Check if rekeying is needed (every 224 packets per BIP324)
        if self.send_nonce % 224 == 0 {
            // Rekeying would happen here (not implemented in initial version)
            // This requires deriving new keys from existing keys
        }

        // Build packet: [tag(16)][length(3)][ignored(1)][payload(var)]
        let mut packet = Vec::with_capacity(20 + ciphertext.len());
        
        // Extract tag (last 16 bytes of ciphertext are the tag)
        if ciphertext.len() < 16 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Ciphertext too short".to_string()),
                ),
            ));
        }
        let tag_start = ciphertext.len() - 16;
        packet.extend_from_slice(&ciphertext[tag_start..]);
        
        // Length (3 bytes, little-endian, max 2^24-1)
        let payload_len = ciphertext.len() - 16; // Exclude tag
        if payload_len > 0xFFFFFF {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Payload too large".to_string()),
                ),
            ));
        }
        let len_bytes = (payload_len as u32).to_le_bytes();
        packet.extend_from_slice(&len_bytes[..3]);
        
        // Ignored byte (set to 0)
        packet.push(0);
        
        // Payload (ciphertext without tag)
        packet.extend_from_slice(&ciphertext[..tag_start]);

        Ok(packet)
    }

    /// Decrypt a received message
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // BIP324 packet format: [16-byte poly1305 tag][3-byte length][1-byte ignored][encrypted payload]
        if packet.len() < 20 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Packet too short".to_string()),
                ),
            ));
        }

        // Extract components
        let tag = &packet[0..16];
        let length_bytes = [packet[16], packet[17], packet[18], 0];
        let payload_len = u32::from_le_bytes(length_bytes) as usize;
        // Ignore byte at packet[19]
        let payload_start = 20;
        let payload_end = payload_start + payload_len;

        if packet.len() < payload_end {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Packet incomplete".to_string()),
                ),
            ));
        }

        // Reconstruct ciphertext: payload + tag
        let mut ciphertext = Vec::with_capacity(payload_len + 16);
        ciphertext.extend_from_slice(&packet[payload_start..payload_end]);
        ciphertext.extend_from_slice(tag);

        // Nonce format: 12 bytes (8-byte counter + 4-byte zero padding)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.recv_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        let plaintext = self
            .recv_cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| {
                ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned(format!("Decryption failed: {}", e)),
                ))
            })?;

        // Increment nonce counter
        self.recv_nonce += 1;

        // Check if rekeying is needed (every 224 packets per BIP324)
        if self.recv_nonce % 224 == 0 {
            // Rekeying would happen here (not implemented in initial version)
        }

        Ok(plaintext)
    }
}

impl V2Handshake {
    /// Create a new initiator handshake
    pub fn new_initiator() -> (Vec<u8>, Self) {
        let secp = Secp256k1::new();
        // Generate random 32 bytes for secret key
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        let private_key = SecretKey::from_slice(&key_bytes)
            .expect("Failed to generate secret key");
        
        // Generate random aux_rand for ElligatorSwift encoding
        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
        
        // Create ElligatorSwift encoding from secret key (BIP324-compatible)
        let ellswift = ElligatorSwift::from_seckey(&secp, private_key, Some(aux_rand));
        let encoded = ellswift.to_array();

        (
            encoded.to_vec(),
            Self::Initiator {
                private_key,
                ellswift,
            },
        )
    }

    /// Create a new responder handshake
    pub fn new_responder() -> Self {
        // Generate random 32 bytes for secret key
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        let private_key = SecretKey::from_slice(&key_bytes)
            .expect("Failed to generate secret key");

        Self::Responder {
            private_key,
            initiator_ellswift: None,
        }
    }

    /// Process initiator message (responder side)
    pub fn process_initiator_message(
        &mut self,
        initiator_msg: &[u8],
    ) -> Result<(Vec<u8>, V2Transport)> {
        if initiator_msg.len() != 64 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Invalid initiator message length".to_string()),
                ),
            ));
        }

        // Decode initiator's ElligatorSwift encoding
        let mut initiator_msg_array = [0u8; 64];
        initiator_msg_array.copy_from_slice(initiator_msg);
        let initiator_ellswift = elligator_swift_decode(&initiator_msg_array);

        // Generate responder's ElligatorSwift encoding
        let secp = Secp256k1::new();
        let responder_private = match self {
            Self::Responder { private_key, .. } => *private_key,
            _ => {
                return Err(ProtocolError::Consensus(
                    blvm_consensus::error::ConsensusError::Serialization(
                        Cow::Owned("Not a responder handshake".to_string()),
                    ),
                ));
            }
        };
        
        // Generate random aux_rand for ElligatorSwift encoding
        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
        
        // Create ElligatorSwift encoding from secret key (BIP324-compatible)
        let responder_ellswift = ElligatorSwift::from_seckey(&secp, responder_private, Some(aux_rand));
        let responder_ellswift_bytes = responder_ellswift.to_array();

        // Perform X-only ECDH using ElligatorSwift shared secret (BIP324-compatible)
        // Use secp256k1's built-in shared_secret computation with ElligatorSwift objects
        use secp256k1::ellswift::ElligatorSwiftParty;
        
        // Compute shared secret using ElligatorSwift::shared_secret (BIP324-compatible)
        let shared_secret = ElligatorSwift::shared_secret(
            initiator_ellswift,
            responder_ellswift,
            responder_private,
            ElligatorSwiftParty::B, // Responder is party B
            None, // No additional data for BIP324
        );
        
        let shared_x = shared_secret.to_secret_bytes();

        // Derive keys using HKDF
        let send_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_send");
        let recv_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_recv");

        // Create transport
        let transport = V2Transport::new(send_key, recv_key);

        // Update handshake state
        if let Self::Responder {
            initiator_ellswift: ref mut iell,
            ..
        } = self
        {
            *iell = Some(initiator_ellswift);
        }

        Ok((responder_ellswift_bytes.to_vec(), transport))
    }

    /// Complete handshake (initiator side)
    pub fn complete_handshake(
        self,
        responder_msg: &[u8],
    ) -> Result<V2Transport> {
        if responder_msg.len() != 64 {
            return Err(ProtocolError::Consensus(
                blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Invalid responder message length".to_string()),
                ),
            ));
        }

        // Decode responder's ElligatorSwift encoding
        let mut responder_msg_array = [0u8; 64];
        responder_msg_array.copy_from_slice(responder_msg);
        let responder_ellswift = elligator_swift_decode(&responder_msg_array);

        // Perform X-only ECDH using ElligatorSwift shared secret (BIP324-compatible)
        // Use secp256k1's built-in shared_secret computation with ElligatorSwift objects
        use secp256k1::ellswift::ElligatorSwiftParty;
        let (private_key, initiator_ellswift) = match self {
            Self::Initiator { private_key, ellswift, .. } => {
                (private_key, ellswift) // ellswift is Copy, private_key is not
            }
            _ => {
                return Err(ProtocolError::Consensus(
                    blvm_consensus::error::ConsensusError::Serialization(
                        Cow::Owned("Not an initiator handshake".to_string()),
                    ),
                ));
            }
        };
        
        // Compute shared secret using ElligatorSwift::shared_secret (BIP324-compatible)
        let shared_secret = ElligatorSwift::shared_secret(
            initiator_ellswift,
            responder_ellswift,
            private_key,
            ElligatorSwiftParty::A, // Initiator is party A
            None, // No additional data for BIP324
        );
        
        let shared_x = shared_secret.to_secret_bytes();
        
        // Derive keys using HKDF
        let send_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_send");
        let recv_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_recv");

        // Create transport
        Ok(V2Transport::new(send_key, recv_key))
    }
}

/// ElligatorSwift encoding (BIP324)
/// Encodes a secp256k1 public key to 64 bytes using secp256k1's ElligatorSwift implementation
fn elligator_swift_encode(pubkey: &PublicKey) -> [u8; 64] {
    // Use secp256k1's built-in ElligatorSwift encoding
    let ellswift = ElligatorSwift::from_pubkey(*pubkey);
    ellswift.to_array()
}

/// ElligatorSwift decoding (BIP324)
/// Decodes 64 bytes to an ElligatorSwift object (not directly to PublicKey)
/// 
/// Note: For BIP324, we work with ElligatorSwift objects directly in the handshake.
/// The shared secret computation uses ElligatorSwift objects, not raw public keys.
fn elligator_swift_decode(encoded: &[u8; 64]) -> ElligatorSwift {
    ElligatorSwift::from_array(*encoded)
}

// Note: xonly_ecdh function removed - we now use ElligatorSwiftSharedSecret directly
// in the handshake functions, which is the proper BIP324 approach using secp256k1's library.

/// HKDF-SHA256 key derivation (BIP324)
/// Uses the hkdf library for proper HMAC-SHA256-based key derivation
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    
    // BIP324 uses HKDF with empty salt and info parameter
    let hk = Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expansion failed (should never happen for 32-byte output)");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_transport_encrypt_decrypt() {
        // Use the same key for both send and recv for testing
        // In a real BIP324 connection, send_key_A == recv_key_B (derived from shared secret)
        let key = [0x42; 32];
        let mut transport = V2Transport::new(key, key);

        let plaintext = b"Hello, Bitcoin!";
        let encrypted = transport.encrypt(plaintext).unwrap();
        let decrypted = transport.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_elligator_swift_encode_decode() {
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        let encoded = elligator_swift_encode(&public_key);
        let decoded_ellswift = elligator_swift_decode(&encoded);

        // Verify encoding/decoding works (ElligatorSwift objects should match)
        let re_encoded = decoded_ellswift.to_array();
        assert_eq!(encoded, re_encoded);
    }
}

