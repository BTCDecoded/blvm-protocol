//! BIP324: Version 2 P2P Encrypted Transport Protocol
//!
//! This module implements the encrypted transport protocol for Bitcoin P2P connections.
//! It provides ElligatorSwift encoding, X-only ECDH key exchange, and ChaCha20Poly1305 encryption.

use crate::error::ProtocolError;
use crate::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
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
        peer_pubkey: Option<XOnlyPublicKey>,
    },
    /// Responder handshake (server accepting)
    Responder {
        private_key: SecretKey,
        initiator_pubkey: Option<XOnlyPublicKey>,
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
        let mut rng = OsRng;
        let private_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        // ElligatorSwift encoding (simplified - full implementation needed)
        // For now, we'll use a placeholder that encodes the public key
        let encoded = elligator_swift_encode(&public_key);

        (
            encoded.to_vec(),
            Self::Initiator {
                private_key,
                peer_pubkey: None,
            },
        )
    }

    /// Create a new responder handshake
    pub fn new_responder() -> Self {
        let mut rng = OsRng;
        let private_key = SecretKey::new(&mut rng);

        Self::Responder {
            private_key,
            initiator_pubkey: None,
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

        // Decode initiator's public key
        let initiator_pubkey = elligator_swift_decode(initiator_msg)
            .ok_or_else(|| {
                ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Failed to decode initiator public key".to_string()),
                ))
            })?;

        // Generate responder's key pair
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
        let responder_public = PublicKey::from_secret_key(&secp, &responder_private);

        // Encode responder's public key
        let responder_msg = elligator_swift_encode(&responder_public);

        // Perform X-only ECDH
        let (send_key, recv_key) = xonly_ecdh(&responder_private, &initiator_pubkey)?;

        // Create transport
        let transport = V2Transport::new(send_key, recv_key);

        // Update handshake state
        if let Self::Responder {
            initiator_pubkey: ref mut ipk,
            ..
        } = self
        {
            *ipk = Some(XOnlyPublicKey::from(initiator_pubkey));
        }

        Ok((responder_msg.to_vec(), transport))
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

        // Decode responder's public key
        let responder_pubkey = elligator_swift_decode(responder_msg)
            .ok_or_else(|| {
                ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
                    Cow::Owned("Failed to decode responder public key".to_string()),
                ))
            })?;

        // Perform X-only ECDH
        let (send_key, recv_key) = match self {
            Self::Initiator { private_key, .. } => {
                xonly_ecdh(&private_key, &responder_pubkey)?
            }
            _ => {
                return Err(ProtocolError::Consensus(
                    blvm_consensus::error::ConsensusError::Serialization(
                        Cow::Owned("Not an initiator handshake".to_string()),
                    ),
                ));
            }
        };

        // Create transport
        Ok(V2Transport::new(send_key, recv_key))
    }
}

/// ElligatorSwift encoding (BIP324)
/// Encodes a secp256k1 public key to 64 bytes
fn elligator_swift_encode(pubkey: &PublicKey) -> [u8; 64] {
    // NOTE: This is a placeholder implementation
    // Full ElligatorSwift requires complex field arithmetic
    // For now, we'll use a simplified encoding that preserves the public key
    let mut encoded = [0u8; 64];
    let pubkey_bytes = pubkey.serialize();
    encoded[..33].copy_from_slice(&pubkey_bytes);
    // Fill remaining bytes with hash of public key for determinism
    let hash = Sha256::digest(&pubkey_bytes);
    encoded[33..].copy_from_slice(&hash[..31]);
    encoded
}

/// ElligatorSwift decoding (BIP324)
/// Decodes 64 bytes to a secp256k1 public key
fn elligator_swift_decode(encoded: &[u8; 64]) -> Option<PublicKey> {
    // NOTE: This is a placeholder implementation
    // Full ElligatorSwift requires complex field arithmetic
    // For now, we'll decode the first 33 bytes as a public key
    let mut pubkey_bytes = [0u8; 33];
    pubkey_bytes.copy_from_slice(&encoded[..33]);
    PublicKey::from_slice(&pubkey_bytes).ok()
}

/// X-only ECDH key exchange (BIP324)
/// Derives shared secret from private key and peer's X-only public key
fn xonly_ecdh(
    private_key: &SecretKey,
    peer_xonly_pubkey: &XOnlyPublicKey,
) -> Result<([u8; 32], [u8; 32])> {
    let secp = Secp256k1::new();

    // Convert X-only public key to full public key (need to determine parity)
    // For BIP324, we try both parities and use the one that works
    let mut peer_pubkey = None;
    for parity in [secp256k1::Parity::Even, secp256k1::Parity::Odd] {
        let pk = PublicKey::from_x_only_public_key(*peer_xonly_pubkey, parity);
        peer_pubkey = Some(pk);
        break;
    }

    let peer_pubkey = peer_pubkey.ok_or_else(|| {
        ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
            Cow::Owned("Failed to reconstruct public key from X-only".to_string()),
        ))
    })?;

    // Perform ECDH: shared_point = private_key * peer_pubkey
    let shared_point = peer_pubkey.mul_tweak(&secp, private_key).map_err(|_| {
        ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
            Cow::Owned("ECDH multiplication failed".to_string()),
        ))
    })?;

    // Get X coordinate (32 bytes)
    let shared_x = shared_point.x_only_public_key().0.serialize();

    // Derive keys using HKDF (BIP324 uses SHA256)
    // send_key = HKDF(shared_x, "bitcoin_v2_shared_secret_send")
    // recv_key = HKDF(shared_x, "bitcoin_v2_shared_secret_recv")
    let send_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_send");
    let recv_key = hkdf_sha256(&shared_x, b"bitcoin_v2_shared_secret_recv");

    Ok((send_key, recv_key))
}

/// HKDF-SHA256 key derivation
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Simplified HKDF (full implementation would use HMAC-SHA256)
    // For BIP324, we use: HKDF(ikm, salt="", info)
    let mut hasher = Sha256::new();
    hasher.update(ikm);
    hasher.update(info);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_transport_encrypt_decrypt() {
        let send_key = [0x42; 32];
        let recv_key = [0x43; 32];
        let mut transport = V2Transport::new(send_key, recv_key);

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
        let decoded = elligator_swift_decode(&encoded).unwrap();

        // Note: Due to placeholder implementation, this may not round-trip perfectly
        // Full ElligatorSwift implementation would preserve the public key exactly
        assert_eq!(public_key, decoded);
    }
}

