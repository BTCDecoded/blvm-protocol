//! BIP324 version 2 P2P encrypted transport.
//!
//! Key schedule, garbage terminators, and packet framing follow the specification.
//! The length field is FSChaCha20. The header and contents are FSChaCha20-Poly1305.

use crate::Result;
use crate::error::ProtocolError;
use blvm_secp256k1::ellswift::{ellswift_create, ellswift_xdh};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::getrandom;
use hkdf::Hkdf;
use sha2::Sha256;
use std::borrow::Cow;

/// Rekey after this many packets in one direction.
const REKEY_INTERVAL: u64 = 224;
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
/// Garbage longer than this is not a valid handshake.
pub const GARBAGE_MAX: usize = 4095;

/// `magic || "version" || five zero bytes`. A v1 connection begins with these 16 bytes.
pub fn v1_version_prefix(magic: [u8; 4]) -> [u8; 16] {
    let mut prefix = [0u8; 16];
    prefix[..4].copy_from_slice(&magic);
    prefix[4..].copy_from_slice(b"version\x00\x00\x00\x00\x00");
    prefix
}

/// Keys derived from one ECDH shared secret.
#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub initiator_l: [u8; 32],
    pub initiator_p: [u8; 32],
    pub responder_l: [u8; 32],
    pub responder_p: [u8; 32],
    pub send_garbage_terminator: [u8; 16],
    pub recv_garbage_terminator: [u8; 16],
    pub session_id: [u8; 32],
}

/// Outbound length and content ciphers.
pub struct V2Send {
    send_l: FsChaCha20,
    send_p: FsChaCha20Poly1305,
}

/// Inbound length and content ciphers.
pub struct V2Recv {
    recv_l: FsChaCha20,
    recv_p: FsChaCha20Poly1305,
}

/// Packet encryption state for one direction pair.
pub struct V2Transport {
    send: V2Send,
    recv: V2Recv,
}

/// A finished handshake. Terminators and the session id stay with the ciphers.
pub struct V2Session {
    transport: V2Transport,
    pub session_id: [u8; 32],
    pub send_garbage_terminator: [u8; 16],
    pub recv_garbage_terminator: [u8; 16],
}

/// Initiator state after the ellswift and garbage have been chosen.
pub struct InitiatorPending {
    private_key: [u8; 32],
    ellswift: [u8; 64],
    garbage: Vec<u8>,
}

/// Responder state after the shared secret, before its garbage and version packet are sent.
pub struct ResponderPending {
    ellswift: [u8; 64],
    session: V2Session,
    garbage: Vec<u8>,
}

/// BIP324 handshake state.
pub enum V2Handshake {
    Initiator {
        private_key: [u8; 32],
        ellswift: [u8; 64],
    },
    Responder {
        private_key: [u8; 32],
        initiator_ellswift: Option<[u8; 64]>,
    },
}

struct FsChaCha20 {
    key: [u8; 32],
    block_counter: u32,
    chunk_counter: u64,
    keystream: Vec<u8>,
}

struct FsChaCha20Poly1305 {
    key: [u8; 32],
    packet_counter: u64,
}

fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }
    let mut init = [0u32; 16];
    init[0] = 0x6170_7865;
    init[1] = 0x3320_646e;
    init[2] = 0x7962_2d32;
    init[3] = 0x6b20_6574;
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut state = init;
    for _ in 0..10 {
        quarter(&mut state, 0, 4, 8, 12);
        quarter(&mut state, 1, 5, 9, 13);
        quarter(&mut state, 2, 6, 10, 14);
        quarter(&mut state, 3, 7, 11, 15);
        quarter(&mut state, 0, 5, 10, 15);
        quarter(&mut state, 1, 6, 11, 12);
        quarter(&mut state, 2, 7, 8, 13);
        quarter(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(init[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

impl FsChaCha20 {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            block_counter: 0,
            chunk_counter: 0,
            keystream: Vec::new(),
        }
    }

    fn keystream_bytes(&mut self, nbytes: usize) -> Vec<u8> {
        while self.keystream.len() < nbytes {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&(self.chunk_counter / REKEY_INTERVAL).to_le_bytes());
            self.keystream.extend_from_slice(&chacha20_block(
                &self.key,
                &nonce,
                self.block_counter,
            ));
            self.block_counter += 1;
        }
        let out = self.keystream[..nbytes].to_vec();
        self.keystream.drain(..nbytes);
        out
    }

    fn crypt(&mut self, chunk: &[u8]) -> Vec<u8> {
        let ks = self.keystream_bytes(chunk.len());
        let out: Vec<u8> = chunk.iter().zip(ks).map(|(b, k)| b ^ k).collect();
        if (self.chunk_counter + 1) % REKEY_INTERVAL == 0 {
            let next = self.keystream_bytes(32);
            self.key.copy_from_slice(&next);
            self.block_counter = 0;
        }
        self.chunk_counter += 1;
        out
    }
}

impl FsChaCha20Poly1305 {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            packet_counter: 0,
        }
    }

    fn crypt(&mut self, aad: &[u8], text: &[u8], decrypt: bool) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&((self.packet_counter % REKEY_INTERVAL) as u32).to_le_bytes());
        nonce[4..].copy_from_slice(&(self.packet_counter / REKEY_INTERVAL).to_le_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce_ref = Nonce::from_slice(&nonce);
        let payload = Payload { msg: text, aad };
        let ret = if decrypt {
            cipher.decrypt(nonce_ref, payload)
        } else {
            cipher.encrypt(nonce_ref, payload)
        }
        .map_err(|_| protocol_err("packet authentication failed"))?;
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0 {
            let mut rekey_nonce = nonce;
            rekey_nonce[..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
            let rekey = ChaCha20Poly1305::new(Key::from_slice(&self.key));
            let mixed = rekey
                .encrypt(
                    Nonce::from_slice(&rekey_nonce),
                    Payload {
                        msg: &[0u8; 32],
                        aad: &[],
                    },
                )
                .map_err(|_| protocol_err("rekey failed"))?;
            self.key.copy_from_slice(&mixed[..32]);
        }
        self.packet_counter += 1;
        Ok(ret)
    }
}

fn protocol_err(msg: &str) -> ProtocolError {
    ProtocolError::Consensus(blvm_consensus::error::ConsensusError::Serialization(
        Cow::Owned(msg.to_string()),
    ))
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out)
        .expect("HKDF expansion fits in 255 blocks");
}

/// Derive the session keys. `initiating` selects which pair this peer sends with.
pub fn session_keys(shared_secret: &[u8; 32], initiating: bool, magic: [u8; 4]) -> SessionKeys {
    let mut salt = b"bitcoin_v2_shared_secret".to_vec();
    salt.extend_from_slice(&magic);
    let mut initiator_l = [0u8; 32];
    let mut initiator_p = [0u8; 32];
    let mut responder_l = [0u8; 32];
    let mut responder_p = [0u8; 32];
    let mut garbage = [0u8; 32];
    let mut session_id = [0u8; 32];
    hkdf_sha256(&salt, shared_secret, b"initiator_L", &mut initiator_l);
    hkdf_sha256(&salt, shared_secret, b"initiator_P", &mut initiator_p);
    hkdf_sha256(&salt, shared_secret, b"responder_L", &mut responder_l);
    hkdf_sha256(&salt, shared_secret, b"responder_P", &mut responder_p);
    hkdf_sha256(&salt, shared_secret, b"garbage_terminators", &mut garbage);
    hkdf_sha256(&salt, shared_secret, b"session_id", &mut session_id);
    let (send_garbage, recv_garbage) = if initiating {
        (
            garbage[..16].try_into().unwrap(),
            garbage[16..].try_into().unwrap(),
        )
    } else {
        (
            garbage[16..].try_into().unwrap(),
            garbage[..16].try_into().unwrap(),
        )
    };
    SessionKeys {
        initiator_l,
        initiator_p,
        responder_l,
        responder_p,
        send_garbage_terminator: send_garbage,
        recv_garbage_terminator: recv_garbage,
        session_id,
    }
}

impl SessionKeys {
    fn transport(self, initiating: bool) -> V2Transport {
        let (send_l, send_p, recv_l, recv_p) = if initiating {
            (
                self.initiator_l,
                self.initiator_p,
                self.responder_l,
                self.responder_p,
            )
        } else {
            (
                self.responder_l,
                self.responder_p,
                self.initiator_l,
                self.initiator_p,
            )
        };
        V2Transport {
            send: V2Send {
                send_l: FsChaCha20::new(send_l),
                send_p: FsChaCha20Poly1305::new(send_p),
            },
            recv: V2Recv {
                recv_l: FsChaCha20::new(recv_l),
                recv_p: FsChaCha20Poly1305::new(recv_p),
            },
        }
    }

    fn into_session(self, initiating: bool) -> V2Session {
        let session_id = self.session_id;
        let send_garbage_terminator = self.send_garbage_terminator;
        let recv_garbage_terminator = self.recv_garbage_terminator;
        V2Session {
            transport: self.transport(initiating),
            session_id,
            send_garbage_terminator,
            recv_garbage_terminator,
        }
    }
}

impl V2Send {
    /// Encrypt contents. The ignore bit is clear and there is no associated data.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_packet(plaintext, &[], false)
    }

    /// Encrypt one packet. `ignore` sets the header bit. `aad` is authenticated with this packet only.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Result<Vec<u8>> {
        if contents.len() > 0x00ff_ffff {
            return Err(protocol_err("contents longer than 2^24-1"));
        }
        let mut plain = Vec::with_capacity(1 + contents.len());
        plain.push(if ignore { 0x80 } else { 0 });
        plain.extend_from_slice(contents);
        let body = self.send_p.crypt(aad, &plain, false)?;
        let len = (contents.len() as u32).to_le_bytes();
        let enc_len = self.send_l.crypt(&len[..3]);
        let mut packet = enc_len;
        packet.extend_from_slice(&body);
        Ok(packet)
    }
}

impl V2Recv {
    /// Decrypt the 3-byte length and return the contents length.
    pub fn decrypt_length(&mut self, enc_len: &[u8]) -> Result<usize> {
        if enc_len.len() != 3 {
            return Err(protocol_err("length is 3 bytes"));
        }
        let len_bytes = self.recv_l.crypt(enc_len);
        Ok(u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], 0]) as usize)
    }

    /// Decrypt the header byte and contents. The length cipher is not touched.
    pub fn decrypt_body(&mut self, body: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        let plain = self.recv_p.crypt(aad, body, true)?;
        if plain.is_empty() {
            return Err(protocol_err("decrypted packet has no header"));
        }
        let ignore = plain[0] & 0x80 != 0;
        Ok((plain[1..].to_vec(), ignore))
    }

    /// Decrypt one packet and return its contents.
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_packet(packet, &[])
            .map(|(contents, _)| contents)
    }

    /// Decrypt one packet. Returns the contents and the ignore bit.
    pub fn decrypt_packet(&mut self, packet: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        if packet.len() < 3 + 1 + 16 {
            return Err(protocol_err("packet too short"));
        }
        let contents_len = self.decrypt_length(&packet[..3])?;
        let body_len = 1 + contents_len + 16;
        if packet.len() != 3 + body_len {
            return Err(protocol_err("packet length does not match"));
        }
        let (contents, ignore) = self.decrypt_body(&packet[3..], aad)?;
        if contents.len() != contents_len {
            return Err(protocol_err("decrypted contents length mismatch"));
        }
        Ok((contents, ignore))
    }
}

impl V2Transport {
    /// Same key on the length and content ciphers, in both directions. For round-trip tests.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send: V2Send {
                send_l: FsChaCha20::new(send_key),
                send_p: FsChaCha20Poly1305::new(send_key),
            },
            recv: V2Recv {
                recv_l: FsChaCha20::new(recv_key),
                recv_p: FsChaCha20Poly1305::new(recv_key),
            },
        }
    }

    /// Encrypt contents. The ignore bit is clear and there is no associated data.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.send.encrypt(plaintext)
    }

    /// Decrypt one packet and return its contents.
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.recv.decrypt(packet)
    }

    /// Encrypt one packet. `ignore` sets the header bit. `aad` is authenticated with this packet only.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Result<Vec<u8>> {
        self.send.encrypt_packet(contents, aad, ignore)
    }

    /// Decrypt one packet. Returns the contents and the ignore bit.
    pub fn decrypt_packet(&mut self, packet: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.recv.decrypt_packet(packet, aad)
    }

    /// Decrypt the 3-byte length and return the contents length.
    pub fn decrypt_length(&mut self, enc_len: &[u8]) -> Result<usize> {
        self.recv.decrypt_length(enc_len)
    }

    /// Decrypt the header byte and contents.
    pub fn decrypt_body(&mut self, body: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.recv.decrypt_body(body, aad)
    }
}

impl V2Session {
    /// Encrypt contents. The ignore bit is clear and there is no associated data.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.transport.encrypt(plaintext)
    }

    /// Decrypt one packet and return its contents.
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.transport.decrypt(packet)
    }

    /// Encrypt one packet. `ignore` sets the header bit. `aad` is authenticated with this packet only.
    pub fn encrypt_packet(&mut self, contents: &[u8], aad: &[u8], ignore: bool) -> Result<Vec<u8>> {
        self.transport.encrypt_packet(contents, aad, ignore)
    }

    /// Decrypt one packet. Returns the contents and the ignore bit.
    pub fn decrypt_packet(&mut self, packet: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.transport.decrypt_packet(packet, aad)
    }

    /// Decrypt the 3-byte length and return the contents length.
    pub fn decrypt_length(&mut self, enc_len: &[u8]) -> Result<usize> {
        self.transport.decrypt_length(enc_len)
    }

    /// Decrypt the header byte and contents.
    pub fn decrypt_body(&mut self, body: &[u8], aad: &[u8]) -> Result<(Vec<u8>, bool)> {
        self.transport.decrypt_body(body, aad)
    }

    /// Separate the directions so a reader and a writer can own one each.
    pub fn split(self) -> (V2Send, V2Recv) {
        (self.transport.send, self.transport.recv)
    }
}

fn shared_secret(
    ours: &[u8; 64],
    theirs: &[u8; 64],
    private_key: &[u8; 32],
    initiating: bool,
) -> Result<[u8; 32]> {
    let secret = if initiating {
        ellswift_xdh(ours, theirs, private_key, false)
    } else {
        ellswift_xdh(theirs, ours, private_key, true)
    };
    secret.ok_or_else(|| protocol_err("ElligatorSwift ECDH failed"))
}

fn transport_from_secret(secret: &[u8; 32], initiating: bool) -> V2Transport {
    session_keys(secret, initiating, MAINNET_MAGIC).transport(initiating)
}

impl V2Handshake {
    /// Create a new initiator handshake. The bytes are the 64-byte ellswift opening.
    pub fn new_initiator() -> (Vec<u8>, Self) {
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
        let ellswift = ellswift_create(&key_bytes, Some(&aux_rand))
            .expect("Failed to create ElligatorSwift encoding");
        (
            ellswift.to_vec(),
            Self::Initiator {
                private_key: key_bytes,
                ellswift,
            },
        )
    }

    /// Create a new responder handshake.
    pub fn new_responder() -> Self {
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).expect("Failed to generate random bytes");
        Self::Responder {
            private_key: key_bytes,
            initiator_ellswift: None,
        }
    }

    /// Process the initiator opening. Returns this side's ellswift and the receive transport.
    pub fn process_initiator_message(
        &mut self,
        initiator_msg: &[u8],
    ) -> Result<(Vec<u8>, V2Transport)> {
        if initiator_msg.len() != 64 {
            return Err(protocol_err("Invalid initiator message length"));
        }
        let mut initiator_ell64 = [0u8; 64];
        initiator_ell64.copy_from_slice(initiator_msg);
        let responder_private = match self {
            Self::Responder { private_key, .. } => *private_key,
            _ => return Err(protocol_err("Not a responder handshake")),
        };
        let mut aux_rand = [0u8; 32];
        getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
        let responder_ell64 = ellswift_create(&responder_private, Some(&aux_rand))
            .expect("Failed to create ElligatorSwift encoding");
        let secret = shared_secret(
            &responder_ell64,
            &initiator_ell64,
            &responder_private,
            false,
        )?;
        if let Self::Responder {
            initiator_ellswift, ..
        } = self
        {
            *initiator_ellswift = Some(initiator_ell64);
        }
        Ok((
            responder_ell64.to_vec(),
            transport_from_secret(&secret, false),
        ))
    }

    /// Complete the initiator handshake with the responder's 64-byte ellswift.
    pub fn complete_handshake(self, responder_msg: &[u8]) -> Result<V2Transport> {
        if responder_msg.len() != 64 {
            return Err(protocol_err("Invalid responder message length"));
        }
        let mut responder_ell64 = [0u8; 64];
        responder_ell64.copy_from_slice(responder_msg);
        let (private_key, initiator_ell64) = match self {
            Self::Initiator {
                private_key,
                ellswift,
            } => (private_key, ellswift),
            _ => return Err(protocol_err("Not an initiator handshake")),
        };
        let secret = shared_secret(&initiator_ell64, &responder_ell64, &private_key, true)?;
        Ok(transport_from_secret(&secret, true))
    }
}

fn fresh_ellswift() -> ([u8; 32], [u8; 64]) {
    let mut key_bytes = [0u8; 32];
    getrandom(&mut key_bytes).expect("Failed to generate random bytes");
    let mut aux_rand = [0u8; 32];
    getrandom(&mut aux_rand).expect("Failed to generate aux_rand");
    let ellswift = ellswift_create(&key_bytes, Some(&aux_rand))
        .expect("Failed to create ElligatorSwift encoding");
    (key_bytes, ellswift)
}

fn garbage_ok(garbage: &[u8]) -> Result<()> {
    if garbage.len() > GARBAGE_MAX {
        return Err(protocol_err("garbage longer than 4095"));
    }
    Ok(())
}

impl InitiatorPending {
    /// Garbage this side already sent after its ellswift public key.
    pub fn garbage(&self) -> &[u8] {
        &self.garbage
    }
}

/// Opening bytes are ellswift || garbage. Garbage may be empty.
pub fn begin_initiator(garbage: &[u8]) -> Result<(Vec<u8>, InitiatorPending)> {
    garbage_ok(garbage)?;
    let (private_key, ellswift) = fresh_ellswift();
    let mut opening = ellswift.to_vec();
    opening.extend_from_slice(garbage);
    Ok((
        opening,
        InitiatorPending {
            private_key,
            ellswift,
            garbage: garbage.to_vec(),
        },
    ))
}

/// Responder keys from the initiator's 64-byte ellswift. `magic` is the network salt.
pub fn responder_accept(
    initiator_ellswift: &[u8],
    garbage: &[u8],
    magic: [u8; 4],
) -> Result<ResponderPending> {
    garbage_ok(garbage)?;
    if initiator_ellswift.len() != 64 {
        return Err(protocol_err("ellswift is 64 bytes"));
    }
    let mut initiator_ell64 = [0u8; 64];
    initiator_ell64.copy_from_slice(initiator_ellswift);
    let (private_key, ellswift) = fresh_ellswift();
    let secret = shared_secret(&ellswift, &initiator_ell64, &private_key, false)?;
    Ok(ResponderPending {
        ellswift,
        session: session_keys(&secret, false, magic).into_session(false),
        garbage: garbage.to_vec(),
    })
}

impl ResponderPending {
    /// ellswift || garbage || terminator || version packet. The packet authenticates `garbage`.
    pub fn send_version(self, version: &[u8]) -> Result<(Vec<u8>, V2Session)> {
        self.send_with_decoys(&[], version)
    }

    /// Same as [`Self::send_version`], with ignore-bit decoys before the version packet.
    /// The first packet authenticates `garbage`. Later packets use empty associated data.
    pub fn send_with_decoys(
        mut self,
        decoys: &[&[u8]],
        version: &[u8],
    ) -> Result<(Vec<u8>, V2Session)> {
        let garbage = std::mem::take(&mut self.garbage);
        let mut wire = self.ellswift.to_vec();
        wire.extend_from_slice(&garbage);
        wire.extend_from_slice(&self.session.send_garbage_terminator);
        wire.extend_from_slice(&write_handshake_packets(
            &mut self.session,
            &garbage,
            decoys,
            version,
        )?);
        Ok((wire, self.session))
    }
}

/// Initiator keys once the responder ellswift is known. `magic` is the network salt.
pub fn initiator_session(
    pending: &InitiatorPending,
    responder_ellswift: &[u8],
    magic: [u8; 4],
) -> Result<V2Session> {
    if responder_ellswift.len() != 64 {
        return Err(protocol_err("ellswift is 64 bytes"));
    }
    let mut responder_ell64 = [0u8; 64];
    responder_ell64.copy_from_slice(responder_ellswift);
    let secret = shared_secret(
        &pending.ellswift,
        &responder_ell64,
        &pending.private_key,
        true,
    )?;
    Ok(session_keys(&secret, true, magic).into_session(true))
}

/// Terminator || version packet. The packet authenticates the garbage this side already sent.
pub fn append_terminator_and_version(
    session: &mut V2Session,
    garbage: &[u8],
    version: &[u8],
) -> Result<Vec<u8>> {
    append_handshake(session, garbage, &[], version)
}

/// Terminator, then optional decoys, then the version packet.
/// The first packet authenticates `garbage`. Later packets use empty associated data.
pub fn append_handshake(
    session: &mut V2Session,
    garbage: &[u8],
    decoys: &[&[u8]],
    version: &[u8],
) -> Result<Vec<u8>> {
    let mut tail = session.send_garbage_terminator.to_vec();
    tail.extend_from_slice(&write_handshake_packets(session, garbage, decoys, version)?);
    Ok(tail)
}

fn write_handshake_packets(
    session: &mut V2Session,
    garbage: &[u8],
    decoys: &[&[u8]],
    version: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut first = true;
    for decoy in decoys {
        let aad: &[u8] = if first { garbage } else { &[] };
        first = false;
        out.extend_from_slice(&session.encrypt_packet(decoy, aad, true)?);
    }
    let aad: &[u8] = if first { garbage } else { &[] };
    out.extend_from_slice(&session.encrypt_packet(version, aad, false)?);
    Ok(out)
}

/// Packets after the garbage terminator. Decoys are skipped. Only the first packet uses `garbage` as associated data.
pub fn take_version_packet(
    session: &mut V2Session,
    mut bytes: &[u8],
    garbage: &[u8],
) -> Result<Vec<u8>> {
    let mut first = true;
    loop {
        if bytes.len() < 3 + 1 + 16 {
            return Err(protocol_err("handshake ended before the version packet"));
        }
        let contents_len = session.decrypt_length(&bytes[..3])?;
        let total = 3 + 1 + contents_len + 16;
        if bytes.len() < total {
            return Err(protocol_err("truncated handshake packet"));
        }
        let aad: &[u8] = if first { garbage } else { &[] };
        first = false;
        let (contents, ignore) = session.decrypt_body(&bytes[3..total], aad)?;
        if contents.len() != contents_len {
            return Err(protocol_err("decrypted contents length mismatch"));
        }
        bytes = &bytes[total..];
        if !ignore {
            if !bytes.is_empty() {
                return Err(protocol_err("bytes follow the version packet"));
            }
            return Ok(contents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_transport_encrypt_decrypt() {
        let key = [0x42; 32];
        let mut transport = V2Transport::new(key, key);
        let plaintext = b"Hello, Bitcoin!";
        let encrypted = transport.encrypt(plaintext).unwrap();
        let decrypted = transport.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_v2_transport_rekey_round_trip() {
        let key = [0x11; 32];
        let mut enc = V2Transport::new(key, key);
        let mut dec = V2Transport::new(key, key);
        for i in 0..300 {
            let pt = format!("msg{i}").into_bytes();
            let pkt = enc.encrypt(&pt).unwrap();
            let out = dec.decrypt(&pkt).unwrap();
            assert_eq!(pt, out, "round-trip failed at i={i}");
        }
    }

    #[test]
    fn test_elligator_swift_encode_decode() {
        let seckey = [0x01u8; 32];
        let ell = ellswift_create(&seckey, None).expect("valid key");
        assert_eq!(ell.len(), 64);
        let shared = ellswift_xdh(&ell, &ell, &seckey, false);
        assert!(shared.is_some(), "XDH should not fail on valid inputs");
    }

    #[test]
    fn packet_encoding_matches_the_reference_vectors() {
        use blvm_secp256k1::ecdsa::pubkey_from_secret;
        use blvm_secp256k1::ellswift::{ellswift_decode_x, ellswift_ecdh_xonly, ellswift_xdh};
        use blvm_secp256k1::scalar::Scalar;

        let csv = include_str!("../tests/data/bip324/packet_encoding_test_vectors.csv");
        let mut rows = 0;
        for line in csv.lines().skip(1) {
            if line.is_empty() {
                continue;
            }
            let col: Vec<&str> = line.split(',').collect();
            assert_eq!(col.len(), 22, "vector row has {} columns", col.len());
            let initiating = col[4] == "1";
            let priv_ours = hex32(col[1]);
            let ell_ours = hex64(col[2]);
            let ell_theirs = hex64(col[3]);
            let mut scalar = Scalar::zero();
            assert!(!scalar.set_b32(&priv_ours));
            let point = pubkey_from_secret(&scalar);
            let mut x = point.x;
            x.normalize();
            let mut x_ours = [0u8; 32];
            x.get_b32(&mut x_ours);
            assert_eq!(hex::encode(x_ours), col[9]);
            assert_eq!(hex::encode(ellswift_decode_x(&ell_ours)), col[9]);
            assert_eq!(hex::encode(ellswift_decode_x(&ell_theirs)), col[10]);
            let x_shared = ellswift_ecdh_xonly(&ell_theirs, &priv_ours).unwrap();
            assert_eq!(hex::encode(x_shared), col[11]);
            let secret = if initiating {
                ellswift_xdh(&ell_ours, &ell_theirs, &priv_ours, false).unwrap()
            } else {
                ellswift_xdh(&ell_theirs, &ell_ours, &priv_ours, true).unwrap()
            };
            assert_eq!(hex::encode(secret), col[12]);
            let keys = session_keys(&secret, initiating, MAINNET_MAGIC);
            assert_eq!(hex::encode(keys.initiator_l), col[13]);
            assert_eq!(hex::encode(keys.initiator_p), col[14]);
            assert_eq!(hex::encode(keys.responder_l), col[15]);
            assert_eq!(hex::encode(keys.responder_p), col[16]);
            assert_eq!(hex::encode(keys.send_garbage_terminator), col[17]);
            assert_eq!(hex::encode(keys.recv_garbage_terminator), col[18]);
            assert_eq!(hex::encode(keys.session_id), col[19]);
            let mut transport = keys.transport(initiating);
            let mut peer = session_keys(&secret, !initiating, MAINNET_MAGIC).transport(!initiating);
            let idx: usize = col[0].parse().unwrap();
            for _ in 0..idx {
                let empty = transport.encrypt_packet(&[], &[], false).unwrap();
                let (body, empty_ignore) = peer.decrypt_packet(&empty, &[]).unwrap();
                assert!(body.is_empty() && !empty_ignore);
            }
            let multiply: usize = col[6].parse().unwrap();
            let mut contents = hex::decode(col[5]).unwrap();
            if multiply != 1 {
                contents = contents.repeat(multiply);
            }
            let aad = hex::decode(col[7]).unwrap();
            let ignore = col[8] == "1";
            let ciphertext = transport.encrypt_packet(&contents, &aad, ignore).unwrap();
            let got = hex::encode(&ciphertext);
            if !col[20].is_empty() {
                assert_eq!(got, col[20]);
            }
            if !col[21].is_empty() {
                assert!(
                    got.ends_with(col[21]),
                    "ciphertext suffix mismatch at idx {idx}"
                );
            }
            let (opened, opened_ignore) = peer.decrypt_packet(&ciphertext, &aad).unwrap();
            assert_eq!(opened, contents);
            assert_eq!(opened_ignore, ignore);
            rows += 1;
        }
        assert_eq!(rows, 7);
    }

    #[test]
    fn garbage_terminator_and_version_complete_the_handshake() {
        let regtest = [0xfa, 0xbf, 0xb5, 0xda];
        for (ours, theirs) in [(b"" as &[u8], b"" as &[u8]), (b"ig", b"rg-garbage")] {
            let (opening, pending) = begin_initiator(ours).unwrap();
            assert_eq!(&opening[64..], ours);
            let responder = responder_accept(&opening[..64], theirs, regtest).unwrap();
            let (wire, mut responder_session) = responder.send_version(b"resp-version").unwrap();
            let mut initiator = initiator_session(&pending, &wire[..64], regtest).unwrap();
            assert_eq!(initiator.session_id, responder_session.session_id);
            assert_ne!(initiator.session_id, [0u8; 32]);
            assert_eq!(
                initiator.send_garbage_terminator,
                responder_session.recv_garbage_terminator
            );
            let rest = &wire[64..];
            assert!(rest.starts_with(theirs));
            let term = initiator.recv_garbage_terminator;
            assert_eq!(&rest[theirs.len()..theirs.len() + 16], &term);
            let packet = &rest[theirs.len() + 16..];
            assert!(
                initiator
                    .decrypt_packet(packet, b"not-the-garbage")
                    .is_err()
            );
            let mut initiator = initiator_session(&pending, &wire[..64], regtest).unwrap();
            let (version, ignore) = initiator.decrypt_packet(packet, theirs).unwrap();
            assert_eq!(version, b"resp-version");
            assert!(!ignore);
            let tail =
                append_terminator_and_version(&mut initiator, ours, b"init-version").unwrap();
            assert_eq!(&tail[..16], &responder_session.recv_garbage_terminator);
            let (version, ignore) = responder_session.decrypt_packet(&tail[16..], ours).unwrap();
            assert_eq!(version, b"init-version");
            assert!(!ignore);
            let next = initiator.encrypt(b"ping").unwrap();
            assert_eq!(responder_session.decrypt(&next).unwrap(), b"ping");
        }
    }

    #[test]
    fn a_decoy_authenticates_the_garbage_and_the_version_follows() {
        let regtest = [0xfa, 0xbf, 0xb5, 0xda];
        let (opening, pending) = begin_initiator(b"ig").unwrap();
        let responder = responder_accept(&opening[..64], b"rg", regtest).unwrap();
        let (wire, mut responder_session) = responder
            .send_with_decoys(&[b"\x00"], b"resp-version")
            .unwrap();
        let mut initiator = initiator_session(&pending, &wire[..64], regtest).unwrap();
        let packets = &wire[64 + 2 + 16..];
        let version = take_version_packet(&mut initiator, packets, b"rg").unwrap();
        assert_eq!(version, b"resp-version");
        let tail = append_handshake(&mut initiator, b"ig", &[b"\x00"], b"init-version").unwrap();
        let version = take_version_packet(&mut responder_session, &tail[16..], b"ig").unwrap();
        assert_eq!(version, b"init-version");
        let next = initiator.encrypt(b"ping").unwrap();
        assert_eq!(responder_session.decrypt(&next).unwrap(), b"ping");

        let (opening, pending) = begin_initiator(b"ig").unwrap();
        let responder = responder_accept(&opening[..64], b"rg", regtest).unwrap();
        let (wire, _) = responder
            .send_with_decoys(&[b"\x00"], b"resp-version")
            .unwrap();
        let mut wrong = initiator_session(&pending, &wire[..64], regtest).unwrap();
        assert!(take_version_packet(&mut wrong, &wire[64 + 2 + 16..], b"no").is_err());
    }

    #[test]
    fn garbage_longer_than_4095_is_rejected() {
        assert!(begin_initiator(&vec![0u8; GARBAGE_MAX + 1]).is_err());
        assert!(begin_initiator(&vec![0u8; GARBAGE_MAX]).is_ok());
    }

    #[test]
    fn a_different_network_magic_does_not_open_the_packet() {
        let regtest = [0xfa, 0xbf, 0xb5, 0xda];
        let (opening, pending) = begin_initiator(b"ig").unwrap();
        let responder = responder_accept(&opening[..64], b"rg", regtest).unwrap();
        let (wire, _) = responder.send_version(b"resp-version").unwrap();
        let mut wrong = initiator_session(&pending, &wire[..64], MAINNET_MAGIC).unwrap();
        let packet = &wire[64 + 2 + 16..];
        assert!(wrong.decrypt_packet(packet, b"rg").is_err());
    }

    #[test]
    fn the_v1_prefix_is_magic_plus_the_version_command() {
        let prefix = v1_version_prefix(MAINNET_MAGIC);
        assert_eq!(&prefix[..4], &MAINNET_MAGIC);
        assert_eq!(&prefix[4..], b"version\x00\x00\x00\x00\x00");
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
}
