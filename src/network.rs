//! Bitcoin P2P Network Protocol (Orange Paper Section 10)
//!
//! This module provides Bitcoin P2P protocol message types and processing.
//! Protocol-specific limits and validation are handled here, with consensus
//! validation delegated to the consensus layer.

use crate::{BitcoinProtocolEngine, Result};
use crate::validation::ProtocolValidationContext;
use bllvm_consensus::types::{OutPoint, UTXO, UtxoSet};
use bllvm_consensus::{Block, BlockHeader, Hash, Transaction, ValidationResult};

/// NetworkMessage: Bitcoin P2P protocol message types
///
/// Network message types for Bitcoin P2P protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMessage {
    Version(VersionMessage),
    VerAck,
    Addr(AddrMessage),
    Inv(InvMessage),
    GetData(GetDataMessage),
    GetHeaders(GetHeadersMessage),
    Headers(HeadersMessage),
    Block(Block),
    Tx(Transaction),
    Ping(PingMessage),
    Pong(PongMessage),
    MemPool,
    FeeFilter(FeeFilterMessage),
}

/// Version message for initial handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// Address message containing peer addresses
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMessage {
    pub addresses: Vec<NetworkAddress>,
}

/// Inventory message listing available objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}

/// GetData message requesting specific objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDataMessage {
    pub inventory: Vec<InventoryVector>,
}

/// GetHeaders message requesting block headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMessage {
    pub version: u32,
    pub block_locator_hashes: Vec<Hash>,
    pub hash_stop: Hash,
}

/// Headers message containing block headers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

/// Ping message for connection keepalive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingMessage {
    pub nonce: u64,
}

/// Pong message responding to ping
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongMessage {
    pub nonce: u64,
}

/// FeeFilter message setting minimum fee rate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeFilterMessage {
    pub feerate: u64,
}

/// Network address structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAddress {
    pub services: u64,
    pub ip: [u8; 16], // IPv6 address
    pub port: u16,
}

/// Inventory vector identifying objects
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryVector {
    pub inv_type: u32,
    pub hash: Hash,
}

/// Network response to a message
#[derive(Debug, Clone)]
pub enum NetworkResponse {
    Ok,
    SendMessage(NetworkMessage),
    SendMessages(Vec<NetworkMessage>),
    Reject(String),
}

/// Peer connection state
#[derive(Debug, Clone)]
pub struct PeerState {
    pub version: u32,
    pub services: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub handshake_complete: bool,
    pub known_addresses: Vec<NetworkAddress>,
    pub ping_nonce: Option<u64>,
    pub last_pong: Option<std::time::SystemTime>,
    pub min_fee_rate: Option<u64>,
}

impl PeerState {
    pub fn new() -> Self {
        Self {
            version: 0,
            services: 0,
            user_agent: String::new(),
            start_height: 0,
            handshake_complete: false,
            known_addresses: Vec::new(),
            ping_nonce: None,
            last_pong: None,
            min_fee_rate: None,
        }
    }
}

impl Default for PeerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain object (block or transaction)
#[derive(Debug, Clone)]
pub enum ChainObject {
    Block(Block),
    Transaction(Transaction),
}

impl ChainObject {
    pub fn as_block(&self) -> Option<&Block> {
        match self {
            ChainObject::Block(block) => Some(block),
            _ => None,
        }
    }

    pub fn as_transaction(&self) -> Option<&Transaction> {
        match self {
            ChainObject::Transaction(tx) => Some(tx),
            _ => None,
        }
    }
}

/// Trait for chain state access (node layer implements this)
///
/// This trait allows the protocol layer to query chain state without
/// owning it. The node layer provides real implementations using its
/// storage modules (BlockStore, TxIndex, MempoolManager).
pub trait ChainStateAccess {
    /// Check if we have an object (block or transaction) by hash
    fn has_object(&self, hash: &Hash) -> bool;

    /// Get an object (block or transaction) by hash
    fn get_object(&self, hash: &Hash) -> Option<ChainObject>;

    /// Get headers for a block locator (for GetHeaders requests)
    /// This implements the Bitcoin block locator algorithm
    fn get_headers_for_locator(&self, locator: &[Hash], stop: &Hash) -> Vec<BlockHeader>;

    /// Get all mempool transactions
    fn get_mempool_transactions(&self) -> Vec<Transaction>;
}

/// Process incoming network message
///
/// This function handles Bitcoin P2P protocol messages, applying protocol-specific
/// limits and delegating consensus validation to the protocol engine.
///
/// # Arguments
///
/// * `engine` - The protocol engine (contains consensus layer)
/// * `message` - The network message to process
/// * `peer_state` - Current peer connection state
/// * `chain_access` - Optional chain state access (node layer provides this)
/// * `utxo_set` - Optional UTXO set for block validation
/// * `height` - Optional block height for validation context
///
/// # Returns
///
/// A `NetworkResponse` indicating the result of processing
pub fn process_network_message(
    engine: &BitcoinProtocolEngine,
    message: &NetworkMessage,
    peer_state: &mut PeerState,
    chain_access: Option<&dyn ChainStateAccess>,
    utxo_set: Option<&UtxoSet>,
    height: Option<u64>,
) -> Result<NetworkResponse> {
    match message {
        NetworkMessage::Version(version) => process_version_message(version, peer_state),
        NetworkMessage::VerAck => process_verack_message(peer_state),
        NetworkMessage::Addr(addr) => process_addr_message(addr, peer_state),
        NetworkMessage::Inv(inv) => process_inv_message(inv, chain_access),
        NetworkMessage::GetData(getdata) => {
            process_getdata_message(getdata, chain_access)
        }
        NetworkMessage::GetHeaders(getheaders) => {
            process_getheaders_message(getheaders, chain_access)
        }
        NetworkMessage::Headers(headers) => process_headers_message(headers),
        NetworkMessage::Block(block) => {
            process_block_message(engine, block, utxo_set, height)
        }
        NetworkMessage::Tx(tx) => process_tx_message(engine, tx, height),
        NetworkMessage::Ping(ping) => process_ping_message(ping, peer_state),
        NetworkMessage::Pong(pong) => process_pong_message(pong, peer_state),
        NetworkMessage::MemPool => process_mempool_message(chain_access),
        NetworkMessage::FeeFilter(feefilter) => process_feefilter_message(feefilter, peer_state),
    }
}

/// Process version message
fn process_version_message(
    version: &VersionMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    // Validate version message
    if version.version < 70001 {
        return Ok(NetworkResponse::Reject("Version too old".to_string()));
    }

    // Update peer state
    peer_state.version = version.version;
    peer_state.services = version.services;
    peer_state.user_agent = version.user_agent.clone();
    peer_state.start_height = version.start_height;

    // Send verack response
    Ok(NetworkResponse::SendMessage(NetworkMessage::VerAck))
}

/// Process verack message
fn process_verack_message(peer_state: &mut PeerState) -> Result<NetworkResponse> {
    peer_state.handshake_complete = true;
    Ok(NetworkResponse::Ok)
}

/// Process addr message
fn process_addr_message(addr: &AddrMessage, peer_state: &mut PeerState) -> Result<NetworkResponse> {
    // Validate address count (protocol limit)
    if addr.addresses.len() > 1000 {
        return Ok(NetworkResponse::Reject("Too many addresses".to_string()));
    }

    // Store addresses for future use
    peer_state.known_addresses.extend(addr.addresses.clone());

    Ok(NetworkResponse::Ok)
}

/// Process inv message
fn process_inv_message(
    inv: &InvMessage,
    chain_access: Option<&dyn ChainStateAccess>,
) -> Result<NetworkResponse> {
    // Validate inventory count (protocol limit)
    if inv.inventory.len() > 50000 {
        return Ok(NetworkResponse::Reject(
            "Too many inventory items".to_string(),
        ));
    }

    // Check which items we need (if chain access provided)
    if let Some(chain) = chain_access {
        let mut needed_items = Vec::new();
        for item in &inv.inventory {
            if !chain.has_object(&item.hash) {
                needed_items.push(item.clone());
            }
        }

        if !needed_items.is_empty() {
            return Ok(NetworkResponse::SendMessage(NetworkMessage::GetData(
                GetDataMessage {
                    inventory: needed_items,
                },
            )));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process getdata message
fn process_getdata_message(
    getdata: &GetDataMessage,
    chain_access: Option<&dyn ChainStateAccess>,
) -> Result<NetworkResponse> {
    // Validate request count (protocol limit)
    if getdata.inventory.len() > 50000 {
        return Ok(NetworkResponse::Reject(
            "Too many getdata items".to_string(),
        ));
    }

    // Send requested objects (if chain access provided)
    if let Some(chain) = chain_access {
        let mut responses = Vec::new();
        for item in &getdata.inventory {
            if let Some(obj) = chain.get_object(&item.hash) {
                match item.inv_type {
                    1 => {
                        // MSG_TX
                        if let Some(tx) = obj.as_transaction() {
                            responses.push(NetworkMessage::Tx(tx.clone()));
                        }
                    }
                    2 => {
                        // MSG_BLOCK
                        if let Some(block) = obj.as_block() {
                            responses.push(NetworkMessage::Block(block.clone()));
                        }
                    }
                    _ => {
                        // Unknown inventory type - skip
                    }
                }
            }
        }

        if !responses.is_empty() {
            return Ok(NetworkResponse::SendMessages(responses));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process getheaders message
fn process_getheaders_message(
    getheaders: &GetHeadersMessage,
    chain_access: Option<&dyn ChainStateAccess>,
) -> Result<NetworkResponse> {
    // Use chain access to find headers (if provided)
    if let Some(chain) = chain_access {
        let headers = chain.get_headers_for_locator(
            &getheaders.block_locator_hashes,
            &getheaders.hash_stop,
        );
        return Ok(NetworkResponse::SendMessage(NetworkMessage::Headers(
            HeadersMessage { headers },
        )));
    }

    Ok(NetworkResponse::Reject("Chain access not available".to_string()))
}

/// Process headers message
fn process_headers_message(headers: &HeadersMessage) -> Result<NetworkResponse> {
    // Validate header count (protocol limit)
    if headers.headers.len() > 2000 {
        return Ok(NetworkResponse::Reject("Too many headers".to_string()));
    }

    // Header validation is consensus logic, not protocol
    // Node layer will validate headers using consensus layer
    Ok(NetworkResponse::Ok)
}

/// Process block message
fn process_block_message(
    engine: &BitcoinProtocolEngine,
    block: &Block,
    utxo_set: Option<&UtxoSet>,
    height: Option<u64>,
) -> Result<NetworkResponse> {
    // Check protocol limits first
    if block.transactions.len() > 10000 {
        return Ok(NetworkResponse::Reject("Too many transactions".to_string()));
    }

    // Delegate to consensus via protocol engine (requires utxo_set and height)
    if let (Some(utxos), Some(h)) = (utxo_set, height) {
        let context = ProtocolValidationContext::new(
            engine.get_protocol_version(),
            h,
        )?;
        let result = engine.validate_block_with_protocol(block, utxos, h, &context)?;

        match result {
            ValidationResult::Valid => Ok(NetworkResponse::Ok),
            ValidationResult::Invalid(reason) => {
                Ok(NetworkResponse::Reject(format!("Invalid block: {}", reason)))
            }
        }
    } else {
        Ok(NetworkResponse::Reject("Missing validation context".to_string()))
    }
}

/// Process transaction message
fn process_tx_message(
    engine: &BitcoinProtocolEngine,
    tx: &Transaction,
    height: Option<u64>,
) -> Result<NetworkResponse> {
    // Check protocol limits and validate
    let context = ProtocolValidationContext::new(
        engine.get_protocol_version(),
        height.unwrap_or(0),
    )?;
    let result = engine.validate_transaction_with_protocol(tx, &context)?;

    match result {
        ValidationResult::Valid => Ok(NetworkResponse::Ok),
        ValidationResult::Invalid(reason) => {
            Ok(NetworkResponse::Reject(format!("Invalid transaction: {}", reason)))
        }
    }
}

/// Process ping message
fn process_ping_message(
    ping: &PingMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    let pong = NetworkMessage::Pong(PongMessage { nonce: ping.nonce });
    Ok(NetworkResponse::SendMessage(pong))
}

/// Process pong message
fn process_pong_message(pong: &PongMessage, peer_state: &mut PeerState) -> Result<NetworkResponse> {
    // Validate pong nonce matches our ping
    if peer_state.ping_nonce == Some(pong.nonce) {
        peer_state.ping_nonce = None;
        peer_state.last_pong = Some(std::time::SystemTime::now());
    }

    Ok(NetworkResponse::Ok)
}

/// Process mempool message
fn process_mempool_message(
    chain_access: Option<&dyn ChainStateAccess>,
) -> Result<NetworkResponse> {
    // Send all mempool transactions (if chain access provided)
    if let Some(chain) = chain_access {
        let mempool_txs = chain.get_mempool_transactions();
        let mut responses = Vec::new();

        for tx in mempool_txs {
            responses.push(NetworkMessage::Tx(tx));
        }

        if !responses.is_empty() {
            return Ok(NetworkResponse::SendMessages(responses));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process feefilter message
fn process_feefilter_message(
    feefilter: &FeeFilterMessage,
    peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    peer_state.min_fee_rate = Some(feefilter.feerate);
    Ok(NetworkResponse::Ok)
}

