//! Bitcoin P2P Network Protocol (Orange Paper Section 10)
//!
//! This module provides Bitcoin P2P protocol message types and processing.
//! Protocol-specific limits and validation are handled here, with consensus
//! validation delegated to the consensus layer.

use crate::validation::ProtocolValidationContext;
use crate::{BitcoinProtocolEngine, ProtocolConfig, Result};
use bllvm_consensus::types::UtxoSet;
use bllvm_consensus::{Block, BlockHeader, Hash, Transaction, ValidationResult};
use std::sync::Arc;

// Commons module is always available (ban list sharing doesn't require utxo-commitments)
pub mod commons {
    pub use crate::commons::*;
}

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
    Block(Arc<Block>),
    Tx(Arc<Transaction>),
    Ping(PingMessage),
    Pong(PongMessage),
    MemPool,
    FeeFilter(FeeFilterMessage),
    // Additional core P2P messages
    GetBlocks(GetBlocksMessage),
    GetAddr,
    NotFound(NotFoundMessage),
    Reject(RejectMessage),
    SendHeaders,
    // BIP152 Compact Block Relay
    SendCmpct(SendCmpctMessage),
    CmpctBlock(CmpctBlockMessage),
    GetBlockTxn(GetBlockTxnMessage),
    BlockTxn(BlockTxnMessage),
    // Commons-specific protocol extensions
    #[cfg(feature = "utxo-commitments")]
    GetUTXOSet(commons::GetUTXOSetMessage),
    #[cfg(feature = "utxo-commitments")]
    UTXOSet(commons::UTXOSetMessage),
    #[cfg(feature = "utxo-commitments")]
    GetFilteredBlock(commons::GetFilteredBlockMessage),
    #[cfg(feature = "utxo-commitments")]
    FilteredBlock(commons::FilteredBlockMessage),
    GetBanList(commons::GetBanListMessage),
    BanList(commons::BanListMessage),
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

/// GetBlocks message requesting blocks by locator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocksMessage {
    pub version: u32,
    pub block_locator_hashes: Vec<Hash>,
    pub hash_stop: Hash,
}

/// NotFound message indicating requested object not found
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotFoundMessage {
    pub inventory: Vec<InventoryVector>,
}

/// Reject message rejecting a message with reason
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectMessage {
    pub message: String,          // Command name of rejected message
    pub code: u8, // Rejection code (0x01=malformed, 0x10=invalid, 0x11=obsolete, 0x12=duplicate, 0x40=nonstandard, 0x41=dust, 0x42=insufficientfee, 0x43=checkpoint)
    pub reason: String, // Human-readable reason
    pub extra_data: Option<Hash>, // Optional hash for rejected object
}

/// SendCmpct message - Negotiate compact block relay support (BIP152)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendCmpctMessage {
    /// Compact block version (1 or 2)
    pub version: u64,
    /// Whether to prefer compact blocks (1) or regular blocks (0)
    pub prefer_cmpct: u8,
}

/// CmpctBlock message - Compact block data (BIP152)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmpctBlockMessage {
    /// Block header
    pub header: BlockHeader,
    /// Short transaction IDs (6 bytes each)
    pub short_ids: Vec<[u8; 6]>,
    /// Prefilled transactions (transactions that are likely missing)
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

/// PrefilledTransaction - Transaction included in compact block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefilledTransaction {
    /// Index in block (0 = coinbase)
    pub index: u16,
    /// Transaction data
    pub tx: Transaction,
}

/// GetBlockTxn message - Request missing transactions from compact block (BIP152)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlockTxnMessage {
    /// Block hash for the compact block
    pub block_hash: Hash,
    /// Indices of transactions to request (0-indexed)
    pub indices: Vec<u16>,
}

/// BlockTxn message - Response with requested transactions (BIP152)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTxnMessage {
    /// Block hash for the compact block
    pub block_hash: Hash,
    /// Requested transactions in order
    pub transactions: Vec<Transaction>,
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
    SendMessage(Box<NetworkMessage>),
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
    Block(Arc<Block>),
    Transaction(Arc<Transaction>),
}

impl ChainObject {
    pub fn as_block(&self) -> Option<&Arc<Block>> {
        match self {
            ChainObject::Block(block) => Some(block),
            _ => None,
        }
    }

    pub fn as_transaction(&self) -> Option<&Arc<Transaction>> {
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
    let config = engine.get_config();
    match message {
        NetworkMessage::Version(version) => process_version_message(version, peer_state, config),
        NetworkMessage::VerAck => process_verack_message(peer_state),
        NetworkMessage::Addr(addr) => process_addr_message(addr, peer_state, config),
        NetworkMessage::Inv(inv) => process_inv_message(inv, chain_access, config),
        NetworkMessage::GetData(getdata) => process_getdata_message(getdata, chain_access, config),
        NetworkMessage::GetHeaders(getheaders) => {
            process_getheaders_message(getheaders, chain_access, config)
        }
        NetworkMessage::Headers(headers) => process_headers_message(headers, config),
        NetworkMessage::Block(block) => {
            process_block_message(engine, block, utxo_set, height, config)
        }
        NetworkMessage::Tx(tx) => process_tx_message(engine, tx, height),
        NetworkMessage::Ping(ping) => process_ping_message(ping, peer_state),
        NetworkMessage::Pong(pong) => process_pong_message(pong, peer_state),
        NetworkMessage::MemPool => process_mempool_message(chain_access),
        NetworkMessage::FeeFilter(feefilter) => process_feefilter_message(feefilter, peer_state),
        NetworkMessage::GetBlocks(getblocks) => {
            process_getblocks_message(getblocks, chain_access, config)
        }
        NetworkMessage::GetAddr => process_getaddr_message(peer_state, config),
        NetworkMessage::NotFound(notfound) => process_notfound_message(notfound, config),
        NetworkMessage::Reject(reject) => process_reject_message(reject, config),
        NetworkMessage::SendHeaders => process_sendheaders_message(peer_state),
        NetworkMessage::SendCmpct(sendcmpct) => {
            process_sendcmpct_message(sendcmpct, peer_state, config)
        }
        NetworkMessage::CmpctBlock(cmpctblock) => process_cmpctblock_message(cmpctblock),
        NetworkMessage::GetBlockTxn(getblocktxn) => {
            process_getblocktxn_message(getblocktxn, chain_access, config)
        }
        NetworkMessage::BlockTxn(blocktxn) => process_blocktxn_message(blocktxn),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetUTXOSet(getutxoset) => process_getutxoset_message(getutxoset),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::UTXOSet(utxoset) => process_utxoset_message(utxoset),
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::GetFilteredBlock(getfiltered) => {
            process_getfilteredblock_message(getfiltered)
        }
        #[cfg(feature = "utxo-commitments")]
        NetworkMessage::FilteredBlock(filtered) => process_filteredblock_message(filtered),
        NetworkMessage::GetBanList(getbanlist) => process_getbanlist_message(getbanlist),
        NetworkMessage::BanList(banlist) => process_banlist_message(banlist),
    }
}

/// Process version message
fn process_version_message(
    version: &VersionMessage,
    peer_state: &mut PeerState,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate version message
    if version.version < 70001 {
        return Ok(NetworkResponse::Reject("Version too old".into()));
    }

    // Validate user agent length (from config)
    if version.user_agent.len() > config.network_limits.max_user_agent_length {
        return Ok(NetworkResponse::Reject(format!(
            "User agent too long (max {} bytes)",
            config.network_limits.max_user_agent_length
        )));
    }

    // Update peer state
    peer_state.version = version.version;
    peer_state.services = version.services;
    peer_state.user_agent = version.user_agent.clone();
    peer_state.start_height = version.start_height;

    // Send verack response
    Ok(NetworkResponse::SendMessage(Box::new(
        NetworkMessage::VerAck,
    )))
}

/// Process verack message
fn process_verack_message(peer_state: &mut PeerState) -> Result<NetworkResponse> {
    peer_state.handshake_complete = true;
    Ok(NetworkResponse::Ok)
}

/// Process addr message
fn process_addr_message(
    addr: &AddrMessage,
    peer_state: &mut PeerState,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate address count (from config)
    if addr.addresses.len() > config.network_limits.max_addr_addresses {
        return Ok(NetworkResponse::Reject(format!(
            "Too many addresses (max {})",
            config.network_limits.max_addr_addresses
        )));
    }

    // Store addresses for future use
    peer_state.known_addresses.extend(addr.addresses.clone());

    Ok(NetworkResponse::Ok)
}

/// Process inv message
fn process_inv_message(
    inv: &InvMessage,
    chain_access: Option<&dyn ChainStateAccess>,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate inventory count (from config)
    if inv.inventory.len() > config.network_limits.max_inv_items {
        return Ok(NetworkResponse::Reject(format!(
            "Too many inventory items (max {})",
            config.network_limits.max_inv_items
        )));
    }

    // Check which items we need (if chain access provided)
    if let Some(chain) = chain_access {
        let mut needed_items = Vec::with_capacity(inv.inventory.len());
        for item in &inv.inventory {
            if !chain.has_object(&item.hash) {
                needed_items.push(item.clone());
            }
        }

        if !needed_items.is_empty() {
            return Ok(NetworkResponse::SendMessage(Box::new(
                NetworkMessage::GetData(GetDataMessage {
                    inventory: needed_items,
                }),
            )));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process getdata message
fn process_getdata_message(
    getdata: &GetDataMessage,
    chain_access: Option<&dyn ChainStateAccess>,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate request count (from config)
    if getdata.inventory.len() > config.network_limits.max_inv_items {
        return Ok(NetworkResponse::Reject(format!(
            "Too many getdata items (max {})",
            config.network_limits.max_inv_items
        )));
    }

    // Send requested objects (if chain access provided)
    if let Some(chain) = chain_access {
        let mut responses = Vec::with_capacity(getdata.inventory.len());
        for item in &getdata.inventory {
            if let Some(obj) = chain.get_object(&item.hash) {
                match item.inv_type {
                    1 => {
                        // MSG_TX
                        if let Some(tx) = obj.as_transaction() {
                            responses.push(NetworkMessage::Tx(Arc::clone(tx)));
                        }
                    }
                    2 => {
                        // MSG_BLOCK
                        if let Some(block) = obj.as_block() {
                            responses.push(NetworkMessage::Block(Arc::clone(block)));
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
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate block locator size (from config)
    if getheaders.block_locator_hashes.len() > config.validation.max_locator_hashes {
        return Ok(NetworkResponse::Reject(format!(
            "Too many locator hashes (max {})",
            config.validation.max_locator_hashes
        )));
    }

    // Use chain access to find headers (if provided)
    if let Some(chain) = chain_access {
        let headers =
            chain.get_headers_for_locator(&getheaders.block_locator_hashes, &getheaders.hash_stop);
        return Ok(NetworkResponse::SendMessage(Box::new(
            NetworkMessage::Headers(HeadersMessage { headers }),
        )));
    }

    Ok(NetworkResponse::Reject("Chain access not available".into()))
}

/// Process headers message
fn process_headers_message(
    headers: &HeadersMessage,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate header count (from config)
    if headers.headers.len() > config.network_limits.max_headers {
        return Ok(NetworkResponse::Reject(format!(
            "Too many headers (max {})",
            config.network_limits.max_headers
        )));
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
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Check protocol limits first (from config)
    if block.transactions.len() > config.validation.max_txs_per_block {
        return Err(crate::error::ProtocolError::MessageTooLarge {
            size: block.transactions.len(),
            max: config.validation.max_txs_per_block,
        });
    }

    // Delegate to consensus via protocol engine (requires utxo_set and height)
    if let (Some(utxos), Some(h)) = (utxo_set, height) {
        let context = ProtocolValidationContext::new(engine.get_protocol_version(), h)?;
        let result = engine.validate_block_with_protocol(block, utxos, h, &context)?;

        match result {
            ValidationResult::Valid => Ok(NetworkResponse::Ok),
            ValidationResult::Invalid(reason) => {
                Ok(NetworkResponse::Reject(format!("Invalid block: {reason}")))
            }
        }
    } else {
        Err(crate::error::ProtocolError::Configuration(
            "Missing validation context (utxo_set and height required)".into(),
        ))
    }
}

/// Process transaction message
fn process_tx_message(
    engine: &BitcoinProtocolEngine,
    tx: &Transaction,
    height: Option<u64>,
) -> Result<NetworkResponse> {
    // Check protocol limits and validate
    let context =
        ProtocolValidationContext::new(engine.get_protocol_version(), height.unwrap_or(0))?;
    let result = engine.validate_transaction_with_protocol(tx, &context)?;

    match result {
        ValidationResult::Valid => Ok(NetworkResponse::Ok),
        ValidationResult::Invalid(reason) => Ok(NetworkResponse::Reject(format!(
            "Invalid transaction: {reason}"
        ))),
    }
}

/// Process ping message
fn process_ping_message(
    ping: &PingMessage,
    _peer_state: &mut PeerState,
) -> Result<NetworkResponse> {
    let pong = NetworkMessage::Pong(PongMessage { nonce: ping.nonce });
    Ok(NetworkResponse::SendMessage(Box::new(pong)))
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
fn process_mempool_message(chain_access: Option<&dyn ChainStateAccess>) -> Result<NetworkResponse> {
    // Send all mempool transactions (if chain access provided)
    if let Some(chain) = chain_access {
        let mempool_txs = chain.get_mempool_transactions();
        let mut responses = Vec::with_capacity(mempool_txs.len());

        for tx in mempool_txs {
            responses.push(NetworkMessage::Tx(Arc::new(tx)));
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

/// Process getblocks message
fn process_getblocks_message(
    getblocks: &GetBlocksMessage,
    chain_access: Option<&dyn ChainStateAccess>,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate block locator size (from config)
    if getblocks.block_locator_hashes.len() > config.validation.max_locator_hashes {
        return Ok(NetworkResponse::Reject(format!(
            "Too many locator hashes (max {})",
            config.validation.max_locator_hashes
        )));
    }

    // Use chain access to find blocks (if provided)
    // Note: GetBlocks is similar to GetHeaders but returns full blocks
    // For now, we'll delegate to GetHeaders logic or return inv message
    if let Some(chain) = chain_access {
        // Find blocks using locator and return inv message
        let mut inventory = Vec::with_capacity(getblocks.block_locator_hashes.len());
        for hash in &getblocks.block_locator_hashes {
            if chain.has_object(hash) {
                inventory.push(InventoryVector {
                    inv_type: 2, // MSG_BLOCK
                    hash: *hash,
                });
            }
        }

        if !inventory.is_empty() {
            return Ok(NetworkResponse::SendMessage(Box::new(NetworkMessage::Inv(
                InvMessage { inventory },
            ))));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process getaddr message
fn process_getaddr_message(
    peer_state: &mut PeerState,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Return known addresses (if any)
    if !peer_state.known_addresses.is_empty() {
        // Limit to configured max addresses
        let max_addrs = config
            .network_limits
            .max_addr_addresses
            .min(peer_state.known_addresses.len());
        let mut addresses = Vec::with_capacity(max_addrs);
        addresses.extend(peer_state.known_addresses.iter().take(max_addrs).cloned());

        return Ok(NetworkResponse::SendMessage(Box::new(
            NetworkMessage::Addr(AddrMessage { addresses }),
        )));
    }

    Ok(NetworkResponse::Ok)
}

/// Process notfound message
fn process_notfound_message(
    notfound: &NotFoundMessage,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate inventory count (from config)
    if notfound.inventory.len() > config.network_limits.max_inv_items {
        return Ok(NetworkResponse::Reject(format!(
            "Too many notfound items (max {})",
            config.network_limits.max_inv_items
        )));
    }

    // NotFound is informational - just acknowledge
    Ok(NetworkResponse::Ok)
}

/// Process reject message
fn process_reject_message(
    reject: &RejectMessage,
    _config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate message name length (Bitcoin protocol limit: 12 bytes)
    // This is a fixed protocol limit, not configurable
    if reject.message.len() > 12 {
        return Ok(NetworkResponse::Reject(
            "Invalid reject message name".into(),
        ));
    }

    // Validate reason length (Bitcoin protocol limit: 111 bytes)
    // This is a fixed protocol limit, not configurable
    if reject.reason.len() > 111 {
        return Ok(NetworkResponse::Reject("Reject reason too long".into()));
    }

    // Reject is informational - log and acknowledge
    // In production, this would trigger appropriate handling (ban peer, etc.)
    Ok(NetworkResponse::Ok)
}

/// Process sendheaders message
fn process_sendheaders_message(_peer_state: &mut PeerState) -> Result<NetworkResponse> {
    // Enable headers-only mode for this peer
    // This is a flag that affects future GetHeaders responses
    // For now, we just acknowledge (actual implementation would set a flag)
    Ok(NetworkResponse::Ok)
}

/// Process sendcmpct message (BIP152)
fn process_sendcmpct_message(
    sendcmpct: &SendCmpctMessage,
    _peer_state: &mut PeerState,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate version (must be 1 or 2, or match configured preferred version)
    let valid_versions = [1, 2];
    if !valid_versions.contains(&sendcmpct.version) {
        return Ok(NetworkResponse::Reject(
            "Invalid compact block version".into(),
        ));
    }

    // Check if compact blocks are enabled
    if !config.compact_blocks.enabled {
        return Ok(NetworkResponse::Reject("Compact blocks not enabled".into()));
    }

    // Store compact block preference in peer state
    // (actual implementation would store this)
    let _ = (sendcmpct.version, sendcmpct.prefer_cmpct);
    Ok(NetworkResponse::Ok)
}

/// Process cmpctblock message (BIP152)
fn process_cmpctblock_message(_cmpctblock: &CmpctBlockMessage) -> Result<NetworkResponse> {
    // Validate compact block and reconstruct full block
    // For now, just acknowledge (actual implementation would validate and reconstruct)
    Ok(NetworkResponse::Ok)
}

/// Process getblocktxn message (BIP152)
fn process_getblocktxn_message(
    getblocktxn: &GetBlockTxnMessage,
    chain_access: Option<&dyn ChainStateAccess>,
    config: &ProtocolConfig,
) -> Result<NetworkResponse> {
    // Validate indices count (from config)
    if getblocktxn.indices.len() > config.compact_blocks.max_blocktxn_indices {
        return Ok(NetworkResponse::Reject(format!(
            "Too many transaction indices (max {})",
            config.compact_blocks.max_blocktxn_indices
        )));
    }

    // Use chain access to get requested transactions
    if let Some(chain) = chain_access {
        let mut transactions = Vec::new();
        for &index in &getblocktxn.indices {
            // Get block and extract transaction at index
            // (simplified - actual implementation would get block first)
            if let Some(obj) = chain.get_object(&getblocktxn.block_hash) {
                if let Some(block) = obj.as_block() {
                    if (index as usize) < block.transactions.len() {
                        transactions.push(block.transactions[index as usize].clone());
                    }
                }
            }
        }

        if !transactions.is_empty() {
            return Ok(NetworkResponse::SendMessage(Box::new(
                NetworkMessage::BlockTxn(BlockTxnMessage {
                    block_hash: getblocktxn.block_hash,
                    transactions,
                }),
            )));
        }
    }

    Ok(NetworkResponse::Ok)
}

/// Process blocktxn message (BIP152)
fn process_blocktxn_message(_blocktxn: &BlockTxnMessage) -> Result<NetworkResponse> {
    // Validate transactions and use to reconstruct block
    // For now, just acknowledge (actual implementation would validate and reconstruct)
    Ok(NetworkResponse::Ok)
}

#[cfg(feature = "utxo-commitments")]
/// Process getutxoset message
fn process_getutxoset_message(_getutxoset: &commons::GetUTXOSetMessage) -> Result<NetworkResponse> {
    // Request UTXO set at specific height
    // For now, just acknowledge (actual implementation would fetch and return UTXO set)
    Ok(NetworkResponse::Ok)
}

#[cfg(feature = "utxo-commitments")]
/// Process utxoset message
fn process_utxoset_message(_utxoset: &commons::UTXOSetMessage) -> Result<NetworkResponse> {
    // Receive UTXO set commitment
    // For now, just acknowledge (actual implementation would validate and store)
    Ok(NetworkResponse::Ok)
}

#[cfg(feature = "utxo-commitments")]
/// Process getfilteredblock message
fn process_getfilteredblock_message(
    _getfiltered: &commons::GetFilteredBlockMessage,
) -> Result<NetworkResponse> {
    // Request filtered block (spam-filtered)
    // For now, just acknowledge (actual implementation would filter and return)
    Ok(NetworkResponse::Ok)
}

#[cfg(feature = "utxo-commitments")]
/// Process filteredblock message
fn process_filteredblock_message(
    _filtered: &commons::FilteredBlockMessage,
) -> Result<NetworkResponse> {
    // Receive filtered block
    // For now, just acknowledge (actual implementation would validate and process)
    Ok(NetworkResponse::Ok)
}

/// Process getbanlist message
fn process_getbanlist_message(_getbanlist: &commons::GetBanListMessage) -> Result<NetworkResponse> {
    // Request ban list from peer
    // For now, just acknowledge (actual implementation would return ban list)
    Ok(NetworkResponse::Ok)
}

/// Process banlist message
fn process_banlist_message(_banlist: &commons::BanListMessage) -> Result<NetworkResponse> {
    // Receive ban list from peer
    // For now, just acknowledge (actual implementation would validate and merge)
    Ok(NetworkResponse::Ok)
}
