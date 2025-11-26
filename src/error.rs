//! Protocol-specific error types
//!
//! This module defines error types for the protocol layer that wrap consensus errors
//! and add protocol-specific error context.

use crate::ProtocolVersion;
use std::borrow::Cow;
use thiserror::Error;

/// Protocol-specific error types
///
/// This enum wraps consensus errors and adds protocol-specific error types
/// for better error context through the protocol layer.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ProtocolError {
    /// Consensus validation error (wrapped from consensus layer)
    #[error("Consensus error: {0}")]
    Consensus(#[from] bllvm_consensus::error::ConsensusError),

    /// Protocol validation failed (size limits, feature flags, etc.)
    #[error("Protocol validation failed: {0}")]
    Validation(Cow<'static, str>),

    /// Feature not supported by this protocol version
    #[error("Feature not supported: {0}")]
    UnsupportedFeature(String),

    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {expected:?}, got {actual:?}")]
    VersionMismatch {
        expected: ProtocolVersion,
        actual: ProtocolVersion,
    },

    /// Network parameter error
    #[error("Network parameter error: {0}")]
    NetworkParameter(Cow<'static, str>),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(Cow<'static, str>),

    /// Message size exceeds protocol limits
    #[error("Message size exceeds protocol limit: {size} bytes (max {max} bytes)")]
    MessageTooLarge { size: usize, max: usize },

    /// Invalid protocol message
    #[error("Invalid protocol message: {0}")]
    InvalidMessage(Cow<'static, str>),

    /// Service flag error
    #[error("Service flag error: {0}")]
    ServiceFlag(Cow<'static, str>),
}

/// Protocol-specific Result type
pub type Result<T> = std::result::Result<T, ProtocolError>;

