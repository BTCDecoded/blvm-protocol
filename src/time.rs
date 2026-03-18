//! Safe time utilities for fault tolerance
//!
//! Provides time operations that handle system clock errors gracefully,
//! avoiding panics from misconfigured clocks (e.g. before UNIX epoch).

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp (seconds since epoch)
///
/// Returns 0 if system time is before epoch (misconfigured VMs, containers).
/// Prevents panics from `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()`.
#[inline]
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
