//! Genesis blocks.
//!
//! The header and coinbase are built by [`blvm_consensus::block::genesis_block`].

use blvm_consensus::block::genesis_block;
use blvm_consensus::types::{Block, Network};

/// Mainnet genesis. Hash `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.
pub fn mainnet_genesis() -> Block {
    genesis_block(Network::Mainnet)
}

/// Testnet genesis. Hash `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943`.
pub fn testnet_genesis() -> Block {
    genesis_block(Network::Testnet)
}

/// Regtest genesis. Hash `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`.
pub fn regtest_genesis() -> Block {
    genesis_block(Network::Regtest)
}

/// Testnet4 genesis. Hash `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`.
pub fn testnet4_genesis() -> Block {
    genesis_block(Network::Testnet4)
}

/// Signet genesis. Hash `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`.
pub fn signet_genesis() -> Block {
    genesis_block(Network::Signet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet4_genesis_matches_core() {
        let block = testnet4_genesis();
        let hash = blvm_consensus::block::block_header_hash(&block.header);
        let mut display = hash;
        display.reverse();
        assert_eq!(
            hex_encode(&display),
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
        );
        let mut merkle = block.header.merkle_root;
        merkle.reverse();
        assert_eq!(
            hex_encode(&merkle),
            "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
        );
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }
}
