//! Comprehensive Service Flags Tests
//!
//! Tests for service flag combinations, edge cases, and Commons-specific flags.

use blvm_protocol::service_flags::commons::*;
use blvm_protocol::service_flags::standard::*;
use blvm_protocol::service_flags::{
    clear_flag, get_commons_flags, has_flag, set_flag, supports_commons,
};

#[test]
fn test_all_standard_flags() {
    let mut services = 0u64;

    // Test all standard flags
    set_flag(&mut services, NODE_NETWORK);
    assert!(has_flag(services, NODE_NETWORK));

    set_flag(&mut services, NODE_GETUTXO);
    assert!(has_flag(services, NODE_GETUTXO));

    set_flag(&mut services, NODE_BLOOM);
    assert!(has_flag(services, NODE_BLOOM));

    set_flag(&mut services, NODE_WITNESS);
    assert!(has_flag(services, NODE_WITNESS));

    set_flag(&mut services, NODE_XTHIN);
    assert!(has_flag(services, NODE_XTHIN));

    set_flag(&mut services, NODE_COMPACT_FILTERS);
    assert!(has_flag(services, NODE_COMPACT_FILTERS));

    set_flag(&mut services, NODE_NETWORK_LIMITED);
    assert!(has_flag(services, NODE_NETWORK_LIMITED));
}

#[test]
fn test_all_commons_flags() {
    let mut services = 0u64;

    // Test all Commons flags
    set_flag(&mut services, NODE_DANDELION);
    assert!(has_flag(services, NODE_DANDELION));

    set_flag(&mut services, NODE_PACKAGE_RELAY);
    assert!(has_flag(services, NODE_PACKAGE_RELAY));

    set_flag(&mut services, NODE_FIBRE);
    assert!(has_flag(services, NODE_FIBRE));

    set_flag(&mut services, NODE_BAN_LIST_SHARING);
    assert!(has_flag(services, NODE_BAN_LIST_SHARING));
}

#[test]
fn test_flag_combinations() {
    // Test common flag combinations
    let mut services = 0u64;

    // Full node with all standard features
    set_flag(&mut services, NODE_NETWORK);
    set_flag(&mut services, NODE_WITNESS);
    set_flag(&mut services, NODE_COMPACT_FILTERS);

    assert!(has_flag(services, NODE_NETWORK));
    assert!(has_flag(services, NODE_WITNESS));
    assert!(has_flag(services, NODE_COMPACT_FILTERS));
    assert!(!has_flag(services, NODE_NETWORK_LIMITED));

    // Pruned node
    let mut pruned = 0u64;
    set_flag(&mut pruned, NODE_NETWORK);
    set_flag(&mut pruned, NODE_NETWORK_LIMITED);
    set_flag(&mut pruned, NODE_WITNESS);

    assert!(has_flag(pruned, NODE_NETWORK));
    assert!(has_flag(pruned, NODE_NETWORK_LIMITED));
    assert!(has_flag(pruned, NODE_WITNESS));
}

#[test]
fn test_commons_flag_combinations() {
    // Test Commons flag combinations
    let mut services = 0u64;

    // Full Commons node
    set_flag(&mut services, NODE_NETWORK);
    set_flag(&mut services, NODE_FIBRE);
    set_flag(&mut services, NODE_PACKAGE_RELAY);
    set_flag(&mut services, NODE_DANDELION);
    set_flag(&mut services, NODE_BAN_LIST_SHARING);

    assert!(has_flag(services, NODE_FIBRE));
    assert!(has_flag(services, NODE_PACKAGE_RELAY));
    assert!(has_flag(services, NODE_DANDELION));
    assert!(has_flag(services, NODE_BAN_LIST_SHARING));
    assert!(supports_commons(services));
}

#[test]
fn test_clear_flag_behavior() {
    let mut services = NODE_NETWORK | NODE_WITNESS | NODE_BLOOM;

    // Clear one flag
    assert!(clear_flag(&mut services, NODE_BLOOM));
    assert!(!has_flag(services, NODE_BLOOM));
    assert!(has_flag(services, NODE_NETWORK));
    assert!(has_flag(services, NODE_WITNESS));

    // Clear flag that's not set
    assert!(!clear_flag(&mut services, NODE_BLOOM));
    assert!(!has_flag(services, NODE_BLOOM));
}

#[test]
fn test_get_commons_flags() {
    let flags = get_commons_flags();

    // Should include all Commons flags
    assert!(has_flag(flags, NODE_DANDELION));
    assert!(has_flag(flags, NODE_PACKAGE_RELAY));
    assert!(has_flag(flags, NODE_FIBRE));
    assert!(has_flag(flags, NODE_BAN_LIST_SHARING));

    // Should not include standard flags
    assert!(!has_flag(flags, NODE_NETWORK));
    assert!(!has_flag(flags, NODE_WITNESS));
}

#[test]
fn test_supports_commons() {
    // Node with FIBRE should support Commons
    let services1 = NODE_NETWORK | NODE_FIBRE;
    assert!(supports_commons(services1));

    // Node with ban list sharing should support Commons
    let services2 = NODE_NETWORK | NODE_BAN_LIST_SHARING;
    assert!(supports_commons(services2));

    // Node with only standard flags should not support Commons
    let services3 = NODE_NETWORK | NODE_WITNESS;
    assert!(!supports_commons(services3));

    // Node with no flags should not support Commons
    assert!(!supports_commons(0));
}

#[test]
fn test_flag_bit_positions() {
    // Verify flag bit positions don't overlap
    let standard_flags = vec![
        NODE_NETWORK,
        NODE_GETUTXO,
        NODE_BLOOM,
        NODE_WITNESS,
        NODE_XTHIN,
        NODE_COMPACT_FILTERS,
        NODE_NETWORK_LIMITED,
    ];

    // Check no overlaps
    for i in 0..standard_flags.len() {
        for j in (i + 1)..standard_flags.len() {
            assert_eq!(
                standard_flags[i] & standard_flags[j],
                0,
                "Flags {} and {} overlap",
                i,
                j
            );
        }
    }

    // Commons flags should be in higher bits
    let commons_flags = vec![
        NODE_DANDELION,
        NODE_PACKAGE_RELAY,
        NODE_FIBRE,
        NODE_BAN_LIST_SHARING,
    ];

    // Check no overlaps with standard flags
    for standard in &standard_flags {
        for commons in &commons_flags {
            assert_eq!(
                standard & commons,
                0,
                "Standard flag {:x} and Commons flag {:x} overlap",
                standard,
                commons
            );
        }
    }
}

#[test]
fn test_multiple_flag_operations() {
    let mut services = 0u64;

    // Set multiple flags
    set_flag(&mut services, NODE_NETWORK);
    set_flag(&mut services, NODE_WITNESS);
    set_flag(&mut services, NODE_FIBRE);

    // All should be set
    assert!(has_flag(services, NODE_NETWORK));
    assert!(has_flag(services, NODE_WITNESS));
    assert!(has_flag(services, NODE_FIBRE));

    // Clear one, others should remain
    clear_flag(&mut services, NODE_WITNESS);
    assert!(has_flag(services, NODE_NETWORK));
    assert!(!has_flag(services, NODE_WITNESS));
    assert!(has_flag(services, NODE_FIBRE));
}

#[test]
fn test_flag_edge_cases() {
    // Test with all flags set
    let mut all_flags = u64::MAX;

    // All standard flags should be set
    assert!(has_flag(all_flags, NODE_NETWORK));
    assert!(has_flag(all_flags, NODE_WITNESS));
    assert!(has_flag(all_flags, NODE_FIBRE));

    // Clear one flag
    clear_flag(&mut all_flags, NODE_NETWORK);
    assert!(!has_flag(all_flags, NODE_NETWORK));

    // Test with zero
    assert!(!has_flag(0, NODE_NETWORK));
    assert!(!has_flag(0, NODE_WITNESS));
    assert!(!supports_commons(0));
}

#[test]
fn test_flag_serialization() {
    // Test that flags can be serialized/deserialized
    let mut services = 0u64;
    set_flag(&mut services, NODE_NETWORK);
    set_flag(&mut services, NODE_WITNESS);
    set_flag(&mut services, NODE_FIBRE);

    // Serialize to JSON
    let json = serde_json::to_string(&services).unwrap();
    let deserialized: u64 = serde_json::from_str(&json).unwrap();

    // Flags should be preserved
    assert_eq!(services, deserialized);
    assert!(has_flag(deserialized, NODE_NETWORK));
    assert!(has_flag(deserialized, NODE_WITNESS));
    assert!(has_flag(deserialized, NODE_FIBRE));
}

#[test]
fn test_typical_node_configurations() {
    // Full node configuration
    let mut full_node = 0u64;
    set_flag(&mut full_node, NODE_NETWORK);
    set_flag(&mut full_node, NODE_WITNESS);
    set_flag(&mut full_node, NODE_COMPACT_FILTERS);
    set_flag(&mut full_node, NODE_FIBRE);
    set_flag(&mut full_node, NODE_PACKAGE_RELAY);

    assert!(has_flag(full_node, NODE_NETWORK));
    assert!(has_flag(full_node, NODE_WITNESS));
    assert!(has_flag(full_node, NODE_FIBRE));
    assert!(supports_commons(full_node));

    // Pruned node configuration
    let mut pruned_node = 0u64;
    set_flag(&mut pruned_node, NODE_NETWORK);
    set_flag(&mut pruned_node, NODE_NETWORK_LIMITED);
    set_flag(&mut pruned_node, NODE_WITNESS);

    assert!(has_flag(pruned_node, NODE_NETWORK));
    assert!(has_flag(pruned_node, NODE_NETWORK_LIMITED));
    assert!(!supports_commons(pruned_node));

    // Commons-only node
    let mut commons_node = 0u64;
    set_flag(&mut commons_node, NODE_NETWORK);
    set_flag(&mut commons_node, NODE_FIBRE);
    set_flag(&mut commons_node, NODE_DANDELION);

    assert!(has_flag(commons_node, NODE_NETWORK));
    assert!(supports_commons(commons_node));
}
