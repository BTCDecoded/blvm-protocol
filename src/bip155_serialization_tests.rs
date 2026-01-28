//! Tests for BIP155 serialization/deserialization

#[cfg(test)]
mod tests {
    use crate::network::{AddrV2Message, AddressType, NetworkAddressV2};
    
    // Note: Serialization functions are currently private in wire.rs
    // Full serialization round-trip tests can be added when wire format module is more exposed.
    // For now, we test the data structures and validation.
    
    #[test]
    fn test_addrv2_message_structure() {
        // Test that AddrV2Message can be created with various address types
        let mut addresses = Vec::new();
        
        // IPv4
        let ipv4_addr = vec![192, 168, 1, 1];
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::IPv4, ipv4_addr, 8333).unwrap(),
        );
        
        // IPv6
        let ipv6_addr = vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::IPv6, ipv6_addr, 8333).unwrap(),
        );
        
        // Tor v3
        let mut tor_addr = vec![0u8; 32];
        for i in 0..32 {
            tor_addr[i] = i as u8;
        }
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::TorV3, tor_addr, 8333).unwrap(),
        );
        
        let addrv2 = AddrV2Message { addresses };
        assert_eq!(addrv2.addresses.len(), 3);
        assert_eq!(addrv2.addresses[0].address_type, AddressType::IPv4);
        assert_eq!(addrv2.addresses[1].address_type, AddressType::IPv6);
        assert_eq!(addrv2.addresses[2].address_type, AddressType::TorV3);
    }
}
