//! Tests for BIP155 (addrv2 message)

#[cfg(test)]
mod tests {
    use crate::network::{AddrV2Message, AddressType, NetworkAddressV2};

    #[test]
    fn test_address_type_lengths() {
        assert_eq!(AddressType::IPv4.address_length(), 4);
        assert_eq!(AddressType::IPv6.address_length(), 16);
        assert_eq!(AddressType::TorV2.address_length(), 10);
        assert_eq!(AddressType::TorV3.address_length(), 32);
        assert_eq!(AddressType::I2P.address_length(), 32);
        assert_eq!(AddressType::CJDNS.address_length(), 16);
    }

    #[test]
    fn test_address_type_from_u8() {
        assert_eq!(AddressType::from_u8(1), Some(AddressType::IPv4));
        assert_eq!(AddressType::from_u8(2), Some(AddressType::IPv6));
        assert_eq!(AddressType::from_u8(3), Some(AddressType::TorV2));
        assert_eq!(AddressType::from_u8(4), Some(AddressType::TorV3));
        assert_eq!(AddressType::from_u8(5), Some(AddressType::I2P));
        assert_eq!(AddressType::from_u8(6), Some(AddressType::CJDNS));
        assert_eq!(AddressType::from_u8(0), None);
        assert_eq!(AddressType::from_u8(255), None);
    }

    #[test]
    fn test_network_address_v2_creation() {
        // Valid IPv4 address
        let ipv4_addr = vec![192, 168, 1, 1];
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv4,
            ipv4_addr.clone(),
            8333,
        )
        .unwrap();
        assert_eq!(addr.time, 1234567890);
        assert_eq!(addr.services, 1);
        assert_eq!(addr.address_type, AddressType::IPv4);
        assert_eq!(addr.address, ipv4_addr);
        assert_eq!(addr.port, 8333);
    }

    #[test]
    fn test_network_address_v2_invalid_length() {
        // IPv4 address with wrong length
        let invalid_addr = vec![192, 168, 1]; // Only 3 bytes, should be 4
        let result = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv4,
            invalid_addr,
            8333,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_network_address_v2_ipv6() {
        // Valid IPv6 address
        let ipv6_addr = vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv6,
            ipv6_addr.clone(),
            8333,
        )
        .unwrap();
        assert_eq!(addr.address_type, AddressType::IPv6);
        assert_eq!(addr.address, ipv6_addr);
    }

    #[test]
    fn test_network_address_v2_tor_v3() {
        // Valid Tor v3 address (32 bytes)
        let mut tor_addr = vec![0u8; 32];
        for i in 0..32 {
            tor_addr[i] = i as u8;
        }
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::TorV3,
            tor_addr.clone(),
            8333,
        )
        .unwrap();
        assert_eq!(addr.address_type, AddressType::TorV3);
        assert_eq!(addr.address, tor_addr);
    }

    #[test]
    fn test_to_legacy_ipv4() {
        // IPv4 address should convert to legacy format
        let ipv4_addr = vec![192, 168, 1, 1];
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv4,
            ipv4_addr,
            8333,
        )
        .unwrap();
        let legacy = addr.to_legacy();
        assert!(legacy.is_some());
        let legacy_addr = legacy.unwrap();
        assert_eq!(legacy_addr.port, 8333);
        assert_eq!(legacy_addr.services, 1);
        // Check IPv6-mapped format: ::ffff:192.168.1.1
        assert_eq!(legacy_addr.ip[10], 0xff);
        assert_eq!(legacy_addr.ip[11], 0xff);
        assert_eq!(legacy_addr.ip[12], 192);
        assert_eq!(legacy_addr.ip[13], 168);
        assert_eq!(legacy_addr.ip[14], 1);
        assert_eq!(legacy_addr.ip[15], 1);
    }

    #[test]
    fn test_to_legacy_ipv6() {
        // IPv6 address should convert to legacy format
        let ipv6_addr = vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv6,
            ipv6_addr.clone(),
            8333,
        )
        .unwrap();
        let legacy = addr.to_legacy();
        assert!(legacy.is_some());
        let legacy_addr = legacy.unwrap();
        assert_eq!(legacy_addr.port, 8333);
        assert_eq!(legacy_addr.services, 1);
        // Check IPv6 address matches
        let mut expected_ip = [0u8; 16];
        expected_ip.copy_from_slice(&ipv6_addr);
        assert_eq!(legacy_addr.ip, expected_ip);
    }

    #[test]
    fn test_to_legacy_tor_v3() {
        // Tor v3 address should NOT convert to legacy format
        let mut tor_addr = vec![0u8; 32];
        for i in 0..32 {
            tor_addr[i] = i as u8;
        }
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::TorV3,
            tor_addr,
            8333,
        )
        .unwrap();
        let legacy = addr.to_legacy();
        assert!(legacy.is_none()); // Tor addresses can't be converted
    }

    #[test]
    fn test_addrv2_message() {
        let mut addresses = Vec::new();
        
        // Add IPv4 address
        let ipv4_addr = vec![192, 168, 1, 1];
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::IPv4, ipv4_addr, 8333).unwrap(),
        );
        
        // Add IPv6 address
        let ipv6_addr = vec![
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::IPv6, ipv6_addr, 8333).unwrap(),
        );
        
        // Add Tor v3 address
        let mut tor_addr = vec![0u8; 32];
        for i in 0..32 {
            tor_addr[i] = i as u8;
        }
        addresses.push(
            NetworkAddressV2::new(1234567890, 1, AddressType::TorV3, tor_addr, 8333).unwrap(),
        );
        
        let addrv2 = AddrV2Message { addresses };
        assert_eq!(addrv2.addresses.len(), 3);
    }
}

