//! Tests for BIP155 serialization/deserialization

#[cfg(test)]
mod tests {
    use crate::network::{AddrV2Message, AddressType, NetworkAddressV2};
    use crate::wire::{deserialize_addrv2, serialize_addrv2};

    #[test]
    fn test_serialize_deserialize_addrv2_ipv4() {
        let ipv4_addr = vec![192, 168, 1, 1];
        let addr = NetworkAddressV2::new(
            1234567890,
            1,
            AddressType::IPv4,
            ipv4_addr.clone(),
            8333,
        )
        .unwrap();
        let addrv2 = AddrV2Message {
            addresses: vec![addr],
        };

        let serialized = serialize_addrv2(&addrv2).unwrap();
        let deserialized = deserialize_addrv2(&serialized).unwrap();

        assert_eq!(addrv2.addresses.len(), deserialized.addresses.len());
        assert_eq!(addrv2.addresses[0].time, deserialized.addresses[0].time);
        assert_eq!(addrv2.addresses[0].services, deserialized.addresses[0].services);
        assert_eq!(addrv2.addresses[0].address_type, deserialized.addresses[0].address_type);
        assert_eq!(addrv2.addresses[0].address, deserialized.addresses[0].address);
        assert_eq!(addrv2.addresses[0].port, deserialized.addresses[0].port);
    }

    #[test]
    fn test_serialize_deserialize_addrv2_ipv6() {
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
        let addrv2 = AddrV2Message {
            addresses: vec![addr],
        };

        let serialized = serialize_addrv2(&addrv2).unwrap();
        let deserialized = deserialize_addrv2(&serialized).unwrap();

        assert_eq!(addrv2.addresses[0].address_type, deserialized.addresses[0].address_type);
        assert_eq!(addrv2.addresses[0].address, deserialized.addresses[0].address);
    }

    #[test]
    fn test_serialize_deserialize_addrv2_tor_v3() {
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
        let addrv2 = AddrV2Message {
            addresses: vec![addr],
        };

        let serialized = serialize_addrv2(&addrv2).unwrap();
        let deserialized = deserialize_addrv2(&serialized).unwrap();

        assert_eq!(addrv2.addresses[0].address_type, deserialized.addresses[0].address_type);
        assert_eq!(addrv2.addresses[0].address, deserialized.addresses[0].address);
    }

    #[test]
    fn test_serialize_deserialize_addrv2_multiple() {
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

        let serialized = serialize_addrv2(&addrv2).unwrap();
        let deserialized = deserialize_addrv2(&serialized).unwrap();

        assert_eq!(addrv2.addresses.len(), deserialized.addresses.len());
        for i in 0..addrv2.addresses.len() {
            assert_eq!(addrv2.addresses[i].address_type, deserialized.addresses[i].address_type);
            assert_eq!(addrv2.addresses[i].address, deserialized.addresses[i].address);
        }
    }
}

