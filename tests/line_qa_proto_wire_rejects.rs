//! Rejects the wire decoders already return for a short payload or a bad address.

use blvm_protocol::address::{AddressError, BitcoinAddress};
use blvm_protocol::wire::{deserialize_feefilter, deserialize_ping, deserialize_pong};

#[test]
fn deserialize_ping_rejects_a_short_payload() {
    match deserialize_ping(&[1, 2, 3]) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("Ping message too short: 3 bytes"),
                "short ping returned {message}"
            );
        }
        Ok(ping) => panic!("short ping decoded nonce {}", ping.nonce),
    }
}

#[test]
fn deserialize_pong_rejects_a_short_payload() {
    match deserialize_pong(&[0; 7]) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("Pong message too short: 7 bytes"),
                "short pong returned {message}"
            );
        }
        Ok(pong) => panic!("short pong decoded nonce {}", pong.nonce),
    }
}

#[test]
fn deserialize_feefilter_rejects_a_short_payload() {
    match deserialize_feefilter(&[]) {
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("FeeFilter message too short"),
                "short feefilter returned {message}"
            );
        }
        Ok(filter) => panic!("empty feefilter decoded rate {}", filter.feerate),
    }
}

#[test]
fn bitcoin_address_decode_rejects_text_that_is_not_bech32() {
    match BitcoinAddress::decode("not-an-address") {
        Err(AddressError::InvalidEncoding) => {}
        Ok(address) => panic!("plain text decoded as {address:?}"),
        Err(other) => panic!("plain text returned {other:?}"),
    }
}
