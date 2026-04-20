#![no_main]
//! BIP70 P2P payment types: bincode decode + `validate` / `PaymentProtocolClient` paths.
use blvm_protocol::payment::{
    Payment, PaymentACK, PaymentProtocolClient, PaymentRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<PaymentRequest>(data);
    let _ = bincode::deserialize::<Payment>(data);
    let _ = bincode::deserialize::<PaymentACK>(data);

    if let Ok(pr) = bincode::deserialize::<PaymentRequest>(data) {
        let _ = pr.validate();
        let _ = PaymentProtocolClient::validate_payment_request(&pr, None);
    }

    if let Ok(p) = bincode::deserialize::<Payment>(data) {
        let _ = p.validate();
    }

    if let Ok(ack) = bincode::deserialize::<PaymentACK>(data) {
        if data.len() >= 33 {
            let _ = ack.verify_signature(&data[..33]);
        }
    }
});
