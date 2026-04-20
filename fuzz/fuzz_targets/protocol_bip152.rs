#![no_main]
//! BIP152 compact block wire paths: sendcmpct, cmpctblock, getblocktxn, blocktxn.
use blvm_protocol::bip152::CompactBlock;
use blvm_protocol::wire::{
    deserialize_blocktxn, deserialize_cmpctblock, deserialize_getblocktxn, deserialize_sendcmpct,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_sendcmpct(data);
    let _ = deserialize_getblocktxn(data);
    let _ = deserialize_blocktxn(data);

    if let Ok(wire) = deserialize_cmpctblock(data) {
        let _: CompactBlock = CompactBlock::from(&wire);
        let _: CompactBlock = wire.clone().into();
    }
});
