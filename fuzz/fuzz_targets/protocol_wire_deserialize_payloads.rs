#![no_main]
//! Direct fuzzing of public `wire::deserialize_*` payload parsers (no framing).
use blvm_protocol::wire::{
    deserialize_addr, deserialize_addrv2, deserialize_block, deserialize_blocktxn,
    deserialize_cmpctblock, deserialize_feefilter, deserialize_getblocks, deserialize_getblocktxn,
    deserialize_getdata, deserialize_getheaders, deserialize_headers, deserialize_inv,
    deserialize_notfound, deserialize_ping, deserialize_pong, deserialize_reject,
    deserialize_sendcmpct, deserialize_tx, deserialize_version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_version(data);
    let _ = deserialize_addr(data);
    let _ = deserialize_addrv2(data);
    let _ = deserialize_inv(data);
    let _ = deserialize_getdata(data);
    let _ = deserialize_getheaders(data);
    let _ = deserialize_headers(data);
    let _ = deserialize_block(data);
    let _ = deserialize_tx(data);
    let _ = deserialize_ping(data);
    let _ = deserialize_pong(data);
    let _ = deserialize_feefilter(data);
    let _ = deserialize_getblocks(data);
    let _ = deserialize_notfound(data);
    let _ = deserialize_reject(data);
    let _ = deserialize_sendcmpct(data);
    let _ = deserialize_cmpctblock(data);
    let _ = deserialize_getblocktxn(data);
    let _ = deserialize_blocktxn(data);

    if data.len() > 4 {
        let mid = data.len() / 2;
        let _ = deserialize_headers(&data[..mid]);
        let _ = deserialize_tx(&data[mid..]);
    }
});
