#![no_main]
//! Framed P2P decode + command dispatch (mirrors node allowlist; fuzz must exercise every arm).
use blvm_protocol::node_tcp::TcpFramedParser;
use blvm_protocol::p2p_commands::cmd;
use libfuzzer_sys::fuzz_target;

/// Superset of commands a production node may accept (matches `blvm-node` `ALLOWED_COMMANDS` without optional erlay / CTV-only cmds).
const ALLOWED: &[&str] = &[
    cmd::VERSION,
    cmd::VERACK,
    cmd::PING,
    cmd::PONG,
    cmd::GETHEADERS,
    cmd::HEADERS,
    cmd::SENDHEADERS,
    cmd::GETBLOCKS,
    cmd::BLOCK,
    cmd::GETDATA,
    cmd::INV,
    cmd::TX,
    cmd::NOTFOUND,
    cmd::GETADDR,
    cmd::ADDR,
    cmd::ADDRV2,
    cmd::MEMPOOL,
    cmd::REJECT,
    cmd::FEEFILTER,
    cmd::SENDCMPCT,
    cmd::CMPCTBLOCK,
    cmd::GETBLOCKTXN,
    cmd::BLOCKTXN,
    cmd::GETUTXOSET,
    cmd::UTXOSET,
    cmd::GETUTXOPROOF,
    cmd::UTXOPROOF,
    cmd::GETFILTEREDBLOCK,
    cmd::FILTEREDBLOCK,
    cmd::GETCFILTERS,
    cmd::CFILTER,
    cmd::GETCFHEADERS,
    cmd::CFHEADERS,
    cmd::GETCFCHECKPT,
    cmd::CFCHECKPT,
    cmd::GETPAYMENTREQUEST,
    cmd::PAYMENTREQUEST,
    cmd::PAYMENT,
    cmd::PAYMENTACK,
    cmd::SETTLEMENTNOTIFICATION,
    cmd::SENDPKGTXN,
    cmd::PKGTXN,
    cmd::PKGTXNREJECT,
    cmd::GETBANLIST,
    cmd::BANLIST,
    cmd::ECONREG,
    cmd::ECONVETO,
    cmd::ECONSTATUS,
    cmd::ECONFORK,
    cmd::GETMODULE,
    cmd::MODULE,
    cmd::GETMODULEBYHASH,
    cmd::MODULEBYHASH,
    cmd::MODULEINV,
    cmd::GETMODULELIST,
    cmd::MODULELIST,
    cmd::MESH,
];

fuzz_target!(|data: &[u8]| {
    let _ = TcpFramedParser::parse_message(data, ALLOWED);

    if data.len() > 24 {
        let _ = TcpFramedParser::parse_message(&data[..24], ALLOWED);
    }
    if data.len() >= 24 {
        let mut corrupted = data.to_vec();
        corrupted[0] = !corrupted[0];
        let _ = TcpFramedParser::parse_message(&corrupted, ALLOWED);
    }
});
