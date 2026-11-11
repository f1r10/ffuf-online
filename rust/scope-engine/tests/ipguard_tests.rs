//! Table-driven tests for the hard IP guards.

use std::net::IpAddr;

use scope_engine::ipguard::{classify, ensure_allowed};
use scope_engine::model::ReasonCode;

/// One row: (address, expected classification).
const TABLE: &[(&str, Option<ReasonCode>)] = &[
    // ---- cloud metadata ----
    ("169.254.169.254", Some(ReasonCode::MetadataIpBlocked)),
    ("fd00:ec2::254", Some(ReasonCode::MetadataIpBlocked)),
    // ---- loopback ----
    ("127.0.0.1", Some(ReasonCode::LoopbackIpBlocked)),
    ("127.255.255.255", Some(ReasonCode::LoopbackIpBlocked)),
    ("::1", Some(ReasonCode::LoopbackIpBlocked)),
    // ---- link-local ----
    ("169.254.0.1", Some(ReasonCode::LinkLocalIpBlocked)),
    ("169.254.255.255", Some(ReasonCode::LinkLocalIpBlocked)),
    ("fe80::1", Some(ReasonCode::LinkLocalIpBlocked)),
    ("fe80::abcd:1234", Some(ReasonCode::LinkLocalIpBlocked)),
    // ---- private ----
    ("10.0.0.1", Some(ReasonCode::PrivateIpBlocked)),
    ("10.255.255.255", Some(ReasonCode::PrivateIpBlocked)),
    ("172.16.0.1", Some(ReasonCode::PrivateIpBlocked)),
    ("172.31.255.255", Some(ReasonCode::PrivateIpBlocked)),
    ("192.168.0.1", Some(ReasonCode::PrivateIpBlocked)),
    ("192.168.255.255", Some(ReasonCode::PrivateIpBlocked)),
    ("fc00::1", Some(ReasonCode::PrivateIpBlocked)),
    ("fd00::1", Some(ReasonCode::PrivateIpBlocked)),
    // ---- reserved / never-routable ----
    ("0.0.0.0", Some(ReasonCode::ReservedIpBlocked)),
    ("0.1.2.3", Some(ReasonCode::ReservedIpBlocked)),
    ("100.64.0.1", Some(ReasonCode::ReservedIpBlocked)),
    ("100.127.255.254", Some(ReasonCode::ReservedIpBlocked)),
    ("192.0.0.1", Some(ReasonCode::ReservedIpBlocked)),
    ("192.0.2.5", Some(ReasonCode::ReservedIpBlocked)),
    ("198.18.0.1", Some(ReasonCode::ReservedIpBlocked)),
    ("198.51.100.7", Some(ReasonCode::ReservedIpBlocked)),
    ("203.0.113.9", Some(ReasonCode::ReservedIpBlocked)),
    ("224.0.0.1", Some(ReasonCode::ReservedIpBlocked)),
    ("239.255.255.255", Some(ReasonCode::ReservedIpBlocked)),
    ("240.0.0.1", Some(ReasonCode::ReservedIpBlocked)),
    ("255.255.255.255", Some(ReasonCode::ReservedIpBlocked)),
    ("::", Some(ReasonCode::ReservedIpBlocked)),
    ("2001:db8::1", Some(ReasonCode::ReservedIpBlocked)),
    ("ff02::1", Some(ReasonCode::ReservedIpBlocked)),
    // ---- public / allowed ----
    ("8.8.8.8", None),
    ("1.1.1.1", None),
    ("93.184.216.34", None),
    ("172.32.0.1", None),  // just outside 172.16/12
    ("100.128.0.1", None), // just outside 100.64/10
    ("192.167.1.1", None), // just below 192.168/16
    ("11.0.0.1", None),    // just outside 10/8
    ("2001:4860:4860::8888", None),
    ("2606:4700:4700::1111", None),
];

#[test]
fn classify_table() {
    assert!(TABLE.len() >= 30, "table must cover at least 30 addresses");
    for (addr, expected) in TABLE {
        let ip: IpAddr = addr.parse().expect("test address must parse");
        assert_eq!(
            classify(ip),
            *expected,
            "classify({}) => {:?}, expected {:?}",
            addr,
            classify(ip),
            expected
        );
    }
}

#[test]
fn ensure_allowed_matches_classify() {
    for (addr, expected) in TABLE {
        let ip: IpAddr = addr.parse().unwrap();
        match expected {
            Some(code) => assert_eq!(ensure_allowed(ip), Err(*code), "ensure_allowed({})", addr),
            None => assert_eq!(ensure_allowed(ip), Ok(()), "ensure_allowed({})", addr),
        }
    }
}

#[test]
fn metadata_is_checked_before_link_local() {
    // 169.254.169.254 is inside link-local 169.254/16 but must report metadata.
    let ip: IpAddr = "169.254.169.254".parse().unwrap();
    assert_eq!(classify(ip), Some(ReasonCode::MetadataIpBlocked));
}
