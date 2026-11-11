//! Hard IP guards.
//!
//! Certain destination classes must never be reachable, regardless of scope
//! rules. The checks are ordered and the **first** match wins.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::model::ReasonCode;

/// Reserved / never-routable IPv4 networks.
const RESERVED_V4: &[&str] = &[
    "0.0.0.0/8",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
];

/// Reserved / never-routable IPv6 networks.
const RESERVED_V6: &[&str] = &["::/128", "::/8", "2001:db8::/32", "ff00::/8"];

/// The IPv4 cloud metadata endpoint (AWS/GCP/Azure/OpenStack).
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// The IPv6 cloud metadata endpoint (AWS IMDSv2 over IPv6).
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);

/// Classify an IP address, returning the blocking reason or `None` when the
/// address is public and allowed.
///
/// Order (first match wins):
/// 1. cloud metadata
/// 2. loopback
/// 3. link-local
/// 4. private
/// 5. reserved / never-routable
pub fn classify(ip: IpAddr) -> Option<ReasonCode> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Ensure an IP is allowed, returning the blocking reason otherwise.
pub fn ensure_allowed(ip: IpAddr) -> Result<(), ReasonCode> {
    match classify(ip) {
        Some(code) => Err(code),
        None => Ok(()),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Option<ReasonCode> {
    if ip == METADATA_V4 {
        return Some(ReasonCode::MetadataIpBlocked);
    }
    if ip.is_loopback() {
        return Some(ReasonCode::LoopbackIpBlocked);
    }
    if ip.is_link_local() {
        return Some(ReasonCode::LinkLocalIpBlocked);
    }
    if ip.is_private() {
        return Some(ReasonCode::PrivateIpBlocked);
    }
    for cidr in RESERVED_V4 {
        let net: Ipv4Net = cidr.parse().expect("static CIDR is valid");
        if net.contains(&ip) {
            return Some(ReasonCode::ReservedIpBlocked);
        }
    }
    None
}

fn classify_v6(ip: Ipv6Addr) -> Option<ReasonCode> {
    if ip == METADATA_V6 {
        return Some(ReasonCode::MetadataIpBlocked);
    }
    if ip.is_loopback() {
        return Some(ReasonCode::LoopbackIpBlocked);
    }
    let seg = ip.segments();
    // fe80::/10
    if (seg[0] & 0xffc0) == 0xfe80 {
        return Some(ReasonCode::LinkLocalIpBlocked);
    }
    // fc00::/7
    if (seg[0] & 0xfe00) == 0xfc00 {
        return Some(ReasonCode::PrivateIpBlocked);
    }
    for cidr in RESERVED_V6 {
        let net: Ipv6Net = cidr.parse().expect("static CIDR is valid");
        if net.contains(&ip) {
            return Some(ReasonCode::ReservedIpBlocked);
        }
    }
    None
}
