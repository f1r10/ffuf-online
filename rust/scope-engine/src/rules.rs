//! Target normalization and rule matching.
//!
//! All matching is done on a *normalized* host (lowercase, trailing dot
//! stripped, IPv6 brackets removed) and, for URL rules, on a normalized full
//! URL (lowercase scheme+host, single slashes, no trailing slash).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::error::Error;
use crate::model::{RuleKind, ScopeRule, Target, TargetKind};

/// Characters that are never valid inside a target value.
const FORBIDDEN: &[char] = &[';', '|', '&', '$', '`', '\'', '"'];

/// A normalized view of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    /// Lowercase host (or IP / CIDR string for those kinds).
    pub host: String,
    /// Normalized full URL, when the target carries a scheme.
    pub full_url: Option<String>,
}

/// Returns `true` if `s` contains whitespace, a control character, or any of
/// the [`FORBIDDEN`] characters.
fn contains_forbidden(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || FORBIDDEN.contains(&c))
}

/// Lowercase a value and strip a single trailing dot.
fn lowercase_strip_dot(s: &str) -> String {
    let lower = s.to_lowercase();
    match lower.strip_suffix('.') {
        Some(trimmed) => trimmed.to_string(),
        None => lower,
    }
}

/// Remove surrounding IPv6 brackets: `[::1]` -> `::1`.
fn strip_brackets(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Split `host[:port]` (handling `[ipv6]`) into a host and an optional port.
fn split_authority(authority: &str) -> (String, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let host = &rest[..idx];
            let after = &rest[idx + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
            return (host.to_string(), port);
        }
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), Some(port));
        }
    }
    (authority.to_string(), None)
}

/// Parsed pieces of a `scheme://host[:port]/path` string.
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

/// Parse a bare URL of the form `scheme://host[:port][/path]`.
fn parse_url(s: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = s.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), String::new()),
    };
    let (host, port) = split_authority(&authority);
    let host = lowercase_strip_dot(&strip_brackets(&host));
    if host.is_empty() {
        return None;
    }
    Some(ParsedUrl {
        scheme: scheme.to_lowercase(),
        host,
        port,
        path,
    })
}

/// Collapse repeated slashes and strip a trailing slash (leaving the empty
/// root as an empty string).
fn normalize_path(p: &str) -> String {
    let mut out = String::new();
    let mut prev_slash = false;
    for c in p.chars() {
        if c == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    while out.ends_with('/') && out.len() > 1 {
        out.pop();
    }
    if out == "/" {
        out.clear();
    }
    out
}

/// Reassemble a normalized URL from its parts (re-bracketing IPv6 hosts).
fn build_url(scheme: &str, host: &str, port: Option<u16>, path: &str) -> String {
    let host_part = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    let mut url = format!("{}://{}", scheme, host_part);
    if let Some(p) = port {
        url.push(':');
        url.push_str(&p.to_string());
    }
    url.push_str(path);
    url
}

/// Normalize an arbitrary URL-ish string into the canonical URL form.
pub fn normalize_rule_url(value: &str) -> String {
    let v = lowercase_strip_dot(value);
    match parse_url(&v) {
        Some(p) => {
            let path = normalize_path(&p.path);
            build_url(&p.scheme, &p.host, p.port, &path)
        }
        None => v.trim_end_matches('/').to_string(),
    }
}

/// Extract the host portion of a URL-ish string (used for redirect
/// re-validation).
pub fn extract_host(url: &str) -> Option<String> {
    let v = lowercase_strip_dot(url);
    if let Some(p) = parse_url(&v) {
        return Some(p.host);
    }
    let no_path = v.split('/').next().unwrap_or(&v);
    let (host, _) = split_authority(no_path);
    let host = strip_brackets(&host);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Normalize and validate a target.
pub fn normalize_target(target: &Target) -> Result<NormalizedTarget, Error> {
    let raw_value = target.value.as_str();
    if raw_value.is_empty() {
        return Err(Error::invalid_target("target value is empty"));
    }
    if contains_forbidden(raw_value) {
        return Err(Error::invalid_target(
            "target value contains whitespace or forbidden characters",
        ));
    }

    let value = lowercase_strip_dot(raw_value);

    match target.kind {
        TargetKind::Ip => {
            let host = strip_brackets(&value);
            if host.parse::<IpAddr>().is_err() {
                return Err(Error::invalid_target(format!(
                    "`{}` is not a valid IP address",
                    target.value
                )));
            }
            return Ok(NormalizedTarget {
                host,
                full_url: None,
            });
        }
        TargetKind::Cidr => {
            let host = strip_brackets(&value);
            if host.parse::<IpNet>().is_err() {
                return Err(Error::invalid_target(format!(
                    "`{}` is not a valid CIDR network",
                    target.value
                )));
            }
            return Ok(NormalizedTarget {
                host,
                full_url: None,
            });
        }
        _ => {}
    }

    // A value that is a bare URL is split into its parts; explicit struct
    // fields win over anything parsed from the value.
    let parsed = parse_url(&value);

    let scheme = target
        .scheme
        .as_ref()
        .map(|s| s.to_lowercase())
        .or_else(|| parsed.as_ref().map(|p| p.scheme.clone()));

    let host = if let Some(h) = target.host.as_ref() {
        lowercase_strip_dot(&strip_brackets(h))
    } else if let Some(p) = parsed.as_ref() {
        p.host.clone()
    } else {
        strip_brackets(&value)
    };

    if host.is_empty() {
        return Err(Error::invalid_target("target host is empty"));
    }

    let port = target
        .port
        .or_else(|| parsed.as_ref().and_then(|p| p.port));

    let path = target
        .path
        .clone()
        .or_else(|| parsed.as_ref().map(|p| p.path.clone()));

    let full_url = scheme.as_ref().map(|s| {
        build_url(
            s,
            &host,
            port,
            &normalize_path(path.as_deref().unwrap_or("")),
        )
    });

    Ok(NormalizedTarget { host, full_url })
}

/// `Domain` matches the apex and any sub-domain, on label boundaries.
pub fn domain_rule_matches(rule_value: &str, host: &str) -> bool {
    let rv = lowercase_strip_dot(rule_value);
    if rv.is_empty() {
        return false;
    }
    host == rv || host.ends_with(&format!(".{}", rv))
}

/// `WildcardDomain` matches sub-domains only, never the apex.
pub fn wildcard_rule_matches(rule_value: &str, host: &str) -> bool {
    let rv = lowercase_strip_dot(rule_value);
    let rv = rv.strip_prefix("*.").unwrap_or(&rv).to_string();
    if rv.is_empty() {
        return false;
    }
    host.ends_with(&format!(".{}", rv))
}

/// `Hostname` matches with exact case-insensitive equality only.
pub fn hostname_rule_matches(rule_value: &str, host: &str) -> bool {
    lowercase_strip_dot(rule_value) == host
}

/// `Ip` matches when both sides parse as `IpAddr` and are equal.
pub fn ip_rule_matches(rule_value: &str, value: &str) -> bool {
    match (rule_value.parse::<IpAddr>(), value.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `Cidr` matches when `value` parses as an `IpAddr` inside the network.
pub fn cidr_rule_matches(rule_value: &str, value: &str) -> bool {
    match (rule_value.parse::<IpNet>(), value.parse::<IpAddr>()) {
        (Ok(net), Ok(ip)) => net.contains(&ip),
        _ => false,
    }
}

/// `UrlPrefix` matches a normalized full URL prefix on a boundary.
pub fn url_prefix_rule_matches(rule_value: &str, full_url: &str) -> bool {
    let ru = normalize_rule_url(rule_value);
    let fu = normalize_rule_url(full_url);
    if ru.is_empty() || fu.is_empty() {
        return false;
    }
    if !fu.starts_with(&ru) {
        return false;
    }
    match fu.as_bytes().get(ru.len()) {
        // Exact match, or a boundary at a path separator / port.
        None | Some(b'/') | Some(b':') => true,
        Some(_) => false,
    }
}

/// Decide whether a rule matches a normalized target.
///
/// `host` is the normalized host; `full_url` is present when the target has a
/// scheme; `dest_ip` is the destination IP being checked (for `Ip`/`Cidr`).
pub fn rule_matches(
    rule: &ScopeRule,
    host: &str,
    full_url: Option<&str>,
    dest_ip: Option<&str>,
) -> bool {
    match rule.kind {
        RuleKind::Domain => domain_rule_matches(&rule.value, host),
        RuleKind::WildcardDomain => wildcard_rule_matches(&rule.value, host),
        RuleKind::Hostname => hostname_rule_matches(&rule.value, host),
        RuleKind::Ip => {
            ip_rule_matches(&rule.value, host)
                || dest_ip.is_some_and(|d| ip_rule_matches(&rule.value, d))
        }
        RuleKind::Cidr => {
            cidr_rule_matches(&rule.value, host)
                || dest_ip.is_some_and(|d| cidr_rule_matches(&rule.value, d))
        }
        RuleKind::UrlPrefix => {
            full_url.is_some_and(|u| url_prefix_rule_matches(&rule.value, u))
        }
    }
}

/// Helper used by tests and callers: is `value` a syntactically valid IP?
pub fn is_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
}

/// Helper used by tests: is `value` a valid IPv4 or IPv6 literal (bracketed
/// forms allowed)?
pub fn is_ipv4(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok()
}

/// Helper used by tests: is `value` a valid IPv6 literal (bracketed forms
/// allowed)?
pub fn is_ipv6(value: &str) -> bool {
    strip_brackets(value).parse::<Ipv6Addr>().is_ok()
}
