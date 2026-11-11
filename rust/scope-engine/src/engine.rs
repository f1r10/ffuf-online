//! The scope evaluation pipeline.
//!
//! `evaluate` runs the checks in a fixed order and returns the **first**
//! failing decision. See the crate README for the full pipeline.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::model::{
    Decision, PolicyProfile, ReasonCode, RuleAction, ScopeDecision, ScopeRequest, ScopeRule,
};
use crate::{ipguard, rules};

/// Risk flag emitted when the destination IP is not among the resolved IPs.
pub const DNS_REBINDING_FLAG: &str = "dns_rebinding_suspected";

/// Build a [`ScopeDecision`].
#[allow(clippy::too_many_arguments)]
fn make_decision(
    request_id: &str,
    scope_version: u32,
    decision: Decision,
    reason_code: ReasonCode,
    reason: impl Into<String>,
    matched_rule_id: Option<String>,
    normalized_target: Option<String>,
    risk_flags: Vec<String>,
) -> ScopeDecision {
    ScopeDecision {
        request_id: request_id.to_string(),
        decision,
        reason_code,
        reason: reason.into(),
        matched_rule_id,
        normalized_target,
        risk_flags,
        scope_version,
        evaluated_at: Utc::now(),
    }
}

/// Build a rejection carrying the request id / scope version, used by the
/// egress path after a successful scope evaluation.
pub fn make_rejection(
    req: &ScopeRequest,
    reason_code: ReasonCode,
    reason: impl Into<String>,
) -> ScopeDecision {
    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let scope_version = req.scope_version.unwrap_or(0);
    let normalized_target = rules::normalize_target(&req.target).ok().map(|n| n.host);
    make_decision(
        &request_id,
        scope_version,
        Decision::Rejected,
        reason_code,
        reason,
        None,
        normalized_target,
        Vec::new(),
    )
}

/// Evaluate a scope request, returning the resulting decision.
pub fn evaluate(req: &ScopeRequest) -> ScopeDecision {
    let now: DateTime<Utc> = req.now.unwrap_or_else(Utc::now);
    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let scope_version = req.scope_version.unwrap_or(0);

    let reject = |reason_code: ReasonCode,
                  reason: String,
                  matched_rule_id: Option<String>,
                  normalized_target: Option<String>,
                  risk_flags: Vec<String>| {
        make_decision(
            &request_id,
            scope_version,
            Decision::Rejected,
            reason_code,
            reason,
            matched_rule_id,
            normalized_target,
            risk_flags,
        )
    };

    // 1. Normalize / validate the target.
    let normalized = match rules::normalize_target(&req.target) {
        Ok(n) => n,
        Err(e) => {
            return reject(
                ReasonCode::InvalidTarget,
                e.to_string(),
                None,
                None,
                Vec::new(),
            )
        }
    };
    let host = normalized.host.clone();
    let full_url = normalized.full_url.clone();

    // 2. Authorization.
    match req.authorization.as_ref() {
        None => {
            return reject(
                ReasonCode::AuthorizationMissing,
                "authorization is missing".to_string(),
                None,
                Some(host),
                Vec::new(),
            )
        }
        Some(auth) => {
            if !auth.authorized {
                return reject(
                    ReasonCode::AuthorizationMissing,
                    "authorization.authorized is false".to_string(),
                    None,
                    Some(host),
                    Vec::new(),
                );
            }
            if let Some(expires_at) = auth.expires_at {
                if expires_at <= now {
                    return reject(
                        ReasonCode::AuthorizationExpired,
                        format!("authorization expired at {}", expires_at.to_rfc3339()),
                        None,
                        Some(host),
                        Vec::new(),
                    );
                }
            }
        }
    }

    // 3. Profile gating.
    match req.policy_profile {
        PolicyProfile::Passive => {}
        PolicyProfile::LowImpactDiscovery => {
            if req.rate_policy.is_none() {
                return reject(
                    ReasonCode::RatePolicyMissing,
                    "policy profile `low_impact_discovery` requires a rate policy".to_string(),
                    None,
                    Some(host),
                    Vec::new(),
                );
            }
        }
        PolicyProfile::AuthorizedVulnerabilityTesting => {
            let has_concurrency = req
                .rate_policy
                .as_ref()
                .is_some_and(|r| r.max_concurrency.is_some());
            let has_expiry = req
                .authorization
                .as_ref()
                .and_then(|a| a.expires_at)
                .is_some();
            if !(has_concurrency && has_expiry) {
                return reject(
                    ReasonCode::ProfileNotPermitted,
                    "policy profile `authorized_vulnerability_testing` requires a rate policy \
                     with max_concurrency and an authorization expiry"
                        .to_string(),
                    None,
                    Some(host),
                    Vec::new(),
                );
            }
        }
    }

    // 4. Scope rules.
    if req.scope_rules.is_empty() {
        return reject(
            ReasonCode::NoScopeRules,
            "no scope rules supplied".to_string(),
            None,
            Some(host),
            Vec::new(),
        );
    }

    let dest_ip = req.dest_ip.as_deref();

    // Exclusions always win.
    for rule in &req.scope_rules {
        if rule.action == RuleAction::Exclude
            && rules::rule_matches(rule, &host, full_url.as_deref(), dest_ip)
        {
            return reject(
                ReasonCode::Excluded,
                format!("target matches exclude rule `{}`", rule.id),
                Some(rule.id.clone()),
                Some(host),
                Vec::new(),
            );
        }
    }

    let matched_include: Option<String> = req
        .scope_rules
        .iter()
        .find(|r| {
            r.action == RuleAction::Include
                && rules::rule_matches(r, &host, full_url.as_deref(), dest_ip)
        })
        .map(|r| r.id.clone());

    let matched_include = match matched_include {
        Some(id) => id,
        None => {
            return reject(
                ReasonCode::OutOfScope,
                "target matched no include rule".to_string(),
                None,
                Some(host),
                Vec::new(),
            )
        }
    };

    // 5. IP guards.
    if let Some(ips) = &req.resolved_ips {
        for ip_str in ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if let Some(code) = ipguard::classify(ip) {
                    return reject(
                        code,
                        format!("resolved ip {} is blocked ({:?})", ip_str, code),
                        Some(matched_include.clone()),
                        Some(host),
                        Vec::new(),
                    );
                }
            }
        }
    }
    if let Some(dest) = &req.dest_ip {
        if let Ok(ip) = dest.parse::<IpAddr>() {
            if let Some(code) = ipguard::classify(ip) {
                return reject(
                    code,
                    format!("destination ip {} is blocked ({:?})", dest, code),
                    Some(matched_include.clone()),
                    Some(host),
                    Vec::new(),
                );
            }
        }
    }

    // 6. Redirect re-validation.
    if let Some(chain) = &req.redirect_chain {
        for url in chain {
            if !redirect_in_scope(url, &req.scope_rules, dest_ip) {
                return reject(
                    ReasonCode::RedirectOutOfScope,
                    format!("redirect `{}` is out of scope", url),
                    Some(matched_include.clone()),
                    Some(host),
                    Vec::new(),
                );
            }
        }
    }

    // 7. Risk flags (non-fatal).
    let mut risk_flags: Vec<String> = Vec::new();
    if let Some(dest) = &req.dest_ip {
        if let Some(ips) = &req.resolved_ips {
            if !ips.is_empty() && !ips.iter().any(|x| x == dest) {
                risk_flags.push(DNS_REBINDING_FLAG.to_string());
            }
        }
    }

    // 8. Approved.
    make_decision(
        &request_id,
        scope_version,
        Decision::Approved,
        ReasonCode::InScope,
        format!("target `{}` is in scope", host),
        Some(matched_include),
        Some(host),
        risk_flags,
    )
}

/// A redirect URL is in scope when its host is included and not excluded.
fn redirect_in_scope(url: &str, scope_rules: &[ScopeRule], dest_ip: Option<&str>) -> bool {
    let host = match rules::extract_host(url) {
        Some(h) => h,
        None => return false,
    };
    for rule in scope_rules {
        if rule.action == RuleAction::Exclude
            && rules::rule_matches(rule, &host, Some(url), dest_ip)
        {
            return false;
        }
    }
    scope_rules.iter().any(|r| {
        r.action == RuleAction::Include && rules::rule_matches(r, &host, Some(url), dest_ip)
    })
}
