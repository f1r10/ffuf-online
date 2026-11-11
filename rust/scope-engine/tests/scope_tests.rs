//! Integration tests for the scope evaluation pipeline.

use chrono::{Duration, Utc};

use scope_engine::egress::authorize_egress;
use scope_engine::engine::evaluate;
use scope_engine::model::{
    Authorization, Decision, PolicyProfile, RatePolicy, ReasonCode, RuleAction, RuleKind,
    ScopeRequest, ScopeRule, Target, TargetKind,
};

// ---------------------------------------------------------------- helpers

fn target(kind: TargetKind, value: &str) -> Target {
    Target {
        kind,
        value: value.to_string(),
        scheme: None,
        host: None,
        port: None,
        path: None,
    }
}

fn rule(id: &str, kind: RuleKind, value: &str, action: RuleAction) -> ScopeRule {
    ScopeRule {
        id: id.to_string(),
        kind,
        value: value.to_string(),
        action,
    }
}

fn include(id: &str, kind: RuleKind, value: &str) -> ScopeRule {
    rule(id, kind, value, RuleAction::Include)
}

fn exclude(id: &str, kind: RuleKind, value: &str) -> ScopeRule {
    rule(id, kind, value, RuleAction::Exclude)
}

fn auth_ok() -> Authorization {
    Authorization {
        authorized: true,
        expires_at: Some(Utc::now() + Duration::days(1)),
    }
}

fn base(profile: PolicyProfile, target: Target, scope_rules: Vec<ScopeRule>) -> ScopeRequest {
    ScopeRequest {
        request_id: Some("req-test".to_string()),
        tenant_id: "tenant-1".to_string(),
        project_id: "project-1".to_string(),
        scope_version: Some(7),
        policy_profile: profile,
        target,
        resolved_ips: None,
        redirect_chain: None,
        dest_ip: None,
        scope_rules,
        rate_policy: None,
        authorization: Some(auth_ok()),
        now: None,
    }
}

// ---------------------------------------------------------------- scope rules

#[test]
fn approve_in_scope_subdomain() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
    assert_eq!(d.matched_rule_id.as_deref(), Some("r1"));
    assert_eq!(d.normalized_target.as_deref(), Some("app.example.com"));
}

#[test]
fn approve_in_scope_with_domain_rule_matching_apex_and_subdomains() {
    for host in ["example.com", "a.b.example.com"] {
        let req = base(
            PolicyProfile::Passive,
            target(TargetKind::Domain, host),
            vec![include("r1", RuleKind::Domain, "example.com")],
        );
        let d = evaluate(&req);
        assert_eq!(d.decision, Decision::Approved, "host {host} should be approved");
        assert_eq!(d.reason_code, ReasonCode::InScope);
    }
}

#[test]
fn reject_out_of_scope() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "other.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::OutOfScope);
    assert_eq!(d.matched_rule_id, None);
}

#[test]
fn reject_excluded_subdomain_beats_include() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "bad.example.com"),
        vec![
            include("inc", RuleKind::Domain, "example.com"),
            exclude("exc", RuleKind::Domain, "bad.example.com"),
        ],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::Excluded);
    assert_eq!(d.matched_rule_id.as_deref(), Some("exc"));
}

#[test]
fn wildcard_domain_does_not_match_apex() {
    let apex = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "example.com"),
        vec![include("w", RuleKind::WildcardDomain, "*.example.com")],
    );
    let d = evaluate(&apex);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::OutOfScope);

    let sub = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "a.example.com"),
        vec![include("w", RuleKind::WildcardDomain, "*.example.com")],
    );
    let d = evaluate(&sub);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
}

#[test]
fn hostname_rule_is_exact_match_only() {
    let exact = base(
        PolicyProfile::Passive,
        target(TargetKind::Hostname, "host.example.com"),
        vec![include("h", RuleKind::Hostname, "host.example.com")],
    );
    assert_eq!(evaluate(&exact).decision, Decision::Approved);

    let sub = base(
        PolicyProfile::Passive,
        target(TargetKind::Hostname, "sub.host.example.com"),
        vec![include("h", RuleKind::Hostname, "host.example.com")],
    );
    let d = evaluate(&sub);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::OutOfScope);
}

#[test]
fn subdomain_match_respects_label_boundary() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "notexample.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::OutOfScope);
}

#[test]
fn url_prefix_rule_matches() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Url, "https://API.Example.com/api/v1/users"),
        vec![include("u", RuleKind::UrlPrefix, "https://api.example.com/api")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
    assert_eq!(d.matched_rule_id.as_deref(), Some("u"));
}

#[test]
fn cidr_rule_matches_ip_target() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Ip, "203.0.113.10"),
        vec![include("c", RuleKind::Cidr, "203.0.113.0/24")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
}

// ---------------------------------------------------------------- IP guards

fn ip_case(resolved: &str) -> ReasonCode {
    let mut req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.resolved_ips = Some(vec![resolved.to_string()]);
    evaluate(&req).reason_code
}

#[test]
fn block_private_ip() {
    assert_eq!(ip_case("10.0.0.1"), ReasonCode::PrivateIpBlocked);
}

#[test]
fn block_cloud_metadata_ip() {
    assert_eq!(ip_case("169.254.169.254"), ReasonCode::MetadataIpBlocked);
}

#[test]
fn block_loopback_ip() {
    assert_eq!(ip_case("127.0.0.1"), ReasonCode::LoopbackIpBlocked);
}

#[test]
fn block_link_local_ip() {
    assert_eq!(ip_case("169.254.10.10"), ReasonCode::LinkLocalIpBlocked);
}

// ---------------------------------------------------------------- authorization

#[test]
fn reject_expired_authorization() {
    let mut req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.authorization = Some(Authorization {
        authorized: true,
        expires_at: Some(Utc::now() - Duration::days(1)),
    });
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::AuthorizationExpired);
}

#[test]
fn reject_missing_authorization() {
    let mut req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.authorization = None;
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::AuthorizationMissing);
}

// ---------------------------------------------------------------- profile gating

#[test]
fn low_impact_requires_rate_policy() {
    let req = base(
        PolicyProfile::LowImpactDiscovery,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::RatePolicyMissing);
}

#[test]
fn authorized_testing_requires_expiry_and_concurrency() {
    // Rate policy present but no max_concurrency -> not permitted.
    let mut req = base(
        PolicyProfile::AuthorizedVulnerabilityTesting,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.rate_policy = Some(RatePolicy {
        max_rps: Some(10),
        max_concurrency: None,
    });
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::ProfileNotPermitted);

    // Both present -> permitted.
    let mut ok = base(
        PolicyProfile::AuthorizedVulnerabilityTesting,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    ok.rate_policy = Some(RatePolicy {
        max_rps: Some(10),
        max_concurrency: Some(4),
    });
    assert_eq!(evaluate(&ok).decision, Decision::Approved);
}

// ---------------------------------------------------------------- redirects

#[test]
fn reject_redirect_to_out_of_scope_host() {
    let mut req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.redirect_chain = Some(vec!["https://evil.com/login".to_string()]);
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::RedirectOutOfScope);
}

#[test]
fn passive_profile_approved_with_no_rate_policy() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    assert!(req.rate_policy.is_none());
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
}

// ---------------------------------------------------------------- risk flags

#[test]
fn risk_flag_dns_rebinding_when_dest_ip_not_in_resolved() {
    let mut req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    req.resolved_ips = Some(vec!["93.184.216.34".to_string()]);
    req.dest_ip = Some("1.1.1.1".to_string());
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(d.reason_code, ReasonCode::InScope);
    assert!(d.risk_flags.contains(&"dns_rebinding_suspected".to_string()));
}

// ---------------------------------------------------------------- egress

#[test]
fn egress_requires_dest_ip() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = authorize_egress(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::InvalidTarget);

    // With a public destination IP it is approved.
    let mut ok = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    ok.dest_ip = Some("93.184.216.34".to_string());
    assert_eq!(authorize_egress(&ok).decision, Decision::Approved);

    // With a private destination IP it is blocked by the IP guard.
    let mut blocked = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    blocked.dest_ip = Some("10.0.0.5".to_string());
    let d = authorize_egress(&blocked);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::PrivateIpBlocked);
}

// ---------------------------------------------------------------- misc

#[test]
fn empty_scope_rules_rejected() {
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "app.example.com"),
        vec![],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::NoScopeRules);
}

#[test]
fn invalid_target_rejected() {
    // Not a valid IP literal.
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Ip, "999.999.999.999"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::InvalidTarget);

    // Forbidden characters in the value.
    let req = base(
        PolicyProfile::Passive,
        target(TargetKind::Domain, "example.com;rm -rf /"),
        vec![include("r1", RuleKind::Domain, "example.com")],
    );
    let d = evaluate(&req);
    assert_eq!(d.decision, Decision::Rejected);
    assert_eq!(d.reason_code, ReasonCode::InvalidTarget);
}

#[test]
fn unknown_json_field_rejected() {
    let json = r#"{
        "tenant_id": "t1",
        "project_id": "p1",
        "policy_profile": "passive",
        "target": { "kind": "domain", "value": "example.com" },
        "scope_rules": [],
        "totally_unknown_field": true
    }"#;
    let res: Result<ScopeRequest, _> = serde_json::from_str(json);
    assert!(res.is_err(), "unknown top-level field must be rejected");

    // Unknown field inside target must also be rejected.
    let json_target = r#"{
        "tenant_id": "t1",
        "project_id": "p1",
        "policy_profile": "passive",
        "target": { "kind": "domain", "value": "example.com", "bogus": 1 },
        "scope_rules": []
    }"#;
    let res: Result<ScopeRequest, _> = serde_json::from_str(json_target);
    assert!(res.is_err(), "unknown target field must be rejected");
}

#[test]
fn decision_serializes_reason_codes_in_screaming_snake_case() {
    let payload = serde_json::to_string(&ReasonCode::MetadataIpBlocked).unwrap();
    assert_eq!(payload, "\"METADATA_IP_BLOCKED\"");
    let payload = serde_json::to_string(&ReasonCode::DnsRebindingSuspected).unwrap();
    assert_eq!(payload, "\"DNS_REBINDING_SUSPECTED\"");
    let payload = serde_json::to_string(&Decision::Approved).unwrap();
    assert_eq!(payload, "\"approved\"");
}
