//! Domain types mirroring `packages/schemas/scope-request.schema.json` and
//! `packages/schemas/scope-decision.schema.json`.
//!
//! Field names are `snake_case` and every struct that the schemas declare with
//! `additionalProperties: false` uses `#[serde(deny_unknown_fields)]` so an
//! unexpected field is a hard deserialization error rather than a silent pass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Kind of a scope rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Matches the apex and any sub-domain.
    Domain,
    /// Matches sub-domains only (never the apex).
    WildcardDomain,
    /// Exact, case-insensitive host match.
    Hostname,
    /// Exact IP address match.
    Ip,
    /// IP contained in a CIDR network.
    Cidr,
    /// Normalized full URL prefix match.
    UrlPrefix,
}

/// Whether a rule includes or excludes matching targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Adds the target to scope.
    Include,
    /// Removes the target from scope (always wins).
    Exclude,
}

/// A single scope rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRule {
    /// Stable rule identifier, echoed back as `matched_rule_id`.
    pub id: String,
    /// What the value is matched against.
    pub kind: RuleKind,
    /// The pattern value.
    pub value: String,
    /// Include or exclude.
    pub action: RuleAction,
}

/// Kind of the requested target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// A domain (apex + sub-domains).
    Domain,
    /// A wildcard domain.
    WildcardDomain,
    /// An exact host.
    Hostname,
    /// An IP address.
    Ip,
    /// A CIDR network.
    Cidr,
    /// A full URL.
    Url,
    /// A URL prefix.
    UrlPrefix,
}

/// The target under evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// What kind of value this target carries.
    pub kind: TargetKind,
    /// The raw target value (host, IP, CIDR or URL).
    pub value: String,
    /// Optional explicit scheme (wins over a scheme parsed from `value`).
    #[serde(default)]
    pub scheme: Option<String>,
    /// Optional explicit host (wins over a host parsed from `value`).
    #[serde(default)]
    pub host: Option<String>,
    /// Optional explicit port (wins over a port parsed from `value`).
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional explicit path (wins over a path parsed from `value`).
    #[serde(default)]
    pub path: Option<String>,
}

/// The active policy profile, which gates how aggressive a run may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    /// Passive only — no rate policy required.
    Passive,
    /// Low-impact discovery — requires a rate policy.
    LowImpactDiscovery,
    /// Authorized vulnerability testing — requires a rate policy with a
    /// concurrency ceiling and an authorization expiry.
    AuthorizedVulnerabilityTesting,
}

/// Rate limiting policy for a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatePolicy {
    /// Maximum requests per second.
    #[serde(default)]
    pub max_rps: Option<u32>,
    /// Maximum in-flight concurrency.
    #[serde(default)]
    pub max_concurrency: Option<u32>,
}

/// Authorization grant for the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// Whether the operator is authorized at all.
    #[serde(default)]
    pub authorized: bool,
    /// Optional expiry instant.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Input contract for `POST /v1/scope/decide` and `POST /v1/egress/authorize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequest {
    /// Caller-supplied request id; a UUID v4 is generated when absent.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Tenant that owns the run.
    pub tenant_id: String,
    /// Project the run belongs to.
    pub project_id: String,
    /// Version of the scope snapshot.
    #[serde(default)]
    pub scope_version: Option<u32>,
    /// Active policy profile.
    pub policy_profile: PolicyProfile,
    /// The target being evaluated.
    pub target: Target,
    /// DNS-resolved IPs for the target.
    #[serde(default)]
    pub resolved_ips: Option<Vec<String>>,
    /// HTTP redirect chain, re-validated against scope.
    #[serde(default)]
    pub redirect_chain: Option<Vec<String>>,
    /// The actual destination IP an egress connection would use.
    #[serde(default)]
    pub dest_ip: Option<String>,
    /// The scope rules in force.
    pub scope_rules: Vec<ScopeRule>,
    /// Rate policy (required by some profiles).
    #[serde(default)]
    pub rate_policy: Option<RatePolicy>,
    /// Authorization grant.
    #[serde(default)]
    pub authorization: Option<Authorization>,
    /// Evaluation instant override (mostly for tests); defaults to now.
    #[serde(default)]
    pub now: Option<DateTime<Utc>>,
}

/// The verdict, serialized as `"approved"` / `"rejected"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The target/egress is permitted.
    Approved,
    /// The target/egress is denied.
    Rejected,
}

/// Machine-readable reason code, serialized as `SCREAMING_SNAKE_CASE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// Target is in scope and permitted.
    InScope,
    /// Target matched no include rule.
    OutOfScope,
    /// Target matched an exclude rule.
    Excluded,
    /// No scope rules were supplied.
    NoScopeRules,
    /// Target could not be normalized/validated.
    InvalidTarget,
    /// Destination is a private address.
    PrivateIpBlocked,
    /// Destination is a loopback address.
    LoopbackIpBlocked,
    /// Destination is a link-local address.
    LinkLocalIpBlocked,
    /// Destination is a cloud metadata endpoint.
    MetadataIpBlocked,
    /// Destination is reserved / never-routable.
    ReservedIpBlocked,
    /// The authorization grant has expired.
    AuthorizationExpired,
    /// Authorization is missing or not granted.
    AuthorizationMissing,
    /// The chosen profile is not permitted for this request.
    ProfileNotPermitted,
    /// A redirect left the authorized scope.
    RedirectOutOfScope,
    /// The profile requires a rate policy that was not supplied.
    RatePolicyMissing,
    /// The destination IP is not among the DNS-resolved IPs.
    DnsRebindingSuspected,
}

/// Output contract returned to every caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDecision {
    /// Echoes the request id (or a generated UUID v4).
    pub request_id: String,
    /// The verdict.
    pub decision: Decision,
    /// Machine-readable reason code.
    pub reason_code: ReasonCode,
    /// Human-readable explanation.
    pub reason: String,
    /// The include/exclude rule that decided the outcome, if any.
    pub matched_rule_id: Option<String>,
    /// The normalized host of the target, if determinable.
    pub normalized_target: Option<String>,
    /// Non-fatal risk flags.
    pub risk_flags: Vec<String>,
    /// Echo of the scope version.
    pub scope_version: u32,
    /// Evaluation instant (RFC3339).
    pub evaluated_at: DateTime<Utc>,
}
