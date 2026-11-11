//! FFUF Online **Scope Enforcement Engine**.
//!
//! This crate is the single authority that decides whether a target is in scope
//! and whether an egress connection to a destination IP is permitted. It
//! implements the contract in `packages/schemas/scope-request.schema.json` and
//! `packages/schemas/scope-decision.schema.json`.
//!
//! The Go control plane and the Python tool adapters must **call** this engine
//! (via HTTP or the CLI) and must never re-implement scope rules, CIDR matching
//! or IP guards.

pub mod egress;
pub mod engine;
pub mod error;
pub mod ipguard;
pub mod model;
pub mod rules;
pub mod server;

pub use error::Error;
pub use model::{
    Authorization, Decision, PolicyProfile, RatePolicy, ReasonCode, RuleAction, RuleKind,
    ScopeDecision, ScopeRequest, ScopeRule, Target, TargetKind,
};
