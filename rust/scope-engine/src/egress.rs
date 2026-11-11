//! Egress authorization — the final gate before an outbound connection.

use std::net::IpAddr;

use crate::engine;
use crate::ipguard;
use crate::model::{Decision, ReasonCode, ScopeDecision, ScopeRequest};

/// Authorize an egress connection.
///
/// Runs the full scope evaluation first; a rejection is returned unchanged. A
/// successful scope evaluation is followed by a mandatory `dest_ip` check and
/// a hard IP guard on that destination.
pub fn authorize_egress(req: &ScopeRequest) -> ScopeDecision {
    let decision = engine::evaluate(req);
    if decision.decision == Decision::Rejected {
        return decision;
    }

    let dest_ip = match req.dest_ip.as_deref() {
        Some(dest) if !dest.is_empty() => dest,
        _ => {
            return engine::make_rejection(
                req,
                ReasonCode::InvalidTarget,
                "dest_ip is required for egress authorization",
            )
        }
    };

    let ip: IpAddr = match dest_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return engine::make_rejection(
                req,
                ReasonCode::InvalidTarget,
                "dest_ip is required for egress authorization",
            )
        }
    };

    if let Some(code) = ipguard::classify(ip) {
        return engine::make_rejection(
            req,
            code,
            format!("egress to {} is blocked ({:?})", dest_ip, code),
        );
    }

    // Scope was approved and the destination IP is public — allowed.
    decision
}
