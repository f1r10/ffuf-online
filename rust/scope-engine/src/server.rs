//! HTTP surface (axum).
//!
//! Routes:
//! - `GET  /healthz`
//! - `GET  /v1/version`
//! - `POST /v1/scope/decide`
//! - `POST /v1/egress/authorize`
//!
//! Malformed JSON yields HTTP 400 with `{"error":"invalid_request","detail":..}`.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::model::ScopeRequest;
use crate::{egress, engine};

/// Maximum accepted request body size (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Build the router with all routes and the body limit applied.
pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/version", get(version))
        .route("/v1/scope/decide", post(decide))
        .route("/v1/egress/authorize", post(egress_authorize))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

async fn healthz() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "scope-engine",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn version() -> impl IntoResponse {
    Json(json!({
        "name": "scope-engine",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

fn bad_request(err: serde_json::Error) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_request",
            "detail": err.to_string(),
        })),
    )
        .into_response()
}

async fn decide(body: Bytes) -> Response {
    match serde_json::from_slice::<ScopeRequest>(&body) {
        Ok(req) => Json(engine::evaluate(&req)).into_response(),
        Err(err) => bad_request(err),
    }
}

async fn egress_authorize(body: Bytes) -> Response {
    match serde_json::from_slice::<ScopeRequest>(&body) {
        Ok(req) => Json(egress::authorize_egress(&req)).into_response(),
        Err(err) => bad_request(err),
    }
}

/// Bind to `addr` and serve until terminated.
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("scope-engine listening on http://{}", addr);
    axum::serve(listener, app()).await?;
    Ok(())
}
