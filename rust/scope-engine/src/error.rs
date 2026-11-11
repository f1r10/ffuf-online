//! Error type for normalization / validation failures.

use thiserror::Error;

use crate::model::ReasonCode;

/// Errors produced while normalizing a target or a rule value.
///
/// Every variant maps to [`ReasonCode::InvalidTarget`] in the decision contract.
#[derive(Debug, Error)]
pub enum Error {
    /// The target value could not be normalized/validated.
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    /// A scope rule value could not be interpreted.
    #[error("invalid rule: {0}")]
    InvalidRule(String),
}

impl Error {
    /// The decision reason code that corresponds to this error.
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Error::InvalidTarget(_) | Error::InvalidRule(_) => ReasonCode::InvalidTarget,
        }
    }

    /// Convenience constructor for an invalid-target error.
    pub fn invalid_target(msg: impl Into<String>) -> Self {
        Error::InvalidTarget(msg.into())
    }
}
