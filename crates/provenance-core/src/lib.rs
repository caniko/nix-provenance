//! Shared plumbing for `nix-provenance` reconcilers.
//!
//! Licensed `MIT OR Apache-2.0` so it can be consumed by BOTH the AGPL
//! `immich-provision` crate and the `MIT OR Apache-2.0` `rauthy-provision`
//! crate (permissive code can be linked by either; the reverse is not true).
//! Keep this crate generic — HTTP / secret / serde / set / reconcile primitives
//! only, never service-specific request-building or reconcile bodies. Any helper
//! that originated in the AGPL immich crate is clean-reimplemented here, never
//! copied, so no AGPL source text is relicensed.

#![warn(missing_docs)]

use std::io;

use reqwest::StatusCode;

/// Error returned by shared provisioning helpers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An input failed validation.
    #[error("{message}")]
    InvalidInput {
        /// Human-readable validation failure.
        message: String,
    },
    /// An operating-system operation failed.
    #[error("{context}: {source}")]
    Io {
        /// Operation being performed.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// An HTTP client operation failed.
    #[error("{context}: {source}")]
    Http {
        /// Operation being performed.
        context: String,
        /// Underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },
    /// An HTTP request returned a non-success status.
    #[error("request failed with HTTP {status}")]
    HttpStatus {
        /// Returned status.
        status: StatusCode,
    },
}

impl Error {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn http(context: impl Into<String>, source: reqwest::Error) -> Self {
        Self::Http {
            context: context.into(),
            source,
        }
    }
}

/// Result type returned by shared provisioning helpers.
pub type Result<T> = std::result::Result<T, Error>;

pub mod http;
pub mod password;
pub mod reconcile;
pub mod secret;
pub mod serde_ext;
pub mod setops;
pub mod validate;
