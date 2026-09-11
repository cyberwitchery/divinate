//! shared errors.
//!
//! [`Error::Provenance`] reports an invalid or unresolved evidence chain.
//! unsupported claims use [`crate::assertions::Outcome`].

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
/// errors from reading, verifying, and deriving evidence.
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: invalid json: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{path}: source is not utf-8: {source}")]
    Utf8 {
        path: PathBuf,
        source: std::string::FromUtf8Error,
    },
    #[error("invalid timestamp {value:?}: {source}")]
    Timestamp {
        value: String,
        source: time::error::Parse,
    },
    #[error("{0}")]
    Invalid(String),
    #[error("collection failed: {0}")]
    Collection(String),
    #[error("provenance invalid: {0}")]
    Provenance(String),
    #[error("cannot serialize json: {0}")]
    Serialize(serde_json::Error),
}

/// the crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
