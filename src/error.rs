//! shared errors.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
/// errors from collecting, storing, and verifying the record.
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
    #[error("{path}: invalid yaml: {source}")]
    Yaml {
        path: PathBuf,
        source: Box<serde_saphyr::Error>,
    },
    #[error("{0}")]
    Invalid(String),
    #[error("collection failed: {0}")]
    Collection(String),
    #[error("{0}")]
    Pack(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("cannot serialize json: {0}")]
    Serialize(serde_json::Error),
}

/// the crate's result type.
pub type Result<T> = std::result::Result<T, Error>;
