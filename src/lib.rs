//! divinate keeps a dated record of how software is developed and released.
//!
//! a [`record::Collection`] is one reading of a scope, such as a github
//! organisation. it holds the [`model::Entity`] values the reading met and one
//! [`model::Statement`] per entity and aspect: either the recorded value, or
//! the reason it could not be read. everything is derived from retained
//! [`transcript::Transcript`] values, the exact responses the source returned,
//! so [`verify::verify`] can recompute the whole record offline.

pub mod error;
pub mod facts;
pub mod ledger;
pub mod model;
pub mod pack;
pub mod process;
pub mod record;
pub mod source;
pub mod transcript;
pub mod verify;

use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// return a lowercase sha-256 digest.
#[must_use]
pub fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// derive a content-addressed id from a serializable value.
///
/// # Errors
///
/// returns an error when the value cannot be serialized.
pub fn content_id<T: serde::Serialize>(prefix: &str, value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(Error::Serialize)?;
    Ok(format!("{prefix}_{}", &hex_digest(&bytes)[..20]))
}

/// the current time in utc as rfc 3339, to the second.
///
/// # Errors
///
/// returns an error when the time cannot be formatted.
pub fn timestamp() -> Result<String> {
    format_time(time::OffsetDateTime::now_utc())
}

/// parse an rfc 3339 time.
///
/// # Errors
///
/// returns an error when the value is not rfc 3339.
pub fn parse_time(value: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("{value:?} is not an rfc 3339 time: {error}")))
}

/// write a time in utc as rfc 3339, to the second, as the sources do.
///
/// # Errors
///
/// returns an error when the time cannot be formatted.
pub fn format_time(value: time::OffsetDateTime) -> Result<String> {
    value
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|error| Error::Invalid(format!("cannot truncate timestamp: {error}")))?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format timestamp: {error}")))
}

/// read and parse a json file.
///
/// # Errors
///
/// returns an error when the file cannot be read or parsed.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })
}

/// write a value as pretty json, through a temporary file in the same directory.
///
/// # Errors
///
/// returns an error when serialization or writing fails.
pub fn write_json<T: serde::Serialize>(value: &T, path: &Path) -> Result<()> {
    let mut rendered = serde_json::to_vec_pretty(value).map_err(Error::Serialize)?;
    rendered.push(b'\n');
    let temporary = path.with_extension("json.tmp");
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    fs::write(&temporary, rendered).map_err(io)?;
    fs::rename(&temporary, path).map_err(io)
}
