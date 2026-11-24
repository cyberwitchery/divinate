//! what every source of evidence provides.
//!
//! a [`Source`] reads one system: it finds a credential, reads a scope into
//! transcripts, and says what those transcripts mean. everything else, from
//! storing and verifying to the ledger and the process check, works on the
//! shared model and knows no source by name.

pub mod azure;
pub(crate) mod build;
pub mod github;
pub mod gitlab;
pub(crate) mod reading;
pub(crate) mod work;

use crate::error::{Error, Result};
use crate::model::Derived;
use crate::transcript::{HttpExchange, Transcript};

/// the period work items are read for: opened from `from` up to `until`, both
/// rfc 3339 in utc.
pub struct Period {
    pub from: String,
    pub until: String,
}

/// one request to a source, answered with the exchange to retain.
pub type Fetch<'a> = dyn FnMut(&str) -> Result<HttpExchange> + 'a;
/// the time of a reading, as rfc 3339.
pub type Clock<'a> = dyn Fn() -> Result<String> + 'a;

/// one system evidence is read from.
pub trait Source: Sync {
    /// the word before the colon in a scope and before the slash in a
    /// resource name, such as `github`.
    fn name(&self) -> &'static str;

    /// the scopes this source reads, for a message to the person asking.
    fn scopes(&self) -> &'static str;

    /// find the local credential for this source.
    ///
    /// # Errors
    ///
    /// returns an error when there is none.
    fn token(&self) -> Result<String>;

    /// a fetch function that reads this source with a credential.
    fn client(&self, token: &str) -> Box<Fetch<'static>>;

    /// read a scope. a reading that fails is a transcript that says how it
    /// ended, not an error.
    ///
    /// # Errors
    ///
    /// returns an error when the path is not one this source can read, or a
    /// transcript cannot be sealed.
    fn capture(
        &self,
        path: &str,
        period: &Period,
        clock: &Clock,
        fetch: &mut Fetch,
    ) -> Result<Vec<Transcript>>;

    /// say what the transcripts of one reading mean. this makes no requests.
    ///
    /// # Errors
    ///
    /// returns an error when the transcripts are not one whole reading.
    fn derive(&self, transcripts: &[Transcript]) -> Result<Derived>;
}

/// implement [`Source`] for a host module that has `HOST`, `token`, `client`,
/// `capture`, and `facts::derive`.
macro_rules! source {
    ($(#[$doc:meta])* $name:ident, $scopes:literal) => {
        $(#[$doc])*
        pub struct $name;

        impl $crate::source::Source for $name {
            fn name(&self) -> &'static str {
                HOST.name
            }

            fn scopes(&self) -> &'static str {
                $scopes
            }

            fn token(&self) -> $crate::error::Result<String> {
                token()
            }

            fn client(&self, token: &str) -> Box<$crate::source::Fetch<'static>> {
                client(token)
            }

            fn capture(
                &self,
                path: &str,
                period: &$crate::source::Period,
                clock: &$crate::source::Clock,
                fetch: &mut $crate::source::Fetch,
            ) -> $crate::error::Result<Vec<$crate::transcript::Transcript>> {
                capture(path, period, clock, fetch)
            }

            fn derive(
                &self,
                transcripts: &[$crate::transcript::Transcript],
            ) -> $crate::error::Result<$crate::model::Derived> {
                facts::derive(transcripts)
            }
        }
    };
}
pub(crate) use source;

/// every source this build reads.
#[must_use]
pub fn all() -> [&'static dyn Source; 3] {
    [
        &crate::source::github::Github,
        &crate::source::gitlab::Gitlab,
        &crate::source::azure::Azure,
    ]
}

/// the source a scope such as `github:organisation` names, and the path within it.
///
/// # Errors
///
/// returns an error naming the scopes that can be read.
pub fn for_scope(scope: &str) -> Result<(&'static dyn Source, &str)> {
    scope
        .split_once(':')
        .and_then(|(name, path)| {
            let source = all().into_iter().find(|source| source.name() == name)?;
            Some((source, path))
        })
        .ok_or_else(|| {
            let known = all().map(Source::scopes).join(", ");
            Error::Invalid(format!("cannot read {scope:?}; a scope is one of: {known}"))
        })
}

/// the source that made a set of transcripts.
///
/// # Errors
///
/// returns an error when the transcripts name no source, or more than one.
pub fn for_transcripts(transcripts: &[Transcript]) -> Result<&'static dyn Source> {
    let mut found = all().into_iter().filter(|source| {
        let prefix = format!("{}/", source.name());
        transcripts
            .iter()
            .any(|transcript| transcript.contents.resource.starts_with(&prefix))
    });
    match (found.next(), found.next()) {
        (Some(source), None) => Ok(source),
        (Some(_), Some(_)) => Err(Error::Invalid(
            "a collection reads one source, but its transcripts name two".into(),
        )),
        (None, _) => Err(Error::Invalid(
            "these transcripts are from no source this build reads".into(),
        )),
    }
}
