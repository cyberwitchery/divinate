//! building the record of scopes, the same way for every source.
//!
//! a source reads its own organisations, repositories, and branches. the
//! helpers here turn what it found into entities and statements, and read
//! retained bodies, so every source produces the same shapes.

use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::model::{uid, Class, Entity, Interval, Population, Reading, Statement};
use crate::parse_time;
use crate::transcript::Transcript;

/// how a source is named in the record.
pub(crate) struct Host {
    /// the first part of every entity id, such as `github.com`.
    pub id: &'static str,
    /// the first part of every display name, such as `github`.
    pub name: &'static str,
}

impl Host {
    /// the id of one of this host's entities.
    pub fn uid(&self, kind: &str, id: &str) -> String {
        uid(self.id, kind, id)
    }

    /// somewhere things live: an organisation, a repository, a branch.
    pub fn scope(
        &self,
        kind: &str,
        native_kind: &str,
        id: &str,
        name: impl Into<String>,
        parent: Option<String>,
    ) -> Entity {
        Entity {
            uid: self.uid(kind, id),
            class: Class::Scope,
            kind: kind.into(),
            native_kind: native_kind.into(),
            name: name.into(),
            parent,
            occurred_at: None,
        }
    }

    /// a scope the source would not identify: it has a name and no id.
    pub fn unresolved(&self, kind: &str, native_kind: &str, name: &str) -> Entity {
        let path = name.split_once(':').map_or(name, |(_, path)| path);
        self.scope(kind, native_kind, &format!("unresolved:{path}"), name, None)
    }
}

/// what the record says about one aspect of one entity.
pub(crate) fn state(
    about: &str,
    aspect: &str,
    reading: Reading,
    from: &[&Transcript],
) -> Statement {
    Statement {
        about: about.into(),
        aspect: aspect.into(),
        population: None,
        reading,
        note: None,
        transcripts: from
            .iter()
            .map(|transcript| transcript.id.clone())
            .collect(),
    }
}

/// the entities of a kind under an entity, as its listings reported them.
/// the population is a gap when one of the listings did not complete.
pub(crate) fn population(
    about: &str,
    aspect: &str,
    of: &str,
    interval: Option<Interval>,
    members: &[String],
    listings: &[&Transcript],
) -> Result<Statement> {
    let unread = listings
        .iter()
        .find_map(|listing| listing.contents.termination.gap());
    let reading = if let Some(reason) = unread {
        Reading::gap(reason)
    } else {
        let mut members = members.to_vec();
        members.sort();
        Reading::recorded(json!({ "members": members }))?
    };
    let mut statement = state(about, aspect, reading, listings);
    statement.population = Some(Population {
        of: of.into(),
        interval,
    });
    Ok(statement)
}

/// the period a listing was read for, from its `from` and `until` parameters.
pub(crate) fn interval(listing: &Transcript) -> Option<Interval> {
    Some(Interval {
        from: listing.parameter("from")?.into(),
        until: listing.parameter("until")?.into(),
    })
}

/// the period a listing was read for, to test times against. times are
/// compared as times: sources write them with different precision.
pub(crate) struct Span(Option<(OffsetDateTime, OffsetDateTime)>);

impl Span {
    pub fn of(listing: &Transcript) -> Self {
        let bound = |name| parse_time(listing.parameter(name)?).ok();
        Self(bound("from").zip(bound("until")))
    }

    /// whether a time the source wrote lies in the period. a value that is
    /// not a time does not.
    pub fn holds(&self, at: &Value) -> bool {
        let at = at.as_str().and_then(|at| parse_time(at).ok());
        matches!((self.0, at), (Some((from, until)), Some(at)) if from <= at && at < until)
    }
}

/// the first transcript of a resource.
pub(crate) fn find<'a>(transcripts: &'a [Transcript], resource: &str) -> Option<&'a Transcript> {
    transcripts
        .iter()
        .find(|transcript| transcript.contents.resource == resource)
}

/// every transcript of a resource.
pub(crate) fn all<'a>(
    transcripts: &'a [Transcript],
    resource: &'a str,
) -> impl Iterator<Item = &'a Transcript> {
    transcripts
        .iter()
        .filter(move |transcript| transcript.contents.resource == resource)
}

/// the items of every page that holds a list. a page that holds something
/// else adds nothing.
pub(crate) fn items(transcript: &Transcript) -> Vec<Value> {
    transcript
        .bodies()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .filter_map(|page| match page {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .flatten()
        .collect()
}

/// the items of every page, which must each hold a list.
///
/// # Errors
///
/// returns an error when a page holds something else.
pub(crate) fn list(transcript: &Transcript) -> Result<Vec<Value>> {
    let mut items = Vec::new();
    for body in transcript.bodies() {
        match parse(transcript, body)? {
            Value::Array(page) => items.extend(page),
            _ => return Err(not_expected(transcript, "a list")),
        }
    }
    Ok(items)
}

/// the one object a transcript holds.
///
/// # Errors
///
/// returns an error when there is no body, or it is not json.
pub(crate) fn single(transcript: &Transcript) -> Result<Value> {
    let body = transcript
        .bodies()
        .next()
        .ok_or_else(|| not_expected(transcript, "a response body"))?;
    parse(transcript, body)
}

/// the one object a transcript holds, if it holds one.
pub(crate) fn peek(transcript: &Transcript) -> Option<Value> {
    serde_json::from_str(transcript.bodies().next()?).ok()
}

fn parse(transcript: &Transcript, body: &str) -> Result<Value> {
    serde_json::from_str(body).map_err(|_| not_expected(transcript, "json"))
}

pub(crate) fn not_expected(transcript: &Transcript, expected: &str) -> Error {
    Error::Invalid(format!(
        "transcript {} ({}) does not hold {expected}",
        transcript.id, transcript.contents.resource
    ))
}
