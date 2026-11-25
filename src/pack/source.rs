//! a pack as a source of evidence.
//!
//! a source pack reads its system itself and hands back what it was sent,
//! request by request. those responses are sealed as transcripts and kept
//! like those of any other source. what they mean is asked of the pack in a
//! second request that is given the transcripts and nothing else, so it can
//! be asked again, offline, by whoever verifies the record.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{describe, Packs, PROTOCOL};
use crate::error::{Error, Result};
use crate::hex_digest;
use crate::model::{Derived, Entity, Population, Reading, Relation, Statement};
use crate::source::Period;
use crate::transcript::{
    seal, HttpExchange, HttpRequest, HttpResponse, Termination, Transcript, TranscriptContents,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the pack that read and derived a collection.
pub struct Stamp {
    pub name: String,
    pub version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// one reading, as a pack hands it back.
struct Read {
    resource: String,
    subject: String,
    #[serde(default)]
    parameters: BTreeMap<String, String>,
    captured_at: String,
    exchanges: Vec<Exchanged>,
    termination: Termination,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchanged {
    request: HttpRequest,
    response: Answered,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answered {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// what a pack says its transcripts mean.
struct Told {
    entities: Vec<Entity>,
    statements: Vec<Stated>,
    #[serde(default)]
    relations: Vec<Relation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// one statement, as a pack writes it: a value or a gap.
struct Stated {
    about: String,
    aspect: String,
    #[serde(default)]
    population: Option<Population>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    gap: Option<String>,
    #[serde(default)]
    note: Option<String>,
    transcripts: Vec<String>,
}

/// let a pack read a scope, and keep what it read.
///
/// # Errors
///
/// returns an error when the pack is no source, cannot be run, hands back
/// something that is not a reading, or a reading holds a secret the pack was
/// given.
pub fn collect(
    packs: &dyn Packs,
    pack: &str,
    path: &str,
    period: &Period,
) -> Result<(Vec<Transcript>, Stamp)> {
    let described = describe(packs, pack)?;
    if described.collects.is_none() {
        return Err(Error::Pack(format!(
            "the pack {pack:?} is no source: it has checks and process definitions only"
        )));
    }
    let answer = packs.call(
        pack,
        &json!({
            "protocol": PROTOCOL,
            "request": "collect",
            "path": path,
            "period": { "from": period.from, "until": period.until },
        }),
    )?;
    let bad = |what: String| Error::Pack(format!("the pack {pack:?} {what}"));
    let readings: Vec<Read> = serde_json::from_value(answer["readings"].clone())
        .map_err(|error| bad(format!("handed back readings that cannot be kept: {error}")))?;
    let secrets = packs.secrets(pack);
    let prefix = format!("{pack}/");
    let mut transcripts = Vec::new();
    for reading in readings {
        if !reading.resource.starts_with(&prefix) {
            return Err(bad(format!(
                "names a resource {:?} that does not start with {prefix:?}",
                reading.resource
            )));
        }
        crate::parse_time(&reading.captured_at)?;
        let exchanges = reading
            .exchanges
            .into_iter()
            .map(|exchange| HttpExchange {
                request: exchange.request,
                response: HttpResponse {
                    status: exchange.response.status,
                    headers: exchange.response.headers,
                    body_sha256: hex_digest(exchange.response.body.as_bytes()),
                    body: exchange.response.body,
                },
            })
            .collect::<Vec<_>>();
        let contents = TranscriptContents {
            resource: reading.resource,
            subject: reading.subject,
            parameters: reading.parameters,
            captured_at: reading.captured_at,
            exchanges,
            termination: reading.termination,
        };
        // a credential the pack was given must not be kept, wherever the
        // pack put it.
        let text = serde_json::to_string(&contents).map_err(Error::Serialize)?;
        if secrets.iter().any(|secret| text.contains(secret.as_str())) {
            return Err(bad(format!(
                "handed back a reading of {} that repeats a credential it was given; nothing was kept",
                contents.resource
            )));
        }
        transcripts.push(seal(contents)?);
    }
    Ok((
        transcripts,
        Stamp {
            name: described.name,
            version: described.version,
        },
    ))
}

/// ask a pack what its transcripts mean.
///
/// every entity must carry an id in the pack's own namespace, and every
/// statement must be about one of them and cite transcripts it was given.
///
/// # Errors
///
/// returns an error when the pack cannot be run or says something that
/// cannot be part of a record.
pub fn derive(packs: &dyn Packs, pack: &str, transcripts: &[Transcript]) -> Result<Derived> {
    let answer = packs.call(
        pack,
        &json!({
            "protocol": PROTOCOL,
            "request": "derive",
            "transcripts": transcripts,
        }),
    )?;
    let bad = |what: String| Error::Pack(format!("the pack {pack:?} {what}"));
    let told: Told = serde_json::from_value(answer)
        .map_err(|error| bad(format!("derived something that is not a record: {error}")))?;
    let prefix = format!("{pack}/");
    if let Some(entity) = told
        .entities
        .iter()
        .find(|entity| !entity.uid.starts_with(&prefix))
    {
        return Err(bad(format!(
            "names an entity {:?} outside its own ids, which start with {prefix:?}",
            entity.uid
        )));
    }
    let known = told
        .entities
        .iter()
        .map(|entity| entity.uid.as_str())
        .collect::<BTreeSet<_>>();
    let read = transcripts
        .iter()
        .map(|transcript| transcript.id.as_str())
        .collect::<BTreeSet<_>>();
    let cited = |transcripts: &[String]| transcripts.iter().all(|id| read.contains(id.as_str()));
    let mut statements = Vec::new();
    for stated in told.statements {
        if !known.contains(stated.about.as_str()) {
            return Err(bad(format!(
                "makes a statement about {:?}, which it does not name as an entity",
                stated.about
            )));
        }
        if !cited(&stated.transcripts) {
            return Err(bad(format!(
                "cites a transcript for {:?} of {:?} that it was not given",
                stated.aspect, stated.about
            )));
        }
        let reading = match (stated.value, stated.gap) {
            (Some(value), None) => Reading::recorded(value)?,
            (None, Some(reason)) => Reading::gap(reason),
            _ => {
                return Err(bad(format!(
                    "gives {:?} of {:?} neither or both of a value and a gap",
                    stated.aspect, stated.about
                )))
            }
        };
        statements.push(Statement {
            about: stated.about,
            aspect: stated.aspect,
            population: stated.population,
            reading,
            note: stated.note,
            transcripts: stated.transcripts,
        });
    }
    if let Some(relation) = told
        .relations
        .iter()
        .find(|relation| !cited(&relation.transcripts))
    {
        return Err(bad(format!(
            "cites a transcript for a link from {:?} that it was not given",
            relation.from
        )));
    }
    Ok(Derived {
        entities: told.entities,
        statements,
        relations: told.relations,
    }
    .sorted())
}
