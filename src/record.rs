//! collections and where they are kept.
//!
//! a [`Collection`] is one reading of a scope: one column of the ledger. the
//! state directory holds `collections/<id>.json` and `transcripts/<id>.json`.
//! both are addressed by content and are never rewritten.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::facts;
use crate::model::{Derived, Reading, Statement};
use crate::pack::source::Stamp;
use crate::transcript::Transcript;
use crate::{content_id, read_json, write_json};

/// the version of the rules that turn transcripts into statements.
pub const DERIVATION: &str = "9";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one reading of a scope, addressed by the digest of its contents.
pub struct Collection {
    pub id: String,
    pub contents: CollectionContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// what was read, when, and what it said.
pub struct CollectionContents {
    /// the tool that made the reading, such as `divinate/0.0.1`.
    pub tool: String,
    pub derivation: String,
    /// what was read, such as `github:organisation`.
    pub scope: String,
    pub started_at: String,
    pub completed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// the pack that read and derived this, when a pack did.
    pub pack: Option<Stamp>,
    /// every transcript of the reading, in the order it was made.
    pub transcripts: Vec<String>,
    #[serde(flatten)]
    /// the entities the reading met and what it says about them.
    pub derived: Derived,
}

impl Collection {
    /// how many statements are gaps.
    #[must_use]
    pub fn gaps(&self) -> usize {
        self.contents
            .derived
            .statements
            .iter()
            .filter(|statement| matches!(statement.reading, Reading::Gap { .. }))
            .count()
    }

    /// how many statements were recorded.
    #[must_use]
    pub fn recorded(&self) -> usize {
        self.contents.derived.statements.len() - self.gaps()
    }

    /// the statement about one aspect of the entity with a name, if there is one.
    #[must_use]
    pub fn statement_about(&self, name: &str, aspect: &str) -> Option<&Statement> {
        let entity = self.contents.derived.named(name)?;
        self.contents.derived.statement(&entity.uid, aspect)
    }
}

/// derive a collection from the transcripts of one reading.
///
/// # Errors
///
/// returns an error when the statements cannot be derived or the collection
/// cannot be serialized.
pub fn seal(
    scope: &str,
    started_at: String,
    completed_at: String,
    transcripts: &[Transcript],
) -> Result<Collection> {
    let derived = facts::derive(transcripts)?;
    seal_derived(scope, started_at, completed_at, transcripts, derived, None)
}

/// make a collection of transcripts and what was derived from them, by this
/// crate or by a pack.
///
/// # Errors
///
/// returns an error when the collection cannot be serialized.
pub fn seal_derived(
    scope: &str,
    started_at: String,
    completed_at: String,
    transcripts: &[Transcript],
    derived: Derived,
    pack: Option<Stamp>,
) -> Result<Collection> {
    let contents = CollectionContents {
        tool: concat!("divinate/", env!("CARGO_PKG_VERSION")).into(),
        derivation: DERIVATION.into(),
        scope: scope.into(),
        started_at,
        completed_at,
        pack,
        transcripts: transcripts
            .iter()
            .map(|transcript| transcript.id.clone())
            .collect(),
        derived,
    };
    Ok(Collection {
        id: content_id("col", &contents)?,
        contents,
    })
}

/// write a collection and its transcripts. the collection is written last, so
/// a collection that exists always has its transcripts.
///
/// # Errors
///
/// returns an error when the state directory cannot be written.
pub fn store(state: &Path, collection: &Collection, transcripts: &[Transcript]) -> Result<()> {
    for directory in ["transcripts", "collections"] {
        let path = state.join(directory);
        fs::create_dir_all(&path).map_err(|source| Error::Io { path, source })?;
    }
    for transcript in transcripts {
        write_json(transcript, &transcript_path(state, &transcript.id))?;
    }
    write_json(
        collection,
        &state
            .join("collections")
            .join(format!("{}.json", collection.id)),
    )
}

/// load every collection in a state directory, oldest first.
///
/// # Errors
///
/// returns an error when the directory or one of its files cannot be read.
pub fn load(state: &Path) -> Result<Vec<Collection>> {
    let directory = state.join("collections");
    let listing = fs::read_dir(&directory).map_err(|source| Error::Io {
        path: directory.clone(),
        source,
    })?;
    let mut collections = Vec::new();
    for file in listing {
        let path = file
            .map_err(|source| Error::Io {
                path: directory.clone(),
                source,
            })?
            .path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            collections.push(read_json::<Collection>(&path)?);
        }
    }
    collections.sort_by(|left, right| {
        (&left.contents.started_at, &left.id).cmp(&(&right.contents.started_at, &right.id))
    });
    Ok(collections)
}

/// load one transcript by id.
///
/// # Errors
///
/// returns an error when the transcript is missing or unreadable.
pub fn load_transcript(state: &Path, id: &str) -> Result<Transcript> {
    read_json(&transcript_path(state, id))
}

fn transcript_path(state: &Path, id: &str) -> PathBuf {
    state.join("transcripts").join(format!("{id}.json"))
}
