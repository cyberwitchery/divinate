//! checking a stored record offline.
//!
//! verification needs no network and no credential. it shows that nothing
//! changed after capture. it cannot show that the source reported the truth,
//! or that whoever ran the collection kept everything the source returned.

use std::path::Path;

use crate::error::{Error, Result};
use crate::pack::{self, NoPacks, Packs};
use crate::record::{self, Collection, DERIVATION};
use crate::{content_id, facts, transcript};

#[derive(Debug, PartialEq, Eq)]
/// what a verification covered.
pub struct Report {
    pub collections: usize,
    pub transcripts: usize,
    /// collections whose statements were derived by other rules than this
    /// build's. their bytes were checked, their statements were not recomputed.
    pub not_recomputed: Vec<(String, String)>,
}

/// check every collection in a state directory against its transcripts.
///
/// each collection and transcript must match its id, each retained body its
/// digest, and each collection's entities, statements, and relations must be
/// exactly what its transcripts derive.
///
/// # Errors
///
/// returns an error naming the first thing that does not match.
pub fn verify(state: &Path) -> Result<Report> {
    verify_with(state, &NoPacks)
}

/// check every collection in a state directory against its transcripts,
/// asking the packs at hand to derive again what a pack derived.
///
/// a collection that a pack derived is recomputed when that pack is at hand
/// in the same version. otherwise its bytes are checked and it is listed as
/// not recomputed, with the pack it needs.
///
/// # Errors
///
/// returns an error naming the first thing that does not match.
pub fn verify_with(state: &Path, packs: &dyn Packs) -> Result<Report> {
    let mut report = Report {
        collections: 0,
        transcripts: 0,
        not_recomputed: Vec::new(),
    };
    for collection in record::load(state)? {
        verify_collection(state, &collection, packs, &mut report)?;
    }
    Ok(report)
}

fn verify_collection(
    state: &Path,
    collection: &Collection,
    packs: &dyn Packs,
    report: &mut Report,
) -> Result<()> {
    let expected = content_id("col", &collection.contents)?;
    if expected != collection.id {
        return Err(Error::Verification(format!(
            "collection {} does not match its contents ({expected})",
            collection.id
        )));
    }
    let mut transcripts = Vec::new();
    for id in &collection.contents.transcripts {
        let stored = record::load_transcript(state, id)?;
        if &stored.id != id {
            return Err(Error::Verification(format!(
                "transcript file {id} holds transcript {}",
                stored.id
            )));
        }
        transcript::verify(&stored)?;
        transcripts.push(stored);
    }
    report.collections += 1;
    report.transcripts += transcripts.len();
    let derived = if let Some(stamp) = &collection.contents.pack {
        // the same pack in the same version says the same of the same
        // transcripts. another version may not.
        let at_hand = pack::describe(packs, &stamp.name)
            .ok()
            .filter(|described| described.version == stamp.version);
        if at_hand.is_none() {
            report.not_recomputed.push((
                collection.id.clone(),
                format!(
                    "derived by the pack {} {}, which is not configured here",
                    stamp.name, stamp.version
                ),
            ));
            return Ok(());
        }
        pack::source::derive(packs, &stamp.name, &transcripts)?
    } else if collection.contents.derivation != DERIVATION {
        report
            .not_recomputed
            .push((collection.id.clone(), "derived by other rules".into()));
        return Ok(());
    } else {
        facts::derive(&transcripts)?
    };
    if derived != collection.contents.derived {
        return Err(Error::Verification(format!(
            "collection {}: its statements are not what its transcripts say",
            collection.id
        )));
    }
    Ok(())
}
