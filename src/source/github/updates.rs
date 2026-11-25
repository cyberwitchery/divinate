//! what happened to a branch: merges and pushes.

use super::capture::ACTIVITY;
use super::work::actor;
use crate::error::Result;
use crate::model::{event, Entity};
use crate::parse_time;
use crate::source::build::{self, all, Span};
use crate::source::work::{Happened, Work};
use crate::transcript::Transcript;

/// derive every update of one branch during the period.
pub(super) fn derive(branch: &Entity, transcripts: &[Transcript], work: &mut Work) -> Result<()> {
    let Some(listing) = all(transcripts, ACTIVITY).find(|listing| {
        listing
            .parameter("branch")
            .is_some_and(|name| branch.name.ends_with(&format!("@{name}")))
    }) else {
        return Ok(());
    };
    let period = Span::of(listing);
    let happened = match listing.contents.termination.gap() {
        Some(reason) => Err(reason),
        None => Ok(build::items(listing)
            .iter()
            .filter_map(|update| {
                let at = update["timestamp"]
                    .as_str()
                    .filter(|_| period.holds(&update["timestamp"]))?;
                let kind = match update["activity_type"].as_str()? {
                    "pr_merge" | "merge_queue_merge" => event::MERGE,
                    "push" => event::PUSH,
                    "force_push" => event::FORCE_PUSH,
                    _ => return None,
                };
                let id = format!("activity/{}", update["id"].as_u64()?);
                Some(Happened::new(kind, id, at).by(actor(&update["actor"])))
            })
            .collect()),
    };
    work.updates(branch, happened, reach(listing), listing)
}

/// github reports a year of branch activity. a period that starts earlier is
/// only partly covered.
fn reach(listing: &Transcript) -> Option<String> {
    let read = parse_time(&listing.contents.captured_at).ok()?;
    let from = parse_time(listing.parameter("from")?).ok()?;
    (read - from > time::Duration::days(365)).then(|| {
        "github reports one year of branch activity, so earlier updates are missing".into()
    })
}
