//! releases: what a repository gave out, and what was attached to it.

use serde_json::{json, Value};

use super::capture::RELEASES;
use super::work::actor;
use crate::error::Result;
use crate::model::{aspect, kind, Entity};
use crate::source::build::{find, items, Span};
use crate::source::work::{Release, Work};
use crate::transcript::Transcript;

/// derive the releases of one repository published in the period. a draft is
/// not published, and is left out.
pub(super) fn derive(
    repository: &Entity,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    let Some(listing) = find(transcripts, RELEASES) else {
        return Ok(());
    };
    let period = Span::of(listing);
    for release in items(listing) {
        let (Some(id), Some(tag), Some(published_at)) = (
            release["id"].as_u64(),
            release["tag_name"].as_str(),
            release["published_at"].as_str(),
        ) else {
            continue;
        };
        if release["draft"] == Value::Bool(true) || !period.holds(&release["published_at"]) {
            continue;
        }
        let assets = release["assets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|asset| {
                json!({
                    "name": asset["name"],
                    "size": asset["size"],
                    "digest": asset["digest"],
                })
            })
            .collect();
        work.release(
            Release {
                id: id.to_string(),
                name: format!("{} release {tag}", repository.name),
                tag: release["tag_name"].clone(),
                title: release["name"].clone(),
                prerelease: release["prerelease"].clone(),
                published_at: published_at.to_owned(),
                author: actor(&release["author"]),
                assets,
            },
            aspect::RELEASES,
            listing,
        )?;
    }
    work.population(kind::RELEASE, aspect::RELEASES, &[listing])
}
