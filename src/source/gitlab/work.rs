//! tickets and changes: gitlab's issues and merge requests, and what happened
//! to them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::capture::{
    APPROVALS, CLOSED_BY, DIFFS, ISSUES, JOBS, MERGED, MERGE_REQUESTS, NOTES, PIPELINES, PUSHES,
    RELEASES, STATE_EVENTS,
};
use crate::error::Result;
use crate::model::{aspect, event, kind, relation, Entity};
use crate::source::build::{find, items, list, single, Span};
use crate::source::work::{Actor, Details, Happened, Item, Reference, Release, Target, Work};
use crate::transcript::Transcript;

/// the project-level numbers of the issues or merge requests a listing names.
pub(super) fn numbers(listing: &Transcript) -> Vec<u64> {
    items(listing)
        .iter()
        .filter_map(|item| item["iid"].as_u64())
        .collect()
}

/// the pipelines that ran on the newest commit of a merge request. their jobs
/// are read one by one. pipeline ids grow, so the newest pipeline has the
/// highest.
pub(super) fn head_pipelines(listing: &Transcript) -> Vec<u64> {
    let pipelines = items(listing);
    let Some(newest) = pipelines
        .iter()
        .max_by_key(|pipeline| pipeline["id"].as_u64())
    else {
        return Vec::new();
    };
    pipelines
        .iter()
        .filter(|pipeline| pipeline["sha"] == newest["sha"])
        .filter_map(|pipeline| pipeline["id"].as_u64())
        .collect()
}

/// the branches the merge requests merged in the period went into.
pub(super) fn targets(transcripts: &[Transcript]) -> BTreeSet<String> {
    find(transcripts, MERGED)
        .map(merged)
        .unwrap_or_default()
        .iter()
        .filter_map(|change| change["target_branch"].as_str().map(str::to_owned))
        .collect()
}

/// the merge requests a listing says were merged in its period.
pub(super) fn merged_in_period(listing: &Transcript) -> Vec<u64> {
    merged(listing)
        .iter()
        .filter_map(|item| item["iid"].as_u64())
        .collect()
}

fn merged(listing: &Transcript) -> Vec<Value> {
    let period = Span::of(listing);
    items(listing)
        .into_iter()
        .filter(|item| period.holds(&item["merged_at"]))
        .collect()
}

/// derive the tickets and changes of one project, their events, the actors
/// behind them, and the links between them.
pub(super) fn derive(
    project: &Entity,
    project_id: u64,
    default_branch: Option<&str>,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    // what was read about each item, by the item's name and then by resource.
    let mut read = BTreeMap::<&str, BTreeMap<&str, &Transcript>>::new();
    let mut jobs = BTreeMap::<&str, Vec<&Transcript>>::new();
    for transcript in transcripts {
        let resource = transcript.contents.resource.as_str();
        if resource == JOBS {
            jobs.entry(&transcript.contents.subject)
                .or_default()
                .push(transcript);
        }
        if [NOTES, STATE_EVENTS, CLOSED_BY, APPROVALS, PIPELINES, DIFFS].contains(&resource) {
            read.entry(&transcript.contents.subject)
                .or_default()
                .insert(resource, transcript);
        }
    }
    // each item once, with the populations it belongs to and the listing that names it.
    let mut listed = Vec::<(Value, &'static str, Vec<&'static str>, &Transcript)>::new();
    if let Some(listing) = find(transcripts, ISSUES) {
        for issue in items(listing) {
            listed.push((issue, kind::TICKET, vec![aspect::TICKETS], listing));
        }
    }
    let opened = find(transcripts, MERGE_REQUESTS);
    if let Some(listing) = opened {
        for change in items(listing) {
            listed.push((change, kind::CHANGE, vec![aspect::CHANGES], listing));
        }
    }
    let merged_listing = find(transcripts, MERGED);
    if let Some(listing) = merged_listing {
        for change in merged(listing) {
            let known = listed
                .iter_mut()
                .find(|(known, of, ..)| *of == kind::CHANGE && known["id"] == change["id"]);
            match known {
                Some((_, _, populations, _)) => populations.push(aspect::MERGED_CHANGES),
                None => listed.push((change, kind::CHANGE, vec![aspect::MERGED_CHANGES], listing)),
            }
        }
    }
    for (item, of, populations, listing) in listed {
        let (Some(id), Some(number)) = (item["id"].as_u64(), item["iid"].as_u64()) else {
            continue;
        };
        let change = of == kind::CHANGE;
        let marker = if change { '!' } else { '#' };
        let name = format!("{}{marker}{number}", project.name);
        let details = details(
            of,
            &item,
            project_id,
            read.get(name.as_str()),
            jobs.get(name.as_str()).map_or(&[][..], Vec::as_slice),
        )?;
        let diffs = read
            .get(name.as_str())
            .and_then(|read| read.get(DIFFS).copied());
        let item = Item {
            description: item["description"].clone(),
            files: change.then(|| paths(diffs)),
            files_from: diffs.map(|diffs| diffs.id.clone()),
            kind: of,
            native_kind: if change { "merge request" } else { "issue" }.into(),
            id: id.to_string(),
            name,
            number,
            title: item["title"].clone(),
            state: match item["state"].as_str() {
                Some("merged") => "merged",
                Some("closed") => "closed",
                _ => "open",
            },
            labels: item["labels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|label| label.as_str().map(str::to_owned))
                .collect(),
            opened_at: item["created_at"].clone(),
            closed_at: item["closed_at"].clone(),
            merged_at: item["merged_at"].clone(),
            author: actor(&item["author"]),
            target: change.then(|| {
                let target = item["target_branch"].as_str();
                let read = target.and_then(|name| work.named(&format!("{}@{name}", project.name)));
                Target::new(target, default_branch, read.as_deref())
            }),
        };
        work.item(item, &populations, listing, details)?;
    }
    if let Some(listing) = find(transcripts, ISSUES) {
        work.population(kind::TICKET, aspect::TICKETS, &[listing])?;
    }
    if let Some(listing) = opened {
        work.population(kind::CHANGE, aspect::CHANGES, &[listing])?;
    }
    if let Some(listing) = merged_listing {
        work.population(kind::CHANGE, aspect::MERGED_CHANGES, &[listing])?;
    }
    Ok(())
}

/// the paths of the files a merge request touches, or why they could not be
/// read. a renamed file counts under both of its names.
fn paths(diffs: Option<&Transcript>) -> std::result::Result<Vec<String>, String> {
    let diffs = diffs.ok_or("its files were not read")?;
    if let Some(reason) = diffs.contents.termination.gap() {
        return Err(reason);
    }
    let mut paths = items(diffs)
        .iter()
        .flat_map(|file| [&file["new_path"], &file["old_path"]])
        .filter_map(|path| path.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// derive the releases of one project released in the period. gitlab names
/// a release by its tag, and lists the links attached to it.
pub(super) fn releases(
    project: &Entity,
    project_id: u64,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    let Some(listing) = find(transcripts, RELEASES) else {
        return Ok(());
    };
    let period = Span::of(listing);
    for release in items(listing) {
        let (Some(tag), Some(released_at)) = (
            release["tag_name"].as_str(),
            release["released_at"].as_str(),
        ) else {
            continue;
        };
        if release["upcoming_release"] == Value::Bool(true)
            || !period.holds(&release["released_at"])
        {
            continue;
        }
        let assets = release["assets"]["links"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|link| json!({ "name": link["name"], "kind": link["link_type"] }))
            .collect();
        work.release(
            Release {
                id: format!("{project_id}/{tag}"),
                name: format!("{} release {tag}", project.name),
                tag: release["tag_name"].clone(),
                title: release["name"].clone(),
                prerelease: Value::Null,
                published_at: released_at.to_owned(),
                author: actor(&release["author"]),
                assets,
            },
            aspect::RELEASES,
            listing,
        )?;
    }
    work.population(kind::RELEASE, aspect::RELEASES, &[listing])
}

/// derive every update of one branch during the period. gitlab does
/// not say whether a push merged a merge request, so a push counts as a merge
/// when it ends on a commit of a merged merge request.
pub(super) fn updates(branch: &Entity, transcripts: &[Transcript], work: &mut Work) -> Result<()> {
    let Some(pushes) = find(transcripts, PUSHES) else {
        return Ok(());
    };
    let name = branch.name.rsplit_once('@').map_or("", |(_, name)| name);
    let period = Span::of(pushes);
    let merged = find(transcripts, MERGED);
    let unread = pushes.contents.termination.gap().or_else(|| match merged {
        None => Some("the merged merge requests were not read".to_owned()),
        Some(merged) => merged.contents.termination.gap(),
    });
    let happened = if let Some(reason) = unread {
        Err(reason)
    } else {
        let commits = merged
            .map(items)
            .unwrap_or_default()
            .iter()
            .flat_map(|change| {
                ["merge_commit_sha", "squash_commit_sha", "sha"]
                    .map(|field| change[field].as_str().map(str::to_owned))
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        Ok(items(pushes)
            .iter()
            .filter_map(|push| {
                let data = &push["push_data"];
                let on_branch = data["ref_type"] == "branch"
                    && data["ref"] == name
                    && data["action"] == "pushed"
                    && period.holds(&push["created_at"]);
                let kind = if commits.contains(data["commit_to"].as_str()?) {
                    event::MERGE
                } else {
                    event::PUSH
                };
                let id = format!("push/{}", push["id"].as_u64()?);
                on_branch.then(|| {
                    Happened::new(kind, id, push["created_at"].as_str().unwrap_or_default())
                        .by(actor(&push["author"]))
                })
            })
            .collect())
    };
    work.updates(branch, happened, None, pushes)
}

fn actor(user: &Value) -> Option<Actor> {
    Some(Actor {
        id: user["id"].as_u64()?.to_string(),
        login: user["username"].as_str()?.to_owned(),
        native_kind: if user["bot"] == Value::Bool(true) {
            "bot"
        } else {
            "user"
        }
        .into(),
    })
}

/// what happened to one item, from the readings made about it. every reading
/// its kind needs must have completed, or the events are a gap.
fn details<'a>(
    of: &str,
    item: &Value,
    project_id: u64,
    read: Option<&BTreeMap<&str, &'a Transcript>>,
    jobs: &[&'a Transcript],
) -> Result<Details<'a>> {
    let needed = if of == kind::CHANGE {
        [NOTES, STATE_EVENTS, APPROVALS]
    } else {
        [NOTES, STATE_EVENTS, CLOSED_BY]
    };
    let found = needed
        .iter()
        .filter_map(|resource| read?.get(resource).copied())
        .collect::<Vec<_>>();
    let mut details = Details::unread();
    details.transcripts.clone_from(&found);
    if found.len() < needed.len() {
        return Ok(details);
    }
    if let Some(reason) = found
        .iter()
        .find_map(|transcript| transcript.contents.termination.gap())
    {
        details.events = Err(reason);
        return Ok(details);
    }
    let mut events = Vec::new();
    if of == kind::CHANGE {
        // the checks can be unread while the rest of what happened stands.
        let pipelines = read.and_then(|read| read.get(PIPELINES).copied());
        details.transcripts.extend(pipelines);
        details.transcripts.extend(jobs);
        match checks(pipelines, jobs) {
            Ok(checks) => events.extend(checks),
            Err(reason) => details.without_checks(&reason),
        }
    }
    for transcript in found {
        let resource = transcript.contents.resource.as_str();
        for entry in entries(transcript)? {
            match resource {
                NOTES => {
                    let kind = if entry["system"] == Value::Bool(false) {
                        Some(event::COMMENT)
                    } else {
                        system_note(entry["body"].as_str().unwrap_or_default())
                    };
                    if let Some(kind) = kind {
                        events.extend(happened(kind, "note", &entry, "author", "created_at"));
                    }
                }
                STATE_EVENTS => {
                    let kind = match entry["state"].as_str() {
                        Some("closed") => event::CLOSED,
                        Some("reopened") => event::REOPENED,
                        Some("merged") => event::MERGE,
                        _ => continue,
                    };
                    events.extend(happened(kind, "state", &entry, "user", "created_at"));
                }
                APPROVALS => {
                    for approval in entry["approved_by"].as_array().into_iter().flatten() {
                        let (Some(by), Some(at)) =
                            (actor(&approval["user"]), approval["approved_at"].as_str())
                        else {
                            continue;
                        };
                        events.push(Happened {
                            kind: event::APPROVAL,
                            id: format!("approval/{}/{}", item["id"], by.id),
                            at: at.into(),
                            actor: Some(by),
                            name: None,
                        });
                    }
                }
                CLOSED_BY => details.references.extend(closing(&entry, project_id)),
                _ => {}
            }
        }
    }
    details.events = Ok(events);
    Ok(details)
}

/// how the checks on a merge request ended: each of its pipelines as a whole,
/// and each job of the pipelines on its newest commit. or why that could not
/// be read.
fn checks(
    pipelines: Option<&Transcript>,
    jobs: &[&Transcript],
) -> std::result::Result<Vec<Happened>, String> {
    let pipelines = pipelines.ok_or("its pipelines were not read")?;
    if let Some(reason) = pipelines.contents.termination.gap() {
        return Err(reason);
    }
    let mut checks = items(pipelines)
        .iter()
        .filter_map(|pipeline| check(pipeline, "pipeline", "updated_at", Some("pipeline")))
        .collect::<Vec<_>>();
    for pipeline in head_pipelines(pipelines) {
        let pipeline = pipeline.to_string();
        let read = jobs
            .iter()
            .find(|jobs| jobs.parameter("pipeline") == Some(&pipeline))
            .ok_or("the jobs of its pipelines were not read")?;
        if let Some(reason) = read.contents.termination.gap() {
            return Err(reason);
        }
        checks.extend(
            items(read)
                .iter()
                .filter_map(|job| check(job, "job", "finished_at", None)),
        );
    }
    Ok(checks)
}

/// a pipeline or a job that finished, under `name` or its own.
fn check(entry: &Value, prefix: &str, at: &str, name: Option<&str>) -> Option<Happened> {
    let kind = match entry["status"].as_str()? {
        "success" => event::CHECK_PASSED,
        "failed" | "canceled" => event::CHECK_FAILED,
        _ => return None,
    };
    let id = format!("{prefix}/{}", entry["id"].as_u64()?);
    let name = name.or_else(|| entry["name"].as_str())?;
    Some(Happened::new(kind, id, entry[at].as_str()?).named(name))
}

/// what a system note records, for what gitlab keeps nowhere else: the
/// approvals given and taken back over time, and when commits were added.
/// gitlab.com writes these notes in english. closing and merging are read
/// from the state events instead.
fn system_note(body: &str) -> Option<&'static str> {
    let line = body.lines().next().unwrap_or_default();
    if line == "approved this merge request" {
        Some(event::APPROVAL)
    } else if line == "unapproved this merge request" {
        Some(event::APPROVAL_WITHDRAWN)
    } else if line.starts_with("added ") && line.contains(" commit") {
        Some(event::COMMIT)
    } else {
        None
    }
}

/// the entries of a reading: the items of its lists, or its one object.
fn entries(transcript: &Transcript) -> Result<Vec<Value>> {
    Ok(match single(transcript)? {
        Value::Array(_) => list(transcript)?,
        object => vec![object],
    })
}

fn happened(
    kind: &'static str,
    prefix: &str,
    entry: &Value,
    by: &str,
    at: &str,
) -> Option<Happened> {
    Some(Happened {
        kind,
        id: format!("{prefix}/{}", entry["id"].as_u64()?),
        at: entry[at].as_str()?.to_owned(),
        actor: actor(&entry[by]),
        name: None,
    })
}

/// a merge request gitlab lists as closing the issue.
fn closing(merge_request: &Value, project_id: u64) -> Option<Reference> {
    Some(Reference {
        kind: kind::CHANGE,
        native_kind: "merge request",
        id: merge_request["id"].as_u64()?.to_string(),
        name: format!("gitlab:{}", merge_request["references"]["full"].as_str()?),
        same_scope: merge_request["project_id"].as_u64() == Some(project_id),
        basis: relation::CLOSING_REFERENCE,
    })
}
