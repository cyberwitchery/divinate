//! tickets and changes: github's issues and pull requests, and what happened
//! to them.

use std::collections::BTreeMap;

use serde_json::Value;

use super::capture::{CHECK_RUNS, FILES, PULL_REQUEST, STATUSES, TIMELINE, WORK_ITEMS};
use crate::error::Result;
use crate::model::{aspect, event, kind, relation, Entity};
use crate::source::build::{self, find, Span};
use crate::source::work::{closes, Actor, Details, Happened, Item, Reference, Target, Work};
use crate::transcript::Transcript;

/// an issue or pull request a listing names for its period.
pub(super) struct Listed {
    pub number: u64,
    pub change: bool,
}

/// the issues and pull requests of a listing's period: those opened in it,
/// and the pull requests merged in it.
pub(super) fn in_period(listing: &Transcript) -> Vec<Listed> {
    listed(listing)
        .iter()
        .filter_map(|(item, _)| {
            Some(Listed {
                number: item["number"].as_u64()?,
                change: item.get("pull_request").is_some(),
            })
        })
        .collect()
}

/// each listed item of the period, with the populations it belongs to.
fn listed(listing: &Transcript) -> Vec<(Value, Vec<&'static str>)> {
    let period = Span::of(listing);
    build::items(listing)
        .into_iter()
        .filter_map(|item| {
            let change = item.get("pull_request").is_some();
            let mut populations = Vec::new();
            if period.holds(&item["created_at"]) {
                populations.push(if change {
                    aspect::CHANGES
                } else {
                    aspect::TICKETS
                });
            }
            if period.holds(&item["pull_request"]["merged_at"]) {
                populations.push(aspect::MERGED_CHANGES);
            }
            (!populations.is_empty()).then_some((item, populations))
        })
        .collect()
}

/// the branch a pull request goes into, from its own transcript.
pub(super) fn base(pull: &Transcript) -> Option<String> {
    build::peek(pull)?["base"]["ref"]
        .as_str()
        .map(str::to_owned)
}

/// the commit a pull request proposes, from its own transcript.
pub(super) fn head(pull: &Transcript) -> Option<String> {
    let sha = build::peek(pull)?["head"]["sha"].as_str()?.to_owned();
    (sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(sha)
}

/// derive the tickets and changes of one repository, their events, the actors
/// behind them, and the links between them.
pub(super) fn derive(
    repository: &Entity,
    default_branch: Option<&str>,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    let Some(listing) = find(transcripts, WORK_ITEMS) else {
        return Ok(());
    };
    // what was read about each item, by the item's name and then by resource.
    let mut read = BTreeMap::<&str, BTreeMap<&str, &Transcript>>::new();
    for transcript in transcripts {
        let resource = transcript.contents.resource.as_str();
        if [TIMELINE, PULL_REQUEST, FILES, CHECK_RUNS, STATUSES].contains(&resource) {
            read.entry(&transcript.contents.subject)
                .or_default()
                .insert(resource, transcript);
        }
    }
    for (listed, populations) in listed(listing) {
        let (Some(id), Some(number)) = (listed["id"].as_u64(), listed["number"].as_u64()) else {
            continue;
        };
        let change = listed.get("pull_request").is_some();
        let merged_at = listed["pull_request"]["merged_at"].clone();
        let name = format!("{}#{number}", repository.name);
        let about = read.get(name.as_str());
        let details = details(repository, number, change, about)?;
        // the listing does not name the branch a pull request goes into. its
        // own reading does.
        let base = about.and_then(|read| base(read.get(PULL_REQUEST)?));
        // the branch's settings were read when the record has the branch.
        let read_branch = base
            .as_ref()
            .and_then(|base| work.named(&format!("{}@{base}", repository.name)));
        let files = about.and_then(|read| read.get(FILES).copied());
        let item = Item {
            kind: kind_of(&listed),
            native_kind: native_kind(&listed).into(),
            id: id.to_string(),
            name,
            number,
            title: listed["title"].clone(),
            state: match listed["state"].as_str() {
                _ if change && merged_at.is_string() => "merged",
                Some("closed") => "closed",
                _ => "open",
            },
            labels: listed["labels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|label| label["name"].as_str().map(str::to_owned))
                .collect(),
            opened_at: listed["created_at"].clone(),
            closed_at: listed["closed_at"].clone(),
            merged_at,
            author: actor(&listed["user"]),
            target: change
                .then(|| Target::new(base.as_deref(), default_branch, read_branch.as_deref())),
            description: listed["body"].clone(),
            files: change.then(|| paths(files)),
            files_from: files.map(|files| files.id.clone()),
        };
        work.item(item, &populations, listing, details)?;
    }
    work.population(kind::TICKET, aspect::TICKETS, &[listing])?;
    work.population(kind::CHANGE, aspect::CHANGES, &[listing])?;
    work.population(kind::CHANGE, aspect::MERGED_CHANGES, &[listing])
}

/// the paths of the files a pull request touches, or why they could not be
/// read. a renamed file counts under both of its names.
fn paths(files: Option<&Transcript>) -> std::result::Result<Vec<String>, String> {
    let files = files.ok_or("its files were not read")?;
    if let Some(reason) = files.contents.termination.gap() {
        return Err(reason);
    }
    let mut paths = build::items(files)
        .iter()
        .flat_map(|file| [&file["filename"], &file["previous_filename"]])
        .filter_map(|path| path.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// what happened to one item, from the readings made about it. every reading
/// its kind needs must have completed, or the events are a gap.
fn details<'a>(
    repository: &Entity,
    number: u64,
    change: bool,
    read: Option<&BTreeMap<&str, &'a Transcript>>,
) -> Result<Details<'a>> {
    let find = |resource: &str| read.and_then(|read| read.get(resource).copied());
    let mut details = Details::unread();
    let Some(timeline) = find(TIMELINE) else {
        return Ok(details);
    };
    details.transcripts.push(timeline);
    if let Some(reason) = timeline.contents.termination.gap() {
        details.events = Err(reason);
        return Ok(details);
    }
    let mut found = vec![timeline];
    if change {
        // the checks hang on the commit the pull request names. when one of
        // the three readings is missing, the checks are unread and the rest stands.
        let checks = [PULL_REQUEST, CHECK_RUNS, STATUSES].map(find);
        details.transcripts.extend(checks.iter().flatten());
        let unread = checks.iter().find_map(|reading| match reading {
            None => Some("the commit it proposes was not read".to_owned()),
            Some(reading) => reading.contents.termination.gap(),
        });
        match unread {
            Some(reason) => details.without_checks(&reason),
            None => found.extend(checks.iter().flatten()),
        }
    }
    let mut events = Vec::new();
    for transcript in found {
        match transcript.contents.resource.as_str() {
            TIMELINE => {
                let (happened, references) = read_timeline(repository, number, transcript)?;
                events.extend(happened);
                details.references = references;
            }
            CHECK_RUNS => events.extend(check_runs(transcript)),
            STATUSES => events.extend(statuses(transcript)),
            _ => {}
        }
    }
    details.events = Ok(events);
    Ok(details)
}

/// the check runs that finished on a change's commit. a run that was skipped
/// or is neutral neither passed nor failed.
fn check_runs(transcript: &Transcript) -> Vec<Happened> {
    pages(transcript, "check_runs")
        .iter()
        .filter_map(|run| {
            let kind = match run["conclusion"].as_str()? {
                "success" => event::CHECK_PASSED,
                "failure" | "timed_out" | "cancelled" | "action_required" | "startup_failure" => {
                    event::CHECK_FAILED
                }
                _ => return None,
            };
            let id = format!("check-run/{}", run["id"].as_u64()?);
            Some(
                Happened::new(kind, id, run["completed_at"].as_str()?).named(run["name"].as_str()?),
            )
        })
        .collect()
}

/// the commit statuses reported on a change's commit.
fn statuses(transcript: &Transcript) -> Vec<Happened> {
    pages(transcript, "statuses")
        .iter()
        .filter_map(|status| {
            let kind = match status["state"].as_str()? {
                "success" => event::CHECK_PASSED,
                "failure" | "error" => event::CHECK_FAILED,
                _ => return None,
            };
            let id = format!("status/{}", status["id"].as_u64()?);
            Some(
                Happened::new(kind, id, status["created_at"].as_str()?)
                    .named(status["context"].as_str()?),
            )
        })
        .collect()
}

/// the items every page of a reading holds under one field.
fn pages(transcript: &Transcript, field: &str) -> Vec<Value> {
    transcript
        .bodies()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .filter_map(|mut page| match page[field].take() {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .flatten()
        .collect()
}

fn kind_of(item: &Value) -> &'static str {
    if item.get("pull_request").is_some() {
        kind::CHANGE
    } else {
        kind::TICKET
    }
}

fn native_kind(item: &Value) -> &'static str {
    if item.get("pull_request").is_some() {
        "pull request"
    } else {
        "issue"
    }
}

pub(super) fn actor(user: &Value) -> Option<Actor> {
    Some(Actor {
        id: user["id"].as_u64()?.to_string(),
        login: user["login"].as_str()?.to_owned(),
        native_kind: user["type"].as_str().unwrap_or("user").to_ascii_lowercase(),
    })
}

/// the events of one item's timeline, and the items that refer to it.
fn read_timeline(
    repository: &Entity,
    number: u64,
    timeline: &Transcript,
) -> Result<(Vec<Happened>, Vec<Reference>)> {
    let mut events = Vec::new();
    let mut references = Vec::new();
    let entries = build::list(timeline)?;
    // who wrote each review. a dismissal names the review, not its author.
    let reviewers = entries
        .iter()
        .filter(|entry| entry["event"] == "reviewed")
        .filter_map(|entry| Some((entry["id"].as_u64()?, &entry["user"])))
        .collect::<BTreeMap<_, _>>();
    let added = added_after_a_review(&entries);
    for entry in &entries {
        let name = entry["event"].as_str().unwrap_or_default();
        match name {
            "cross-referenced" => {
                references.extend(reference(repository, number, &entry["source"]["issue"]));
                continue;
            }
            "committed" => {
                if let (Some(sha), Some(made)) =
                    (entry["sha"].as_str(), entry["committer"]["date"].as_str())
                {
                    let at = added.get(sha).map_or(made, |reviewed| made.max(reviewed));
                    events.push(Happened::new(event::COMMIT, format!("commit/{sha}"), at));
                }
                continue;
            }
            _ => {}
        }
        let dismissed = &entry["dismissed_review"];
        let kind = match (name, entry["state"].as_str()) {
            ("commented", _) => event::COMMENT,
            ("closed", _) => event::CLOSED,
            ("reopened", _) => event::REOPENED,
            ("merged", _) => event::MERGE,
            ("reviewed", Some("approved")) => event::APPROVAL,
            ("reviewed", Some("changes_requested")) => event::CHANGES_REQUESTED,
            ("review_dismissed", _) if dismissed["state"] == "approved" => {
                event::APPROVAL_WITHDRAWN
            }
            ("head_ref_force_pushed", _) => event::COMMIT,
            _ => continue,
        };
        let at = if entry["submitted_at"].is_string() {
            &entry["submitted_at"]
        } else {
            &entry["created_at"]
        };
        let (Some(id), Some(at)) = (entry["id"].as_u64(), at.as_str()) else {
            continue;
        };
        // a withdrawn approval is the reviewer's, whoever dismissed it.
        let by = if kind == event::APPROVAL_WITHDRAWN {
            dismissed["review_id"]
                .as_u64()
                .and_then(|review| reviewers.get(&review).copied())
                .unwrap_or(&Value::Null)
        } else if entry["user"].is_object() {
            &entry["user"]
        } else {
            &entry["actor"]
        };
        // a review and a comment are numbered separately, so the source's
        // event name is part of the id.
        events.push(Happened::new(kind, format!("{name}/{id}"), at).by(actor(by)));
    }
    Ok((events, references))
}

/// for each commit that follows a reviewed commit, the time of the latest
/// such review.
///
/// github says when a commit was made, not when it was added to the pull
/// request. a review names the commit it saw, and the timeline lists commits
/// in order, so a commit listed after a reviewed one was added after that
/// review, whenever it was made.
fn added_after_a_review(entries: &[Value]) -> BTreeMap<&str, &str> {
    let commits = entries
        .iter()
        .filter(|entry| entry["event"] == "committed")
        .filter_map(|entry| entry["sha"].as_str())
        .collect::<Vec<_>>();
    let mut added = BTreeMap::new();
    for review in entries.iter().filter(|entry| entry["event"] == "reviewed") {
        let (Some(seen), Some(at)) = (
            review["commit_id"].as_str(),
            review["submitted_at"].as_str(),
        ) else {
            continue;
        };
        let Some(position) = commits.iter().position(|sha| *sha == seen) else {
            continue;
        };
        for later in &commits[position + 1..] {
            let latest = added.entry(*later).or_insert(at);
            *latest = (*latest).max(at);
        }
    }
    added
}

/// another item refers to this one. a change in the same repository whose
/// description says it closes this item is a stronger link than a mention.
fn reference(repository: &Entity, number: u64, source: &Value) -> Option<Reference> {
    let (id, source_number) = (source["id"].as_u64()?, source["number"].as_u64()?);
    let full_name = source["repository"]["full_name"].as_str();
    let home = full_name.map_or_else(|| repository.name.clone(), |name| format!("github:{name}"));
    let same_scope = home == repository.name;
    let closing = kind_of(source) == kind::CHANGE
        && same_scope
        && closes(source["body"].as_str().unwrap_or_default(), '#', number);
    Some(Reference {
        kind: kind_of(source),
        native_kind: native_kind(source),
        id: id.to_string(),
        name: format!("{home}#{source_number}"),
        same_scope,
        basis: if closing {
            relation::CLOSING_KEYWORD
        } else {
            relation::MENTION
        },
    })
}
