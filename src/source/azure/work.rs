//! tickets and changes: azure devops work items and pull requests, and what
//! happened to them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use time::UtcOffset;

use super::capture::REPOSITORIES;
use super::capture::{
    COMPLETED, EVALUATIONS, PULL_REQUESTS, PUSHES, THREADS, WORK_ITEM_LINKS, WORK_ITEM_REVISIONS,
    WORK_ITEM_STATES,
};
use super::facts::{is_uuid, values};
use super::facts::{listed, BUILD_VALIDATION};
use crate::error::Result;
use crate::model::{aspect, event, kind, relation, Entity};
use crate::parse_time;
use crate::source::build::{all, find, Span};
use crate::source::work::{Actor, Details, Happened, Item, Reference, Target, Work};
use crate::transcript::Transcript;

/// a pull request named by a project's listing.
pub(super) struct Pull {
    pub number: u64,
    pub repository_id: String,
    pub repository_name: String,
    /// the branch it goes into.
    pub target: Option<String>,
}

/// the pull requests a listing names whose `field` time is in its period. one whose
/// repository id is not the kind the source issues is left out, so no request
/// is built from it.
pub(super) fn pull_requests(listing: &Transcript, field: &str) -> Vec<Pull> {
    opened(listing, field)
        .iter()
        .filter_map(|pull| {
            let repository = &pull["repository"];
            Some(Pull {
                number: pull["pullRequestId"].as_u64()?,
                repository_id: repository["id"]
                    .as_str()
                    .filter(|id| is_uuid(id))?
                    .to_owned(),
                repository_name: repository["name"].as_str()?.to_owned(),
                target: target_branch(pull),
            })
        })
        .collect()
}

fn target_branch(pull: &Value) -> Option<String> {
    Some(
        pull["targetRefName"]
            .as_str()?
            .strip_prefix("refs/heads/")?
            .to_owned(),
    )
}

/// the work items a revision listing says were opened in its period.
pub(super) struct Tickets {
    pub ids: Vec<u64>,
    /// the work item types among them, such as `Bug`.
    pub types: BTreeSet<String>,
}

pub(super) fn tickets(revisions: &Transcript) -> Tickets {
    let mut found = Tickets {
        ids: Vec::new(),
        types: BTreeSet::new(),
    };
    for (id, revisions) in by_item(revisions) {
        found.ids.push(id);
        found.types.extend(
            revisions
                .iter()
                .filter_map(|revision| revision["fields"]["System.WorkItemType"].as_str())
                .map(str::to_owned),
        );
    }
    found
}

/// the revisions of each work item opened in the listing's period, oldest first.
fn by_item(revisions: &Transcript) -> BTreeMap<u64, Vec<Value>> {
    let mut items = BTreeMap::<u64, Vec<Value>>::new();
    for revision in values(revisions) {
        if let Some(id) = revision["id"].as_u64() {
            items.entry(id).or_default().push(revision);
        }
    }
    let period = Span::of(revisions);
    items.retain(|_, revisions| {
        revisions.sort_by_key(|revision| revision["rev"].as_u64());
        revisions
            .iter()
            .any(|revision| period.holds(&revision["fields"]["System.CreatedDate"]))
    });
    items
}

/// the listed items opened from the listing's `from` up to its `until`.
fn opened(listing: &Transcript, field: &str) -> Vec<Value> {
    let period = Span::of(listing);
    values(listing)
        .into_iter()
        .filter(|item| period.holds(&item[field]))
        .collect()
}

/// a time as azure devops wrote it, in utc to the millisecond. the source
/// writes between zero and seven decimal places, which do not sort as text.
fn moment(value: &Value) -> Option<String> {
    let at = parse_time(value.as_str()?).ok()?.to_offset(UtcOffset::UTC);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.millisecond()
    ))
}

fn moment_value(value: &Value) -> Value {
    moment(value).map_or(Value::Null, Value::String)
}

fn actor(identity: &Value) -> Option<Actor> {
    let name = if identity["uniqueName"].is_string() {
        &identity["uniqueName"]
    } else {
        // azure devops withholds the account name from a reading without a credential.
        &identity["displayName"]
    };
    Some(Actor {
        id: identity["id"].as_str()?.to_owned(),
        login: name.as_str()?.to_owned(),
        native_kind: if identity["isContainer"] == Value::Bool(true) {
            "group"
        } else {
            "user"
        }
        .into(),
    })
}

/// derive the tickets and changes of one project, their events, the actors
/// behind them, and the links between them.
pub(super) fn derive(
    project: &Entity,
    project_id: &str,
    repositories: &BTreeMap<String, String>,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    let about = |resource: &'static str| {
        all(transcripts, resource)
            .map(|transcript| (transcript.contents.subject.as_str(), transcript))
            .collect::<BTreeMap<_, _>>()
    };
    let (threads, evaluations) = (about(THREADS), about(EVALUATIONS));
    // the default branch of each repository, by the repository's id.
    let defaults = all(transcripts, REPOSITORIES)
        .flat_map(listed)
        .filter_map(|repository| Some((repository.id, repository.default_branch?)))
        .collect::<BTreeMap<_, _>>();
    // each pull request once, with the populations it belongs to.
    let mut listed = Vec::<(Value, Vec<&'static str>, &Transcript)>::new();
    let opened_listing = find(transcripts, PULL_REQUESTS);
    if let Some(listing) = opened_listing {
        for pull in opened(listing, "creationDate") {
            listed.push((pull, vec![aspect::CHANGES], listing));
        }
    }
    let completed = find(transcripts, COMPLETED);
    if let Some(listing) = completed {
        for pull in opened(listing, "closedDate") {
            let known = listed
                .iter_mut()
                .find(|(known, ..)| known["pullRequestId"] == pull["pullRequestId"]);
            match known {
                Some((_, populations, _)) => populations.push(aspect::MERGED_CHANGES),
                None => listed.push((pull, vec![aspect::MERGED_CHANGES], listing)),
            }
        }
    }
    for (pull, populations, listing) in listed {
        let (Some(number), Some(repository)) = (
            pull["pullRequestId"].as_u64(),
            pull["repository"]["name"].as_str(),
        ) else {
            continue;
        };
        let name = format!("{}/{repository}!{number}", project.name);
        let details = pull_details(
            number,
            threads.get(name.as_str()).copied(),
            evaluations.get(name.as_str()).copied(),
        );
        let status = pull["status"].as_str();
        let closed_at = match status {
            Some("completed" | "abandoned") => moment_value(&pull["closedDate"]),
            _ => Value::Null,
        };
        let item = Item {
            kind: kind::CHANGE,
            native_kind: "pull request".into(),
            id: number.to_string(),
            name,
            number,
            title: pull["title"].clone(),
            state: match status {
                Some("completed") => "merged",
                Some("abandoned") => "closed",
                _ => "open",
            },
            labels: names(&pull["labels"]),
            opened_at: moment_value(&pull["creationDate"]),
            merged_at: if status == Some("completed") {
                closed_at.clone()
            } else {
                Value::Null
            },
            closed_at,
            author: actor(&pull["createdBy"]),
            target: Some({
                let repository = pull["repository"]["id"].as_str().unwrap_or_default();
                let target = target_branch(&pull);
                let read = target.as_ref().and_then(|target| {
                    work.named(&format!(
                        "{}/{}@{target}",
                        project.name,
                        pull["repository"]["name"].as_str()?
                    ))
                });
                Target::new(
                    target.as_deref(),
                    defaults.get(repository).map(String::as_str),
                    read.as_deref(),
                )
            }),
        };
        work.item(item, &populations, listing, details)?;
    }
    if let Some(listing) = opened_listing {
        work.population(kind::CHANGE, aspect::CHANGES, &[listing])?;
    }
    if let Some(listing) = completed {
        work.population(kind::CHANGE, aspect::MERGED_CHANGES, &[listing])?;
    }
    work_items(project, project_id, repositories, transcripts, work)
}

/// the work items opened in the period, and what happened to each.
fn work_items(
    project: &Entity,
    project_id: &str,
    repositories: &BTreeMap<String, String>,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    if let Some(listing) = find(transcripts, WORK_ITEM_REVISIONS) {
        let read = Read::new(listing, transcripts);
        for (id, revisions) in by_item(listing) {
            let (item, details) = read.ticket(project, project_id, repositories, id, &revisions);
            work.item(item, &[aspect::TICKETS], listing, details)?;
        }
        work.population(kind::TICKET, aspect::TICKETS, &[listing])?;
    }
    Ok(())
}

/// derive every update of each default branch during the period. azure
/// devops does not say whether a push completed a pull request, so a push
/// counts as a merge when it ends on the merge commit of a completed one.
pub(super) fn updates(
    branches: &[Entity],
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    let completed = find(transcripts, COMPLETED);
    for pushes in all(transcripts, PUSHES) {
        let name = pushes.parameter("branch").unwrap_or_default();
        let branch_name = format!("{}@{name}", pushes.contents.subject);
        let Some(branch) = branches.iter().find(|branch| branch.name == branch_name) else {
            continue;
        };
        let period = Span::of(pushes);
        let unread = pushes
            .contents
            .termination
            .gap()
            .or_else(|| match completed {
                None => Some("the completed pull requests were not read".to_owned()),
                Some(completed) => completed.contents.termination.gap(),
            });
        let happened = if let Some(reason) = unread {
            Err(reason)
        } else {
            let merges = completed
                .map(values)
                .unwrap_or_default()
                .iter()
                .filter_map(|pull| {
                    pull["lastMergeCommit"]["commitId"]
                        .as_str()
                        .map(str::to_owned)
                })
                .collect::<BTreeSet<_>>();
            let reference = format!("refs/heads/{name}");
            Ok(values(pushes)
                .iter()
                .filter_map(|push| {
                    let update = push["refUpdates"]
                        .as_array()?
                        .iter()
                        .find(|update| update["name"] == reference.as_str())?;
                    let kind = if merges.contains(update["newObjectId"].as_str()?) {
                        event::MERGE
                    } else {
                        event::PUSH
                    };
                    let repository = update["repositoryId"].as_str().unwrap_or_default();
                    let id = format!("push/{repository}/{}", push["pushId"].as_u64()?);
                    period.holds(&push["date"]).then(|| {
                        Happened::new(kind, id, moment(&push["date"]).unwrap_or_default())
                            .by(actor(&push["pushedBy"]))
                    })
                })
                .collect())
        };
        work.updates(branch, happened, None, pushes)?;
    }
    Ok(())
}

fn names(labels: &Value) -> Vec<String> {
    labels
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|label| label["name"].as_str().map(str::to_owned))
        .collect()
}

/// what happened to one pull request, from its threads. azure devops records
/// a vote and a change of status as a thread of its own.
fn pull_details<'a>(
    number: u64,
    threads: Option<&'a Transcript>,
    evaluations: Option<&'a Transcript>,
) -> Details<'a> {
    let mut details = Details::unread();
    let Some(threads) = threads else {
        return details;
    };
    details.transcripts.push(threads);
    if let Some(reason) = threads.contents.termination.gap() {
        details.events = Err(reason);
        return details;
    }
    // how the policies judged it can be unread while the rest stands.
    details.transcripts.extend(evaluations);
    match evaluations.map(|evaluations| evaluations.contents.termination.gap()) {
        None => details.without_checks("its policy evaluations were not read"),
        Some(Some(reason)) => details.without_checks(&reason),
        Some(None) => {}
    }
    let mut events = Vec::new();
    for thread in values(threads) {
        if thread["isDeleted"] == Value::Bool(true) {
            continue;
        }
        let Some(thread_id) = thread["id"].as_u64() else {
            continue;
        };
        let id = format!("pull/{number}/thread/{thread_id}");
        let property = |name: &str| &thread["properties"][name]["$value"];
        // the thread names the people it is about by a number of its own.
        let who = |name: &str| actor(&thread["identities"][property(name).as_str()?]);
        let system = match property("CodeReviewThreadType").as_str() {
            Some("VoteUpdate") => Some((
                match vote(property("CodeReviewVoteResult")) {
                    Some(5 | 10) => Some(event::APPROVAL),
                    Some(-10 | -5) => Some(event::CHANGES_REQUESTED),
                    // a vote of zero takes the reviewer's earlier vote back.
                    Some(0) => Some(event::APPROVAL_WITHDRAWN),
                    _ => None,
                },
                who("CodeReviewVotedByIdentity"),
            )),
            Some("StatusUpdate") => Some((
                match property("CodeReviewStatus").as_str() {
                    Some("Completed") => Some(event::MERGE),
                    Some("Abandoned") => Some(event::CLOSED),
                    Some("Active") => Some(event::REOPENED),
                    _ => None,
                },
                who("CodeReviewStatusUpdatedByIdentity"),
            )),
            // new commits were pushed to the pull request.
            Some("RefUpdate") => Some((Some(event::COMMIT), who("CodeReviewRefUpdatedByIdentity"))),
            Some(_) => Some((None, None)),
            None => None,
        };
        if let Some((kind, by)) = system {
            if let (Some(kind), Some(at)) = (kind, moment(&thread["publishedDate"])) {
                events.push(Happened {
                    kind,
                    id,
                    at,
                    actor: by,
                    name: None,
                });
            }
            continue;
        }
        for comment in thread["comments"].as_array().into_iter().flatten() {
            let written =
                comment["commentType"] == "text" && comment["isDeleted"] != Value::Bool(true);
            let (true, Some(comment_id), Some(at)) = (
                written,
                comment["id"].as_u64(),
                moment(&comment["publishedDate"]),
            ) else {
                continue;
            };
            events.push(Happened {
                kind: event::COMMENT,
                id: format!("{id}/comment/{comment_id}"),
                at,
                actor: actor(&comment["author"]),
                name: None,
            });
        }
    }
    if details.unread.is_empty() {
        events.extend(evaluations.into_iter().flat_map(validations));
    }
    details.events = Ok(events);
    details
}

/// how the build and status policies judged a pull request. a policy about
/// reviewers is not a check.
fn validations(evaluations: &Transcript) -> Vec<Happened> {
    values(evaluations)
        .iter()
        .filter_map(|evaluation| {
            let configuration = &evaluation["configuration"];
            let settings = &configuration["settings"];
            let build = configuration["type"]["id"] == BUILD_VALIDATION;
            let name = if build {
                settings["displayName"]
                    .as_str()
                    .or(configuration["type"]["displayName"].as_str())?
            } else {
                settings["statusName"].as_str()?
            };
            let kind = match evaluation["status"].as_str()? {
                "approved" => event::CHECK_PASSED,
                "rejected" | "broken" => event::CHECK_FAILED,
                _ => return None,
            };
            let id = format!("evaluation/{}", evaluation["evaluationId"].as_str()?);
            Some(Happened::new(kind, id, moment(&evaluation["completedDate"])?).named(name))
        })
        .collect()
}

/// a vote, which the source writes as a number or as its text.
fn vote(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

/// what was read about the work items beyond their revisions.
struct Read<'a> {
    listing: &'a Transcript,
    /// whether any revision reports a comment count. when none does, the
    /// source does not say when comments were made.
    counts: bool,
    /// the category of each state of each work item type.
    states: BTreeMap<&'a str, (&'a Transcript, BTreeMap<String, String>)>,
    /// the links of each work item, and the transcript that holds them.
    links: BTreeMap<u64, (&'a Transcript, Vec<Value>)>,
    /// the batches of links that were asked for.
    batches: Vec<&'a Transcript>,
}

impl<'a> Read<'a> {
    fn new(listing: &'a Transcript, transcripts: &'a [Transcript]) -> Self {
        let mut read = Self {
            listing,
            counts: values(listing)
                .iter()
                .any(|revision| revision["fields"]["System.CommentCount"].is_u64()),
            states: BTreeMap::new(),
            links: BTreeMap::new(),
            batches: Vec::new(),
        };
        for transcript in transcripts {
            match transcript.contents.resource.as_str() {
                WORK_ITEM_STATES => {
                    let categories = values(transcript)
                        .iter()
                        .filter_map(|state| {
                            Some((
                                state["name"].as_str()?.to_owned(),
                                state["category"].as_str()?.to_owned(),
                            ))
                        })
                        .collect();
                    if let Some(kind) = transcript.parameter("type") {
                        read.states.insert(kind, (transcript, categories));
                    }
                }
                WORK_ITEM_LINKS => {
                    read.batches.push(transcript);
                    for item in values(transcript) {
                        if let Some(id) = item["id"].as_u64() {
                            let relations = item["relations"].as_array().cloned();
                            read.links
                                .insert(id, (transcript, relations.unwrap_or_default()));
                        }
                    }
                }
                _ => {}
            }
        }
        read
    }

    /// the batch of links a work item was asked for in.
    fn batch(&self, id: u64) -> Option<&'a Transcript> {
        let id = id.to_string();
        self.batches.iter().copied().find(|batch| {
            batch
                .parameter("ids")
                .is_some_and(|ids| ids.split(',').any(|listed| listed == id))
        })
    }

    /// one work item and what happened to it, from its revisions.
    fn ticket(
        &self,
        project: &Entity,
        project_id: &str,
        repositories: &BTreeMap<String, String>,
        id: u64,
        revisions: &[Value],
    ) -> (Item, Details<'a>) {
        let field = |revision: &Value, name: &str| revision["fields"][name].clone();
        let latest = revisions.last().cloned().unwrap_or_default();
        let native = field(&latest, "System.WorkItemType");
        let native = native.as_str().unwrap_or("work item");
        let states = self.states.get(native);
        let batch = self.batch(id);
        let mut transcripts = vec![self.listing];
        transcripts.extend(states.map(|(transcript, _)| *transcript));
        transcripts.extend(batch);
        // a state is closed when its category says the work is over.
        let closed = |revision: &Value| {
            let state = field(revision, "System.State");
            let category = states?.1.get(state.as_str()?)?;
            Some(category == "Completed" || category == "Removed")
        };
        let complete = self.complete(native, id, revisions, states, batch, &closed);
        let mut events = Vec::new();
        let mut closed_at = Value::Null;
        let (mut was_closed, mut comments) = (false, 0);
        for revision in revisions {
            let (Some(number), Some(at)) = (
                revision["rev"].as_u64(),
                moment(&field(revision, "System.ChangedDate")),
            ) else {
                continue;
            };
            let mut happened = |kind: &'static str| {
                events.push(Happened {
                    kind,
                    id: format!("work-item/{id}/revision/{number}/{kind}"),
                    at: at.clone(),
                    actor: actor(&field(revision, "System.ChangedBy")),
                    name: None,
                });
            };
            let is_closed = closed(revision).unwrap_or(was_closed);
            if is_closed && !was_closed {
                happened(event::CLOSED);
                closed_at = Value::String(at.clone());
            } else if was_closed && !is_closed {
                happened(event::REOPENED);
                closed_at = Value::Null;
            }
            was_closed = is_closed;
            let count = field(revision, "System.CommentCount")
                .as_u64()
                .unwrap_or(comments);
            if count > comments {
                happened(event::COMMENT);
            }
            comments = count;
        }
        let tags = field(&latest, "System.Tags");
        let item = Item {
            kind: kind::TICKET,
            native_kind: native.to_ascii_lowercase(),
            id: id.to_string(),
            name: format!("{}#{id}", project.name),
            number: id,
            title: field(&latest, "System.Title"),
            state: match closed(&latest) {
                Some(true) => "closed",
                Some(false) => "open",
                None => "unknown",
            },
            labels: tags
                .as_str()
                .into_iter()
                .flat_map(|tags| tags.split(';'))
                .map(|tag| tag.trim().to_owned())
                .filter(|tag| !tag.is_empty())
                .collect(),
            opened_at: moment_value(&field(&latest, "System.CreatedDate")),
            closed_at,
            merged_at: Value::Null,
            author: actor(&field(&latest, "System.CreatedBy")),
            target: None,
        };
        let references = match (&complete, self.links.get(&id)) {
            (Ok(()), Some((_, relations))) => relations
                .iter()
                .filter_map(|relation| linked_pull(project, project_id, repositories, relation))
                .collect(),
            _ => Vec::new(),
        };
        let mut details = Details::unread();
        details.events = complete.map(|()| events);
        details.references = references;
        details.transcripts = transcripts;
        (item, details)
    }

    /// whether everything needed to say what happened to a work item was
    /// read, or what is missing.
    fn complete(
        &self,
        native: &str,
        id: u64,
        revisions: &[Value],
        states: Option<&(&Transcript, BTreeMap<String, String>)>,
        batch: Option<&Transcript>,
        closed: &dyn Fn(&Value) -> Option<bool>,
    ) -> std::result::Result<(), String> {
        let numbered = revisions
            .iter()
            .zip(1..)
            .all(|(revision, expected)| revision["rev"].as_u64() == Some(expected));
        if !numbered {
            return Err("the source did not return every revision".into());
        }
        let Some((states, _)) = states else {
            return Err(format!("the states of {native:?} were not read"));
        };
        if let Some(reason) = states.contents.termination.gap() {
            return Err(format!(
                "the states of {native:?} could not be read ({reason})"
            ));
        }
        if let Some(unknown) = revisions.iter().find(|revision| closed(revision).is_none()) {
            return Err(format!(
                "state {} is not among the states of {native:?}",
                unknown["fields"]["System.State"]
            ));
        }
        if !self.counts {
            return Err("the source did not report comment counts".into());
        }
        let Some(batch) = batch else {
            return Err("its links were not read".into());
        };
        if let Some(reason) = batch.contents.termination.gap() {
            return Err(format!("its links could not be read ({reason})"));
        }
        if !self.links.contains_key(&id) {
            return Err("the source did not return its links".into());
        }
        Ok(())
    }
}

/// a pull request the source links to a work item.
fn linked_pull(
    project: &Entity,
    project_id: &str,
    repositories: &BTreeMap<String, String>,
    relation: &Value,
) -> Option<Reference> {
    if relation["rel"] != "ArtifactLink" {
        return None;
    }
    // vstfs:///Git/PullRequestId/<project id>%2F<repository id>%2F<number>
    let path = relation["url"]
        .as_str()?
        .strip_prefix("vstfs:///Git/PullRequestId/")?
        .replace("%2f", "%2F");
    let mut parts = path.split("%2F");
    let (linked_project, repository, number) = (parts.next()?, parts.next()?, parts.next()?);
    let number = number.parse::<u64>().ok()?;
    let same_scope = linked_project.eq_ignore_ascii_case(project_id);
    let organisation = project.name.split('/').next().unwrap_or_default();
    let name = match repositories.get(&repository.to_ascii_lowercase()) {
        Some(repository) if same_scope => format!("{}/{repository}!{number}", project.name),
        _ => format!("{organisation}!{number}"),
    };
    Some(Reference {
        kind: kind::CHANGE,
        native_kind: "pull request",
        id: number.to_string(),
        name,
        same_scope,
        basis: relation::LINK,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn times_are_written_to_the_millisecond() {
        for (written, expected) in [
            ("2026-02-18T04:35:01.9643061Z", "2026-02-18T04:35:01.964Z"),
            ("2026-02-18T04:35:03.63Z", "2026-02-18T04:35:03.630Z"),
            ("2026-02-18T04:35:03Z", "2026-02-18T04:35:03.000Z"),
            ("2026-02-18T05:35:03+01:00", "2026-02-18T04:35:03.000Z"),
        ] {
            assert_eq!(moment(&json!(written)).as_deref(), Some(expected));
        }
        assert_eq!(moment(&json!("0001-01-01T00:00:00")), None);
    }

    #[test]
    fn votes_are_read_as_numbers_or_text() {
        assert_eq!(vote(&json!("10")), Some(10));
        assert_eq!(vote(&json!(-5)), Some(-5));
        assert_eq!(vote(&json!("approved")), None);
    }
}
