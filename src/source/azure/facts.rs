//! what azure devops transcripts say.
//!
//! every function here reads retained bodies and makes no requests.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::capture::{BRANCH_POLICIES, ORGANISATION, PROJECT, PROJECTS, REPOSITORIES};
use super::HOST;
use crate::error::{Error, Result};
use crate::model::{aspect, kind, Derived, Entity, Reading, Statement};
use crate::source::build::{self, all, find, not_expected, peek, single, state};
use crate::source::work::Work;
use crate::transcript::Transcript;
/// the policy type that requires a number of approvals.
const MINIMUM_REVIEWERS: &str = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd";
/// the policy type that requires a build to pass.
pub(super) const BUILD_VALIDATION: &str = "0609b952-1397-4640-95ec-e00a01b2c241";

/// a repository named by a project's listing.
pub struct Listed {
    pub id: String,
    pub name: String,
    /// absent for an empty repository.
    pub default_branch: Option<String>,
}

/// the repositories a listing names, in the order they were listed. one whose
/// id is not the kind the source issues is left out, so no request is built
/// from it.
#[must_use]
pub fn listed(listing: &Transcript) -> Vec<Listed> {
    values(listing)
        .iter()
        .filter_map(|repository| {
            Some(Listed {
                id: repository["id"]
                    .as_str()
                    .filter(|id| is_uuid(id))?
                    .to_owned(),
                name: repository["name"].as_str()?.to_owned(),
                default_branch: branch_name(&repository["defaultBranch"]),
            })
        })
        .collect()
}

fn branch_name(reference: &Value) -> Option<String> {
    Some(reference.as_str()?.strip_prefix("refs/heads/")?.to_owned())
}

/// the items of a list reading: azure devops wraps every list in an object.
pub(super) fn values(listing: &Transcript) -> Vec<Value> {
    listing
        .bodies()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .filter_map(|mut page| match page["value"].take() {
            Value::Array(items) => Some(items),
            _ => match page["values"].take() {
                Value::Array(items) => Some(items),
                _ => None,
            },
        })
        .flatten()
        .collect()
}

/// the id of the project a transcript holds, if it holds one.
pub(super) fn project_id(about: &Transcript) -> Option<String> {
    let id = peek(about)?["id"].as_str()?.to_owned();
    is_uuid(&id).then_some(id)
}

pub(super) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// derive everything the transcripts of one azure devops reading say.
///
/// # Errors
///
/// returns an error when the reading has neither a project listing nor a
/// project, a branch is not among the repositories read, or a retained body
/// is not what its resource returns.
pub fn derive(transcripts: &[Transcript]) -> Result<Derived> {
    let connection = find(transcripts, ORGANISATION);
    let mut derived = Derived::default();
    if let Some(about) = find(transcripts, PROJECT) {
        let organisation = organisation(connection, parent_name(&about.contents.subject));
        derive_project(about, &organisation, transcripts, &mut derived)?;
        derived.entities.push(organisation);
    } else if let Some(listing) = find(transcripts, PROJECTS) {
        let organisation = organisation(connection, &listing.contents.subject);
        derive_organisation(listing, &organisation, transcripts, &mut derived)?;
        derived.entities.push(organisation);
    } else {
        return Err(Error::Invalid(
            "an azure devops reading has neither a project listing nor a project".into(),
        ));
    }
    Ok(derived)
}

/// `azure:organisation` from `azure:organisation/project`.
fn parent_name(name: &str) -> &str {
    name.split_once('/').map_or(name, |(parent, _)| parent)
}

/// the organisation, identified by the id its connection reports. when that
/// was not read, it has no stable identity.
fn organisation(connection: Option<&Transcript>, name: &str) -> Entity {
    let id = connection
        .and_then(peek)
        .and_then(|body| body["instanceId"].as_str().map(str::to_owned));
    match id {
        Some(id) => HOST.scope(kind::ORGANISATION, "organization", &id, name, None),
        None => HOST.unresolved(kind::ORGANISATION, "organization", name),
    }
}

fn project_statement(about: &str, project: &Value, from: &Transcript) -> Result<Statement> {
    let reading = Reading::recorded(json!({
        "visibility": project["visibility"],
        "state": project["state"],
    }))?;
    Ok(state(about, aspect::PROJECT, reading, &[from]))
}

/// a population as azure devops lists it: what this credential can see.
fn visible(
    about: &Entity,
    aspect: &str,
    of: &str,
    members: &[String],
    listing: &Transcript,
) -> Result<Statement> {
    let mut statement = build::population(&about.uid, aspect, of, None, members, &[listing])?;
    if statement.reading.value().is_some() {
        statement.note = Some(format!(
            "azure devops lists the {aspect} this credential can see, so others may be missing"
        ));
    }
    Ok(statement)
}

/// an organisation: its projects, their repositories, and the default branch of each.
fn derive_organisation(
    listing: &Transcript,
    organisation: &Entity,
    transcripts: &[Transcript],
    derived: &mut Derived,
) -> Result<()> {
    let mut members = Vec::new();
    for project in values(listing) {
        let (Some(id), Some(name)) = (project["id"].as_str(), project["name"].as_str()) else {
            continue;
        };
        let entity = HOST.scope(
            kind::PROJECT,
            "project",
            id,
            format!("{}/{name}", organisation.name),
            Some(organisation.uid.clone()),
        );
        derived
            .statements
            .push(project_statement(&entity.uid, &project, listing)?);
        repositories(&entity, transcripts, derived)?;
        members.push(entity.uid.clone());
        derived.entities.push(entity);
    }
    derived.statements.push(visible(
        organisation,
        aspect::PROJECTS,
        kind::PROJECT,
        &members,
        listing,
    )?);
    Ok(())
}
/// one project, read on its own, with its tickets and changes.
fn derive_project(
    about: &Transcript,
    organisation: &Entity,
    transcripts: &[Transcript],
    derived: &mut Derived,
) -> Result<()> {
    let name = about.contents.subject.clone();
    let parent = Some(organisation.uid.clone());
    if let Some(reason) = about.contents.termination.gap() {
        let mut entity = HOST.unresolved(kind::PROJECT, "project", &name);
        entity.parent = parent;
        derived.statements.push(state(
            &entity.uid,
            aspect::PROJECT,
            Reading::gap(reason),
            &[about],
        ));
        derived.entities.push(entity);
        return Ok(());
    }
    let project = single(about)?;
    let id = project["id"]
        .as_str()
        .ok_or_else(|| not_expected(about, "a project id"))?;
    let entity = HOST.scope(kind::PROJECT, "project", id, name, parent);
    derived
        .statements
        .push(project_statement(&entity.uid, &project, about)?);
    let names = repositories(&entity, transcripts, derived)?;
    let branches = derived
        .entities
        .iter()
        .filter(|entity| entity.kind == kind::BRANCH)
        .cloned()
        .collect::<Vec<_>>();
    let mut work = Work::new(&HOST, &entity, derived);
    super::work::derive(&entity, id, &names, transcripts, &mut work)?;
    super::work::updates(&branches, transcripts, &mut work)?;
    work.finish();
    derived.entities.push(entity);
    Ok(())
}

/// the repositories of one project and the default branch of each. returns
/// the name of each repository by its id.
fn repositories(
    project: &Entity,
    transcripts: &[Transcript],
    derived: &mut Derived,
) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    let Some(listing) = all(transcripts, REPOSITORIES)
        .find(|transcript| transcript.contents.subject == project.name)
    else {
        return Ok(names);
    };
    let mut members = Vec::new();
    for repository in values(listing) {
        let (Some(id), Some(name)) = (repository["id"].as_str(), repository["name"].as_str())
        else {
            continue;
        };
        let entity = HOST.scope(
            kind::REPOSITORY,
            "repository",
            id,
            format!("{}/{name}", project.name),
            Some(project.uid.clone()),
        );
        // a repository is as visible as its project.
        let reading = Reading::recorded(json!({
            "visibility": repository["project"]["visibility"],
            "archived": repository["isDisabled"],
            "fork": repository["isFork"] == Value::Bool(true),
            "default_branch": branch_name(&repository["defaultBranch"]),
        }))?;
        derived
            .statements
            .push(state(&entity.uid, aspect::REPOSITORY, reading, &[listing]));
        names.insert(id.to_owned(), name.to_owned());
        members.push(entity.uid.clone());
        derived.entities.push(entity);
    }
    derived.statements.push(visible(
        project,
        aspect::REPOSITORIES,
        kind::REPOSITORY,
        &members,
        listing,
    )?);
    let prefix = format!("{}/", project.name);
    for policies in all(transcripts, BRANCH_POLICIES).filter(|transcript| {
        transcript
            .contents
            .subject
            .strip_prefix(&prefix)
            .is_some_and(|repository| !repository.contains('/'))
    }) {
        let subject = &policies.contents.subject;
        let Some(repository) = derived.named(subject).map(|entity| entity.uid.clone()) else {
            return Err(Error::Invalid(format!(
                "{subject} is not among the repositories read"
            )));
        };
        let name = policies.parameter("branch").unwrap_or_default();
        let id = repository.rsplit('/').next().unwrap_or_default();
        let branch = HOST.scope(
            kind::BRANCH,
            "branch",
            &format!("{id}/{name}"),
            format!("{subject}@{name}"),
            Some(repository.clone()),
        );
        derived
            .statements
            .extend(branch_statements(&branch.uid, name, policies)?);
        derived.entities.push(branch);
    }
    Ok(names)
}

/// what the policies on a branch require. azure devops selects the policies
/// that apply to the branch itself, including those set for a whole project.
fn branch_statements(about: &str, branch: &str, policies: &Transcript) -> Result<Vec<Statement>> {
    let statement = |aspect: &str, reading| state(about, aspect, reading, &[policies]);
    if let Some(reason) = policies.contents.termination.gap() {
        return Ok([
            aspect::BRANCH_RULES,
            aspect::REVIEW_POLICY,
            aspect::REQUIRED_CHECKS,
        ]
        .iter()
        .map(|aspect| statement(aspect, Reading::gap(reason.clone())))
        .collect());
    }
    let mut found = values(policies)
        .into_iter()
        .filter(|policy| policy["isDeleted"] != Value::Bool(true))
        .collect::<Vec<_>>();
    found.sort_by_key(|policy| {
        (
            policy["type"]["displayName"].as_str().map(str::to_owned),
            policy["id"].as_u64(),
        )
    });
    // a policy holds a merge back only when it is enabled and blocking. one
    // that is enabled and not blocking is advice.
    let binding = |policy: &&Value| {
        policy["isEnabled"] == Value::Bool(true) && policy["isBlocking"] == Value::Bool(true)
    };
    let mut requirements = Vec::new();
    let mut checks = Vec::new();
    for policy in found.iter().filter(binding) {
        let settings = &policy["settings"];
        let source = format!("policy {}", policy["id"]);
        match policy["type"]["id"].as_str() {
            Some(MINIMUM_REVIEWERS) => requirements.push(json!({
                "source": source,
                "required_approvals": settings["minimumApproverCount"],
                "author_may_approve": settings["creatorVoteCounts"],
                "reset_approvals_on_push": settings["resetOnSourcePush"],
                "last_pusher_may_not_approve": settings["blockLastPusherVote"],
            })),
            Some(BUILD_VALIDATION) => checks.push(json!({
                "context": settings["displayName"].as_str().map_or_else(
                    || format!("build definition {}", settings["buildDefinitionId"]),
                    str::to_owned,
                ),
                "source": source,
            })),
            _ => {
                if let Some(status) = settings["statusName"].as_str() {
                    let context = match settings["statusGenre"].as_str() {
                        Some(genre) => format!("{genre}/{status}"),
                        None => status.to_owned(),
                    };
                    checks.push(json!({ "context": context, "source": source }));
                }
            }
        }
    }
    let rules = found
        .iter()
        .map(|policy| {
            json!({
                "type": policy["type"]["displayName"],
                "id": policy["id"],
                "enabled": policy["isEnabled"],
                "blocking": policy["isBlocking"],
                "settings": policy["settings"],
            })
        })
        .collect::<Vec<_>>();
    Ok(vec![
        statement(
            aspect::BRANCH_RULES,
            Reading::recorded(json!({ "branch": branch, "rules": rules }))?,
        ),
        statement(
            aspect::REVIEW_POLICY,
            Reading::recorded(json!({ "branch": branch, "requirements": requirements }))?,
        ),
        statement(
            aspect::REQUIRED_CHECKS,
            Reading::recorded(json!({ "branch": branch, "checks": checks }))?,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::summary;
    use crate::transcript::{exchange, seal, Termination, TranscriptContents};

    // the repository body is what dev.azure.com returned for a public project
    // on 2026-11-24, with names replaced. the policy bodies follow the shape
    // the earlier azure devops collector was written against.
    const REPOSITORIES_BODY: &str = r#"{"value":[{"id":"2459d599-fdb2-4d28-9810-daeec061cf90","name":"service","url":"https://dev.azure.com/example/cbb18261-c48f-4abb-8651-8cdcb5474649/_apis/git/repositories/2459d599-fdb2-4d28-9810-daeec061cf90","project":{"id":"cbb18261-c48f-4abb-8651-8cdcb5474649","name":"platform","state":"wellFormed","revision":31,"visibility":"private","lastUpdateTime":"2026-03-12T17:36:34.21Z"},"defaultBranch":"refs/heads/main","size":163841,"isDisabled":false,"isInMaintenance":false},{"id":"7f3a1c60-1d0e-4b55-9a57-0d2a2f3c9b11","name":"empty","project":{"id":"cbb18261-c48f-4abb-8651-8cdcb5474649","name":"platform","visibility":"private"},"size":0,"isDisabled":false}],"count":2}"#;
    const POLICIES: &str = r#"{"count":4,"value":[
        {"id":7,"isEnabled":true,"isBlocking":true,"isDeleted":false,"type":{"id":"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd","displayName":"Minimum number of reviewers"},"settings":{"minimumApproverCount":2,"creatorVoteCounts":false,"resetOnSourcePush":true,"scope":[{"repositoryId":"2459d599-fdb2-4d28-9810-daeec061cf90","refName":"refs/heads/main","matchKind":"Exact"}]}},
        {"id":9,"isEnabled":true,"isBlocking":true,"isDeleted":false,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"settings":{"buildDefinitionId":12,"displayName":"ci","scope":[{"repositoryId":null}]}},
        {"id":11,"isEnabled":true,"isBlocking":false,"isDeleted":false,"type":{"id":"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd","displayName":"Minimum number of reviewers"},"settings":{"minimumApproverCount":4}},
        {"id":12,"isEnabled":false,"isBlocking":true,"isDeleted":false,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"settings":{"buildDefinitionId":13}}
    ]}"#;
    const BRANCH: &str = "dev.azure.com/branch/2459d599-fdb2-4d28-9810-daeec061cf90/main";

    fn transcript(resource: &str, subject: &str, status: u16, body: &str) -> Transcript {
        let termination = match status {
            200 => Termination::Exhausted,
            _ => Termination::Unauthenticated {
                diagnostic: format!("HTTP {status}: TF400813"),
            },
        };
        seal(TranscriptContents {
            resource: resource.into(),
            subject: subject.into(),
            parameters: BTreeMap::from([("branch".into(), "main".into())]),
            captured_at: "2026-11-24T10:00:00Z".into(),
            exchanges: vec![exchange(
                "https://dev.azure.com/example/",
                status,
                BTreeMap::new(),
                body.into(),
            )],
            termination,
        })
        .unwrap()
    }

    fn organisation_reading(policies: (u16, &str)) -> Derived {
        crate::facts::derive(&[
            transcript(
                ORGANISATION,
                "azure:example",
                200,
                r#"{"instanceId":"b55de4ed-4b5a-4215-a8e4-0a0a5f71e7d8"}"#,
            ),
            transcript(
                PROJECTS,
                "azure:example",
                200,
                r#"{"count":1,"value":[{"id":"cbb18261-c48f-4abb-8651-8cdcb5474649","name":"platform","state":"wellFormed","visibility":"private"}]}"#,
            ),
            transcript(REPOSITORIES, "azure:example/platform", 200, REPOSITORIES_BODY),
            transcript(
                BRANCH_POLICIES,
                "azure:example/platform/service",
                policies.0,
                policies.1,
            ),
        ])
        .unwrap()
    }

    fn summaries(derived: &Derived) -> Vec<String> {
        derived
            .statements
            .iter()
            .filter(|statement| statement.about == BRANCH)
            .map(summary)
            .collect()
    }

    #[test]
    fn only_enabled_blocking_policies_are_requirements() {
        assert_eq!(
            summaries(&organisation_reading((200, POLICIES))),
            [
                "Build, Minimum number of reviewers",
                "2 approvals (policy 7)",
                "ci (policy 9)",
            ]
        );
    }

    #[test]
    fn a_branch_with_no_policies_requires_nothing() {
        assert_eq!(
            summaries(&organisation_reading((200, r#"{"count":0,"value":[]}"#))),
            ["no rules", "no review required", "none required"]
        );
    }

    #[test]
    fn unreadable_policies_are_three_gaps() {
        let found = summaries(&organisation_reading((401, "{}")));
        assert_eq!(found.len(), 3);
        assert!(found
            .iter()
            .all(|summary| summary.starts_with("gap: not authenticated")));
    }

    #[test]
    fn entities_are_identified_by_the_ids_azure_reports() {
        let derived = organisation_reading((200, POLICIES));
        let organisation = derived.named("azure:example").unwrap();
        assert_eq!(
            organisation.uid,
            "dev.azure.com/organisation/b55de4ed-4b5a-4215-a8e4-0a0a5f71e7d8"
        );
        let project = derived.named("azure:example/platform").unwrap();
        assert_eq!(
            (project.kind.as_str(), project.parent.as_deref()),
            ("project", Some(organisation.uid.as_str()))
        );
        let projects = derived
            .statement(&organisation.uid, aspect::PROJECTS)
            .unwrap();
        assert_eq!(summary(projects), "1 project");
        let listed = derived
            .statement(&project.uid, aspect::REPOSITORIES)
            .unwrap();
        assert_eq!(summary(listed), "2 repositories");
        assert!(listed.note.as_deref().unwrap().contains("may be missing"));
        let service = derived.named("azure:example/platform/service").unwrap();
        assert_eq!(service.parent.as_deref(), Some(project.uid.as_str()));
        let about = derived.statement(&service.uid, aspect::REPOSITORY).unwrap();
        assert_eq!(summary(about), "private, default branch main");
        assert_eq!(
            derived
                .named("azure:example/platform/service@main")
                .unwrap()
                .uid,
            BRANCH
        );
        // an empty repository is listed, and has no branch to say anything about.
        let empty = derived.named("azure:example/platform/empty").unwrap();
        let about = derived.statement(&empty.uid, aspect::REPOSITORY).unwrap();
        assert_eq!(summary(about), "private, no default branch");
    }
}
