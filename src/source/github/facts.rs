//! what github transcripts say.
//!
//! every function here reads retained bodies and makes no requests.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::capture::{BRANCH_PROTECTION, BRANCH_RULES, ORGANISATION, REPOSITORIES, REPOSITORY};
use super::HOST;
use crate::error::{Error, Result};
use crate::model::{aspect, kind, Derived, Entity, Reading, Statement};
use crate::source::build::{self, find, items, not_expected, peek, single, state};
use crate::source::work::Work;
use crate::transcript::{Termination, Transcript};

/// a repository named by an organisation listing.
pub struct Listed {
    pub name: String,
    pub default_branch: String,
}

/// the repositories a listing transcript names, in the order they were listed.
#[must_use]
pub fn listed(listing: &Transcript) -> Vec<Listed> {
    items(listing)
        .iter()
        .filter_map(|repository| {
            Some(Listed {
                name: repository["name"].as_str()?.to_owned(),
                default_branch: repository["default_branch"].as_str()?.to_owned(),
            })
        })
        .collect()
}

/// the default branch a repository transcript names.
#[must_use]
pub fn default_branch(repository: &Transcript) -> Option<String> {
    peek(repository)?["default_branch"]
        .as_str()
        .map(str::to_owned)
}

/// derive everything the transcripts of one github reading say.
///
/// # Errors
///
/// returns an error when the reading has neither a repository listing nor a
/// repository, a branch has only one of its two transcripts or is not among
/// the repositories read, or a retained body is not json.
pub fn derive(transcripts: &[Transcript]) -> Result<Derived> {
    if let Some(listing) = find(transcripts, REPOSITORIES) {
        derive_organisation(listing, transcripts)
    } else if let Some(about) = find(transcripts, REPOSITORY) {
        derive_repository(about, transcripts)
    } else {
        Err(Error::Invalid(
            "a github reading has neither a repository listing nor a repository".into(),
        ))
    }
}

/// one repository, read on its own, with its tickets and changes.
fn derive_repository(about: &Transcript, transcripts: &[Transcript]) -> Result<Derived> {
    let name = about.contents.subject.clone();
    let mut derived = Derived::default();
    let mut repositories = BTreeMap::new();
    let entity = if let Some(reason) = about.contents.termination.gap() {
        let entity = HOST.unresolved(kind::REPOSITORY, "repository", &name);
        derived.statements.push(state(
            &entity.uid,
            aspect::REPOSITORY,
            Reading::gap(reason),
            &[about],
        ));
        entity
    } else {
        let repository = single(about)?;
        let id = repository["id"]
            .as_u64()
            .ok_or_else(|| not_expected(about, "a repository id"))?;
        let owner = &repository["owner"];
        let parent = owner["id"].as_u64().map(|owner_id| {
            let native = match owner["type"].as_str() {
                Some("User") => "user",
                _ => "organisation",
            };
            let login = owner["login"].as_str().unwrap_or_default();
            HOST.scope(
                kind::ORGANISATION,
                native,
                &owner_id.to_string(),
                format!("github:{login}"),
                None,
            )
        });
        let entity = HOST.scope(
            kind::REPOSITORY,
            "repository",
            &id.to_string(),
            name,
            parent.as_ref().map(|parent| parent.uid.clone()),
        );
        derived.entities.extend(parent);
        derived
            .statements
            .push(repository_statement(&entity.uid, &repository, about)?);
        repositories.insert(entity.name.clone(), (entity.uid.clone(), id));
        entity
    };
    branches(transcripts, &repositories, &mut derived)?;
    let default = default_branch(about);
    let branches = derived
        .entities
        .iter()
        .filter(|entity| entity.kind == kind::BRANCH)
        .cloned()
        .collect::<Vec<_>>();
    let mut work = Work::new(&HOST, &entity, &mut derived);
    super::work::derive(&entity, default.as_deref(), transcripts, &mut work)?;
    super::releases::derive(&entity, transcripts, &mut work)?;
    if let Some((_, id)) = repositories.get(&entity.name) {
        super::findings::derive(&entity, *id, transcripts, &mut work)?;
    }
    for branch in &branches {
        super::updates::derive(branch, transcripts, &mut work)?;
    }
    work.finish();
    derived.entities.push(entity);
    Ok(derived)
}

fn repository_statement(about: &str, repository: &Value, from: &Transcript) -> Result<Statement> {
    let reading = Reading::recorded(json!({
        "visibility": repository["visibility"],
        "archived": repository["archived"],
        "fork": repository["fork"],
        "default_branch": repository["default_branch"],
    }))?;
    Ok(state(about, aspect::REPOSITORY, reading, &[from]))
}

/// an organisation: its repositories, and the default branch of each.
fn derive_organisation(listing: &Transcript, transcripts: &[Transcript]) -> Result<Derived> {
    let organisation = find(transcripts, ORGANISATION);
    let repositories = items(listing);
    let root = organisation_entity(organisation, listing, &repositories);
    let mut derived = Derived::default();
    let mut by_name = BTreeMap::new();
    for repository in &repositories {
        let (Some(id), Some(name)) = (repository["id"].as_u64(), repository["name"].as_str())
        else {
            continue;
        };
        let entity = HOST.scope(
            kind::REPOSITORY,
            "repository",
            &id.to_string(),
            format!("{}/{name}", root.name),
            Some(root.uid.clone()),
        );
        derived
            .statements
            .push(repository_statement(&entity.uid, repository, listing)?);
        by_name.insert(entity.name.clone(), (entity.uid.clone(), id));
        derived.entities.push(entity);
    }
    derived
        .statements
        .push(population(&root, organisation, listing, &by_name)?);
    derived.entities.push(root);
    branches(transcripts, &by_name, &mut derived)?;
    Ok(derived)
}

/// the default branch of each repository read, and what the source says of it.
fn branches(
    transcripts: &[Transcript],
    repositories: &BTreeMap<String, (String, u64)>,
    derived: &mut Derived,
) -> Result<()> {
    // the two readings of each branch, by repository and branch.
    let mut read = BTreeMap::<(&str, &str), (Option<&Transcript>, Option<&Transcript>)>::new();
    for transcript in transcripts {
        let key = (
            transcript.contents.subject.as_str(),
            transcript.parameter("branch").unwrap_or_default(),
        );
        match transcript.contents.resource.as_str() {
            BRANCH_PROTECTION => read.entry(key).or_default().0 = Some(transcript),
            BRANCH_RULES => read.entry(key).or_default().1 = Some(transcript),
            _ => {}
        }
    }
    for ((subject, name), pair) in read {
        let (Some(protection), Some(rules)) = pair else {
            return Err(Error::Invalid(format!(
                "{subject}: branch protection and branch rules must be read together"
            )));
        };
        let Some((repository, id)) = repositories.get(subject) else {
            return Err(Error::Invalid(format!(
                "{subject} is not among the repositories read"
            )));
        };
        let branch = HOST.scope(
            kind::BRANCH,
            "branch",
            &format!("{id}/{name}"),
            format!("{subject}@{name}"),
            Some(repository.clone()),
        );
        derived
            .statements
            .extend(branch_statements(&branch.uid, name, protection, rules)?);
        derived.entities.push(branch);
    }
    Ok(())
}

/// the organisation, identified by the id it reports, or by the owner id of a
/// repository it lists. when neither was read, it has no stable identity.
fn organisation_entity(
    organisation: Option<&Transcript>,
    listing: &Transcript,
    repositories: &[Value],
) -> Entity {
    let reported = organisation
        .and_then(peek)
        .and_then(|body| body["id"].as_u64());
    let owner = || {
        repositories
            .iter()
            .find_map(|repository| repository["owner"]["id"].as_u64())
    };
    let name = listing.contents.subject.as_str();
    match reported.or_else(owner) {
        Some(id) => HOST.scope(
            kind::ORGANISATION,
            "organisation",
            &id.to_string(),
            name,
            None,
        ),
        None => HOST.unresolved(kind::ORGANISATION, "organisation", name),
    }
}

fn population(
    root: &Entity,
    organisation: Option<&Transcript>,
    listing: &Transcript,
    by_name: &BTreeMap<String, (String, u64)>,
) -> Result<Statement> {
    let members = by_name
        .values()
        .map(|(uid, _)| uid.clone())
        .collect::<Vec<_>>();
    let mut statement = build::population(
        &root.uid,
        aspect::REPOSITORIES,
        kind::REPOSITORY,
        None,
        &members,
        &[listing],
    )?;
    if statement.reading.value().is_some() {
        statement.note = population_note(organisation, by_name.len());
        if let Some(organisation) = organisation {
            statement.transcripts.insert(0, organisation.id.clone());
        }
    }
    Ok(statement)
}

/// say what the listing cannot establish about the whole population.
///
/// the listing holds what the credential can see. it is the whole population
/// only when the organisation reports the same number of repositories.
fn population_note(organisation: Option<&Transcript>, listed: usize) -> Option<String> {
    let reported = organisation
        .filter(|transcript| transcript.contents.termination == Termination::Exhausted)
        .and_then(peek)
        .and_then(|body| {
            Some(body["public_repos"].as_u64()? + body["total_private_repos"].as_u64()?)
        });
    match reported {
        Some(reported) if usize::try_from(reported).ok() == Some(listed) => None,
        Some(reported) => Some(format!(
            "{listed} listed, but the organisation reports {reported}"
        )),
        None => Some(
            "the organisation did not report its private repository count to this credential, \
             so repositories may be missing"
                .into(),
        ),
    }
}

fn branch_statements(
    about: &str,
    branch: &str,
    protection: &Transcript,
    rules: &Transcript,
) -> Result<Vec<Statement>> {
    let protection_reading = protection_reading(protection, branch)?;
    let rules_reading = rules_reading(rules, branch)?;
    // github applies classic protection and rulesets together, so what one of
    // them requires holds even when the other could not be read. the note
    // then says that more may apply.
    let unread = [
        (aspect::BRANCH_PROTECTION, &protection_reading),
        (aspect::BRANCH_RULES, &rules_reading),
    ]
    .iter()
    .filter_map(|(aspect, reading)| {
        let reason = reading.gap_reason()?;
        Some(format!("{aspect} could not be read ({reason})"))
    })
    .collect::<Vec<_>>();
    let empty = json!({});
    let (review, checks, note) = if unread.len() == 2 {
        let reason = unread.join("; ");
        (Reading::gap(reason.clone()), Reading::gap(reason), None)
    } else {
        let protection = protection_reading.value().unwrap_or(&empty);
        let rules = rules_reading.value().unwrap_or(&empty);
        (
            Reading::recorded(json!({
                "branch": branch,
                "requirements": review_requirements(protection, rules),
            }))?,
            Reading::recorded(json!({
                "branch": branch,
                "checks": required_checks(protection, rules),
            }))?,
            unread
                .first()
                .map(|unread| format!("{unread}, so more may be required")),
        )
    };
    let noted = |aspect: &str, reading, from: &[&Transcript]| {
        let mut statement = state(about, aspect, reading, from);
        statement.note.clone_from(&note);
        statement
    };
    Ok(vec![
        state(
            about,
            aspect::BRANCH_PROTECTION,
            protection_reading,
            &[protection],
        ),
        state(about, aspect::BRANCH_RULES, rules_reading, &[rules]),
        noted(aspect::REVIEW_POLICY, review, &[protection, rules]),
        noted(aspect::REQUIRED_CHECKS, checks, &[protection, rules]),
    ])
}

fn protection_reading(transcript: &Transcript, branch: &str) -> Result<Reading> {
    match &transcript.contents.termination {
        Termination::Exhausted => Reading::recorded(json!({
            "branch": branch,
            "protected": true,
            "settings": without_urls(&single(transcript)?),
        })),
        // github answers 404 with this message when it can see the branch and
        // the branch has no classic protection. any other 404 is not an answer.
        Termination::NotFound { diagnostic } if diagnostic.ends_with("Branch not protected") => {
            Reading::recorded(json!({ "branch": branch, "protected": false }))
        }
        other => Ok(Reading::gap(other.gap().unwrap_or_default())),
    }
}

fn rules_reading(transcript: &Transcript, branch: &str) -> Result<Reading> {
    if let Some(reason) = transcript.contents.termination.gap() {
        return Ok(Reading::gap(reason));
    }
    let mut rules = build::list(transcript)?;
    rules.sort_by_key(|rule| {
        (
            rule["type"].as_str().map(str::to_owned),
            rule["ruleset_id"].as_u64(),
            rule.to_string(),
        )
    });
    Reading::recorded(json!({ "branch": branch, "rules": rules }))
}

fn review_requirements(protection: &Value, rules: &Value) -> Vec<Value> {
    let mut requirements = Vec::new();
    let reviews = &protection["settings"]["required_pull_request_reviews"];
    if reviews.is_object() {
        requirements.push(json!({
            "source": "branch protection",
            "required_approvals": reviews["required_approving_review_count"],
            "dismiss_stale_reviews": reviews["dismiss_stale_reviews"],
            "require_code_owner_review": reviews["require_code_owner_reviews"],
            "require_last_push_approval": reviews["require_last_push_approval"],
        }));
    }
    for rule in rules_of_type(rules, "pull_request") {
        let parameters = &rule["parameters"];
        requirements.push(json!({
            "source": ruleset(rule),
            "required_approvals": parameters["required_approving_review_count"],
            "dismiss_stale_reviews": parameters["dismiss_stale_reviews_on_push"],
            "require_code_owner_review": parameters["require_code_owner_review"],
            "require_last_push_approval": parameters["require_last_push_approval"],
        }));
    }
    requirements
}

fn required_checks(protection: &Value, rules: &Value) -> Vec<Value> {
    let mut checks = Vec::new();
    let classic = &protection["settings"]["required_status_checks"];
    let mut contexts = classic["checks"]
        .as_array()
        .map(|checks| {
            checks
                .iter()
                .filter_map(|check| check["context"].as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if contexts.is_empty() {
        contexts = classic["contexts"]
            .as_array()
            .map(|contexts| contexts.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
    }
    for context in contexts {
        checks.push(json!({ "context": context, "source": "branch protection" }));
    }
    for rule in rules_of_type(rules, "required_status_checks") {
        let required = rule["parameters"]["required_status_checks"].as_array();
        for check in required.into_iter().flatten() {
            if let Some(context) = check["context"].as_str() {
                checks.push(json!({ "context": context, "source": ruleset(rule) }));
            }
        }
    }
    checks.sort_by_key(|check| {
        (
            check["context"].as_str().map(str::to_owned),
            check["source"].as_str().map(str::to_owned),
        )
    });
    checks
}

fn rules_of_type<'a>(rules: &'a Value, kind: &'a str) -> impl Iterator<Item = &'a Value> {
    rules["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(move |rule| rule["type"].as_str() == Some(kind))
}

/// name a ruleset by where it is defined and its id.
fn ruleset(rule: &Value) -> String {
    let level = match rule["ruleset_source_type"].as_str() {
        Some("Organization") => "organisation ruleset",
        Some("Enterprise") => "enterprise ruleset",
        _ => "ruleset",
    };
    match rule["ruleset_id"].as_u64() {
        Some(id) => format!("{level} {id}"),
        None => level.into(),
    }
}

/// drop the api links github adds to every object. they say nothing about the setting.
fn without_urls(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .filter(|(name, _)| *name != "url" && !name.ends_with("_url"))
                .map(|(name, value)| (name.clone(), without_urls(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_urls).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::summary;
    use crate::transcript::{exchange, seal, TranscriptContents};

    // the two bodies below are what github returned for this repository's
    // main branch on 2026-11-24.
    const PROTECTION: &str = r#"{"url":"https://api.github.com/repos/cyberwitchery/divinate/branches/main/protection","required_pull_request_reviews":{"url":"https://api.github.com/repos/cyberwitchery/divinate/branches/main/protection/required_pull_request_reviews","dismiss_stale_reviews":true,"require_code_owner_reviews":false,"require_last_push_approval":false,"required_approving_review_count":1},"required_signatures":{"url":"https://api.github.com/repos/cyberwitchery/divinate/branches/main/protection/required_signatures","enabled":false},"enforce_admins":{"url":"https://api.github.com/repos/cyberwitchery/divinate/branches/main/protection/enforce_admins","enabled":false},"required_linear_history":{"enabled":false},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false},"block_creations":{"enabled":false},"required_conversation_resolution":{"enabled":false},"lock_branch":{"enabled":false},"allow_fork_syncing":{"enabled":false}}"#;
    const RULES: &str = r#"[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,"do_not_enforce_on_create":false,"required_status_checks":[{"context":"success","integration_id":15368}]},"ruleset_source_type":"Repository","ruleset_source":"cyberwitchery/divinate","ruleset_id":26609762},{"type":"deletion","ruleset_source_type":"Repository","ruleset_source":"cyberwitchery/divinate","ruleset_id":25620041},{"type":"non_fast_forward","ruleset_source_type":"Repository","ruleset_source":"cyberwitchery/divinate","ruleset_id":25620041}]"#;
    const LISTING: &str = r#"[{"id":2,"name":"tools","owner":{"id":9},"visibility":"public","archived":false,"fork":false,"default_branch":"main"},{"id":1,"name":"service","owner":{"id":9},"visibility":"private","archived":true,"fork":false,"default_branch":"main"}]"#;
    const BRANCH: &str = "github.com/branch/1/main";

    fn transcript(
        resource: &str,
        subject: &str,
        body: &str,
        termination: Termination,
    ) -> Transcript {
        seal(TranscriptContents {
            resource: resource.into(),
            subject: subject.into(),
            parameters: BTreeMap::from([("branch".into(), "main".into())]),
            captured_at: "2026-11-24T10:00:00Z".into(),
            exchanges: vec![exchange(
                "https://api.github.com/",
                if termination == Termination::Exhausted {
                    200
                } else {
                    404
                },
                BTreeMap::new(),
                body.into(),
            )],
            termination,
        })
        .unwrap()
    }

    fn listing() -> Transcript {
        transcript(
            REPOSITORIES,
            "github:example",
            LISTING,
            Termination::Exhausted,
        )
    }

    /// derive one branch of `service` from how its two readings ended.
    fn branch(protection: (&str, Termination), rules: (&str, Termination)) -> Derived {
        let subject = "github:example/service";
        derive(&[
            listing(),
            transcript(BRANCH_PROTECTION, subject, protection.0, protection.1),
            transcript(BRANCH_RULES, subject, rules.0, rules.1),
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

    fn read(body: &str) -> (&str, Termination) {
        (body, Termination::Exhausted)
    }

    fn hidden() -> (&'static str, Termination) {
        let diagnostic = "HTTP 404: Not Found".into();
        ("{}", Termination::NotFound { diagnostic })
    }

    #[test]
    fn review_comes_from_protection_and_checks_from_a_ruleset() {
        let derived = branch(read(PROTECTION), read(RULES));
        assert_eq!(
            summaries(&derived),
            [
                "protected",
                "deletion, non_fast_forward, required_status_checks",
                "1 approval (branch protection)",
                "success (ruleset 26609762)",
            ]
        );
        let protection = derived
            .statement(BRANCH, aspect::BRANCH_PROTECTION)
            .unwrap();
        let settings = &protection.reading.value().unwrap()["settings"];
        assert!(settings.get("url").is_none());
        assert!(settings["required_pull_request_reviews"]
            .get("url")
            .is_none());
    }

    #[test]
    fn an_unprotected_branch_is_recorded_and_is_not_a_gap() {
        let diagnostic = "HTTP 404: Branch not protected".into();
        let derived = branch(("{}", Termination::NotFound { diagnostic }), read("[]"));
        assert_eq!(
            summaries(&derived),
            [
                "not protected",
                "no rules",
                "no review required",
                "none required"
            ]
        );
    }

    #[test]
    fn what_one_mechanism_requires_is_recorded_when_the_other_is_unreadable() {
        let enterprise = r#"[{"type":"pull_request","parameters":{"required_approving_review_count":1},"ruleset_source_type":"Enterprise","ruleset_id":25707624}]"#;
        let derived = branch(hidden(), read(enterprise));
        let found = summaries(&derived);
        assert!(found[0].starts_with("gap: not found, or not visible"));
        assert_eq!(found[2], "1 approval (enterprise ruleset 25707624)");
        assert_eq!(found[3], "none required");
        let review = derived.statement(BRANCH, aspect::REVIEW_POLICY).unwrap();
        let note = review.note.as_deref().unwrap();
        assert!(note.starts_with("branch protection could not be read"));
        assert!(note.ends_with("so more may be required"));
    }

    #[test]
    fn a_policy_is_a_gap_only_when_neither_mechanism_was_read() {
        let derived = branch(hidden(), hidden());
        let found = summaries(&derived);
        assert!(found[2].starts_with("gap: branch protection could not be read"));
        assert!(found[2].contains("; branch rules could not be read"));
        assert!(found[3].starts_with("gap: "));
    }

    #[test]
    fn entities_are_identified_by_the_ids_github_reports() {
        let derived = branch(read(PROTECTION), read(RULES));
        // the organisation response was not read, so a repository's owner id names it.
        let organisation = derived.named("github:example").unwrap();
        assert_eq!(organisation.uid, "github.com/organisation/9");
        let service = derived.named("github:example/service").unwrap();
        assert_eq!(service.uid, "github.com/repository/1");
        assert_eq!(service.parent.as_deref(), Some("github.com/organisation/9"));
        let main = derived.named("github:example/service@main").unwrap();
        assert_eq!((main.uid.as_str(), main.kind.as_str()), (BRANCH, "branch"));
        assert_eq!(main.parent.as_deref(), Some("github.com/repository/1"));
        let about = derived.statement(&service.uid, aspect::REPOSITORY).unwrap();
        assert_eq!(summary(about), "private, default branch main, archived");
    }

    #[test]
    fn the_listing_is_the_population_only_when_the_organisation_agrees() {
        let note = |body: &str| {
            let organisation =
                transcript(ORGANISATION, "github:example", body, Termination::Exhausted);
            let derived = derive(&[organisation, listing()]).unwrap();
            let listed = derived
                .statement("github.com/organisation/9", aspect::REPOSITORIES)
                .unwrap();
            assert_eq!(summary(listed), "2 repositories");
            assert_eq!(
                listed.reading.value().unwrap()["members"],
                json!(["github.com/repository/1", "github.com/repository/2"])
            );
            listed.note.clone()
        };
        assert_eq!(
            note(r#"{"id":9,"public_repos":1,"total_private_repos":1}"#),
            None
        );
        assert_eq!(
            note(r#"{"id":9,"public_repos":1,"total_private_repos":4}"#).as_deref(),
            Some("2 listed, but the organisation reports 5")
        );
        assert!(note(r#"{"id":9,"public_repos":1}"#)
            .unwrap()
            .contains("may be missing"));
    }
}
