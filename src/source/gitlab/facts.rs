//! what gitlab transcripts say.
//!
//! every function here reads retained bodies and makes no requests.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::capture::{
    APPROVAL_RULES, APPROVAL_SETTINGS, GROUP, PROJECT, PROJECTS, PROTECTED_BRANCHES,
};
use super::HOST;
use crate::error::{Error, Result};
use crate::model::{aspect, kind, Derived, Entity, Reading, Statement};
use crate::source::build::{self, find, items, list, not_expected, peek, single, state};
use crate::source::work::Work;
use crate::transcript::Transcript;

/// a project named by a group listing.
pub struct Listed {
    pub id: u64,
    /// the full path, such as `group/subgroup/project`.
    pub path: String,
    /// absent for a project with an empty repository.
    pub default_branch: Option<String>,
}

/// the projects a listing transcript names, in the order they were listed.
#[must_use]
pub fn listed(listing: &Transcript) -> Vec<Listed> {
    items(listing)
        .iter()
        .filter_map(|project| {
            Some(Listed {
                id: project["id"].as_u64()?,
                path: project["path_with_namespace"].as_str()?.to_owned(),
                default_branch: project["default_branch"].as_str().map(str::to_owned),
            })
        })
        .collect()
}

#[derive(Default)]
struct Project<'a> {
    protected: Option<&'a Transcript>,
    settings: Option<&'a Transcript>,
    rules: Option<&'a Transcript>,
}

/// the id and default branch a project transcript names.
#[must_use]
pub fn project_identity(project: &Transcript) -> Option<(u64, Option<String>)> {
    let body = peek(project)?;
    let branch = body["default_branch"].as_str().map(str::to_owned);
    Some((body["id"].as_u64()?, branch))
}

/// derive everything the transcripts of one gitlab reading say.
///
/// # Errors
///
/// returns an error when the reading has neither a project listing nor a
/// project, a project lacks one of its branch transcripts or is not among the
/// projects read, or a retained body is not json.
pub fn derive(transcripts: &[Transcript]) -> Result<Derived> {
    if let Some(listing) = find(transcripts, PROJECTS) {
        derive_group(listing, transcripts)
    } else if let Some(about) = find(transcripts, PROJECT) {
        derive_project(about, transcripts)
    } else {
        Err(Error::Invalid(
            "a gitlab reading has neither a project listing nor a project".into(),
        ))
    }
}

fn repository_statement(about: &str, project: &Value, from: &Transcript) -> Result<Statement> {
    let reading = Reading::recorded(json!({
        "visibility": project["visibility"],
        "archived": project["archived"],
        "fork": project.get("forked_from_project").is_some(),
        "default_branch": project["default_branch"],
    }))?;
    Ok(state(about, aspect::REPOSITORY, reading, &[from]))
}

/// one project, read on its own, with its tickets and changes.
fn derive_project(about: &Transcript, transcripts: &[Transcript]) -> Result<Derived> {
    let name = about.contents.subject.clone();
    let mut derived = Derived::default();
    if let Some(reason) = about.contents.termination.gap() {
        let entity = HOST.unresolved(kind::REPOSITORY, "project", &name);
        derived.statements.push(state(
            &entity.uid,
            aspect::REPOSITORY,
            Reading::gap(reason),
            &[about],
        ));
        derived.entities.push(entity);
        return Ok(derived);
    }
    let project = single(about)?;
    let id = project["id"]
        .as_u64()
        .ok_or_else(|| not_expected(about, "a project id"))?;
    let namespace = &project["namespace"];
    let parent = namespace["id"].as_u64().map(|namespace_id| {
        HOST.scope(
            kind::ORGANISATION,
            namespace["kind"].as_str().unwrap_or("group"),
            &namespace_id.to_string(),
            format!(
                "gitlab:{}",
                namespace["full_path"].as_str().unwrap_or_default()
            ),
            None,
        )
    });
    let entity = HOST.scope(
        kind::REPOSITORY,
        "project",
        &id.to_string(),
        name,
        parent.as_ref().map(|parent| parent.uid.clone()),
    );
    derived.entities.extend(parent);
    derived
        .statements
        .push(repository_statement(&entity.uid, &project, about)?);
    let by_name = BTreeMap::from([(entity.name.clone(), (id, &project))]);
    branches(
        transcripts,
        &by_name,
        about,
        &super::work::targets(transcripts),
        &mut derived,
    )?;
    let branches = derived
        .entities
        .iter()
        .filter(|entity| entity.kind == kind::BRANCH)
        .cloned()
        .collect::<Vec<_>>();
    let mut work = Work::new(&HOST, &entity, &mut derived);
    super::work::derive(
        &entity,
        id,
        project["default_branch"].as_str(),
        transcripts,
        &mut work,
    )?;
    for branch in &branches {
        super::work::updates(branch, transcripts, &mut work)?;
    }
    work.finish();
    derived.entities.push(entity);
    Ok(derived)
}

/// a group: its projects, and the default branch of each.
fn derive_group(listing: &Transcript, transcripts: &[Transcript]) -> Result<Derived> {
    let projects = items(listing);
    let root = group_entity(find(transcripts, GROUP), listing, &projects);
    let mut derived = Derived::default();
    let mut by_name = BTreeMap::new();
    for project in &projects {
        let (Some(id), Some(path)) = (
            project["id"].as_u64(),
            project["path_with_namespace"].as_str(),
        ) else {
            continue;
        };
        let entity = HOST.scope(
            kind::REPOSITORY,
            "project",
            &id.to_string(),
            format!("gitlab:{path}"),
            Some(root.uid.clone()),
        );
        derived
            .statements
            .push(repository_statement(&entity.uid, project, listing)?);
        by_name.insert(entity.name.clone(), (id, project));
        derived.entities.push(entity);
    }
    derived
        .statements
        .push(population(&root, listing, &by_name)?);
    derived.entities.push(root);
    branches(
        transcripts,
        &by_name,
        listing,
        &BTreeSet::new(),
        &mut derived,
    )?;
    Ok(derived)
}

/// the default branch of each project read, and what the source says of it.
/// `listing` is the transcript the projects' own settings came from.
/// `others` are further branches to say the same of. gitlab's settings are
/// read for the whole project, so they need no reading of their own.
fn branches(
    transcripts: &[Transcript],
    projects: &BTreeMap<String, (u64, &Value)>,
    listing: &Transcript,
    others: &BTreeSet<String>,
    derived: &mut Derived,
) -> Result<()> {
    let mut read = BTreeMap::<&str, Project>::new();
    for transcript in transcripts {
        let subject = transcript.contents.subject.as_str();
        match transcript.contents.resource.as_str() {
            PROTECTED_BRANCHES => read.entry(subject).or_default().protected = Some(transcript),
            APPROVAL_SETTINGS => read.entry(subject).or_default().settings = Some(transcript),
            APPROVAL_RULES => read.entry(subject).or_default().rules = Some(transcript),
            _ => {}
        }
    }
    for (subject, read) in read {
        let Some(protected) = read.protected else {
            return Err(Error::Invalid(format!(
                "{subject}: a project's transcripts must be read together"
            )));
        };
        let (id, listed) = projects
            .get(subject)
            .ok_or_else(|| Error::Invalid(format!("{subject} is not among the projects read")))?;
        let default = protected.parameter("branch").unwrap_or_default();
        let mut names = BTreeSet::from([default]);
        names.extend(others.iter().map(String::as_str));
        for name in names {
            let branch = HOST.scope(
                kind::BRANCH,
                "branch",
                &format!("{id}/{name}"),
                format!("{subject}@{name}"),
                Some(HOST.uid(kind::REPOSITORY, &id.to_string())),
            );
            let statements = branch_statements(&branch.uid, name, &read, listing, listed)?;
            if statements.is_empty() {
                return Err(Error::Invalid(format!(
                    "{subject}: a project's transcripts must be read together"
                )));
            }
            derived.statements.extend(statements);
            derived.entities.push(branch);
        }
    }
    Ok(())
}

fn branch_statements(
    about: &str,
    branch: &str,
    read: &Project,
    listing: &Transcript,
    listed: &Value,
) -> Result<Vec<Statement>> {
    let (Some(protected), Some(settings), Some(rules)) =
        (read.protected, read.settings, read.rules)
    else {
        return Ok(Vec::new());
    };
    let protection = protection_reading(protected, branch)?;
    let review = review_reading(settings, rules, &protection, branch)?;
    Ok(vec![
        state(
            about,
            aspect::REVIEW_POLICY,
            review,
            &[protected, settings, rules],
        ),
        state(
            about,
            aspect::REQUIRED_CHECKS,
            checks_reading(listed, branch)?,
            &[listing],
        ),
        state(about, aspect::BRANCH_PROTECTION, protection, &[protected]),
    ])
}

/// the group, identified by the id it reports, or by the namespace id of a
/// project directly under it. when neither was read, it has no stable identity.
fn group_entity(group: Option<&Transcript>, listing: &Transcript, projects: &[Value]) -> Entity {
    let name = listing.contents.subject.as_str();
    let path = name.trim_start_matches("gitlab:");
    let reported = group.and_then(peek).and_then(|body| body["id"].as_u64());
    let direct = || {
        projects
            .iter()
            .filter(|project| project["namespace"]["full_path"].as_str() == Some(path))
            .find_map(|project| project["namespace"]["id"].as_u64())
    };
    match reported.or_else(direct) {
        Some(id) => HOST.scope(kind::ORGANISATION, "group", &id.to_string(), name, None),
        None => HOST.unresolved(kind::ORGANISATION, "group", name),
    }
}

fn population(
    root: &Entity,
    listing: &Transcript,
    by_name: &BTreeMap<String, (u64, &Value)>,
) -> Result<Statement> {
    let members = by_name
        .values()
        .map(|(id, _)| HOST.uid(kind::REPOSITORY, &id.to_string()))
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
        // gitlab reports no project count for a group, so the listing cannot
        // be checked against the whole population.
        statement.note = Some(
            "gitlab does not report how many projects a group has, so projects this credential \
             cannot see may be missing"
                .into(),
        );
    }
    Ok(statement)
}

/// the protected branch rules that match a branch, by name or by wildcard.
fn protection_reading(transcript: &Transcript, branch: &str) -> Result<Reading> {
    if let Some(reason) = transcript.contents.termination.gap() {
        return Ok(Reading::gap(reason));
    }
    let rules = list(transcript)?
        .into_iter()
        .filter(|rule| {
            rule["name"]
                .as_str()
                .is_some_and(|pattern| wildcard_matches(pattern, branch))
        })
        .collect::<Vec<_>>();
    let allowed = |field: &str| {
        rules
            .iter()
            .flat_map(|rule| rule[field].as_array().into_iter().flatten())
            .filter_map(|level| level["access_level_description"].as_str())
            .collect::<BTreeSet<_>>()
    };
    Reading::recorded(json!({
        "branch": branch,
        "protected": !rules.is_empty(),
        "merge": allowed("merge_access_levels"),
        "push": allowed("push_access_levels"),
        "rules": rules,
    }))
}

fn review_reading(
    settings: &Transcript,
    rules: &Transcript,
    protection: &Reading,
    branch: &str,
) -> Result<Reading> {
    let unread = [("approval settings", settings), ("approval rules", rules)]
        .iter()
        .filter_map(|(name, transcript)| {
            let reason = transcript.contents.termination.gap()?;
            Some(format!("{name} could not be read ({reason})"))
        })
        .collect::<Vec<_>>();
    if !unread.is_empty() {
        return Ok(Reading::gap(unread.join("; ")));
    }
    let settings = single(settings)?;
    let rules = list(rules)?;
    let mut requirements = Vec::new();
    for rule in &rules {
        let named = rule["protected_branches"].as_array();
        let applies = if rule["applies_to_all_protected_branches"] == Value::Bool(true) {
            // whether such a rule applies depends on the branch being protected.
            match protection.value() {
                Some(protection) => protection["protected"] == Value::Bool(true),
                None => {
                    return Ok(Reading::gap(
                        "an approval rule applies to all protected branches, and branch \
                         protection could not be read",
                    ))
                }
            }
        } else {
            named.is_none_or(Vec::is_empty)
                || named.into_iter().flatten().any(|protected| {
                    protected["name"]
                        .as_str()
                        .is_some_and(|pattern| wildcard_matches(pattern, branch))
                })
        };
        if applies {
            requirements.push(json!({
                "source": format!("approval rule {}", rule["name"]),
                "required_approvals": rule["approvals_required"],
                "rule_type": rule["rule_type"],
            }));
        }
    }
    if rules.is_empty() && settings["approvals_before_merge"].as_u64().unwrap_or(0) > 0 {
        requirements.push(json!({
            "source": "project setting",
            "required_approvals": settings["approvals_before_merge"],
        }));
    }
    Reading::recorded(json!({
        "branch": branch,
        "requirements": requirements,
        "settings": {
            "author_may_approve": settings["merge_requests_author_approval"],
            "committers_may_not_approve": settings["merge_requests_disable_committers_approval"],
            "reset_approvals_on_push": settings["reset_approvals_on_push"],
            "rules_fixed_per_merge_request": settings["disable_overriding_approvers_per_merge_request"],
        },
    }))
}

/// what a merge needs from ci, from the project's own merge settings.
fn checks_reading(project: &Value, branch: &str) -> Result<Reading> {
    let Some(pipeline) = project["only_allow_merge_if_pipeline_succeeds"].as_bool() else {
        return Ok(Reading::gap(
            "the project listing did not report merge settings to this credential",
        ));
    };
    let mut checks = Vec::new();
    if pipeline {
        checks.push(json!({ "context": "pipeline", "source": "project setting" }));
    }
    if project["only_allow_merge_if_all_status_checks_passed"] == Value::Bool(true) {
        checks.push(json!({ "context": "external status checks", "source": "project setting" }));
    }
    Reading::recorded(json!({
        "branch": branch,
        "checks": checks,
        "skipped_pipeline_counts_as_success": project["allow_merge_on_skipped_pipeline"],
    }))
}

/// gitlab's branch wildcard: `*` stands for any run of characters.
fn wildcard_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts = parts.peekable();
    if parts.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(position) => rest = &rest[position + part.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::summary;
    use crate::transcript::{exchange, seal, Termination, TranscriptContents};

    // the protected branch and approval settings bodies are what gitlab.com
    // returned for a free-tier project on 2026-11-24.
    const PROTECTED: &str = r#"[{"id":170276658,"name":"main","push_access_levels":[{"id":219786192,"access_level":40,"access_level_description":"Maintainers","deploy_key_id":null,"user_id":null,"group_id":null}],"merge_access_levels":[{"id":179678248,"access_level":40,"access_level_description":"Maintainers","user_id":null,"group_id":null}],"allow_force_push":false,"unprotect_access_levels":[],"code_owner_approval_required":false,"inherited":false}]"#;
    const SETTINGS: &str = r#"{"approvers":[],"approver_groups":[],"approvals_before_merge":0,"reset_approvals_on_push":false,"selective_code_owner_removals":false,"disable_overriding_approvers_per_merge_request":false,"merge_requests_author_approval":false,"merge_requests_disable_committers_approval":false,"require_password_to_approve":false,"require_reauthentication_to_approve":false}"#;
    const LISTING: &str = r#"[{"id":7,"path_with_namespace":"example/service","namespace":{"id":3,"full_path":"example"},"visibility":"private","archived":false,"default_branch":"main","only_allow_merge_if_pipeline_succeeds":true,"only_allow_merge_if_all_status_checks_passed":false,"allow_merge_on_skipped_pipeline":false},{"id":8,"path_with_namespace":"example/empty","namespace":{"id":3,"full_path":"example"},"visibility":"private","archived":false,"default_branch":null}]"#;
    const DENIED: &str = r#"{"message":"403 Forbidden"}"#;
    const BRANCH: &str = "gitlab.com/branch/7/main";

    fn transcript(resource: &str, subject: &str, status: u16, body: &str) -> Transcript {
        let termination = match status {
            200 => Termination::Exhausted,
            _ => Termination::PermissionDenied {
                diagnostic: format!("HTTP {status}: 403 Forbidden"),
            },
        };
        seal(TranscriptContents {
            resource: resource.into(),
            subject: subject.into(),
            parameters: BTreeMap::from([("branch".into(), "main".into())]),
            captured_at: "2026-11-24T10:00:00Z".into(),
            exchanges: vec![exchange(
                "https://gitlab.com/api/v4/",
                status,
                BTreeMap::new(),
                body.into(),
            )],
            termination,
        })
        .unwrap()
    }

    fn project(protected: (u16, &str), settings: (u16, &str), rules: (u16, &str)) -> Derived {
        let subject = "gitlab:example/service";
        crate::facts::derive(&[
            transcript(PROJECTS, "gitlab:example", 200, LISTING),
            transcript(PROTECTED_BRANCHES, subject, protected.0, protected.1),
            transcript(APPROVAL_SETTINGS, subject, settings.0, settings.1),
            transcript(APPROVAL_RULES, subject, rules.0, rules.1),
        ])
        .unwrap()
    }

    /// the summaries of the branch's statements, in ledger order.
    fn summaries(derived: &Derived) -> Vec<String> {
        derived
            .statements
            .iter()
            .filter(|statement| statement.about == BRANCH)
            .map(summary)
            .collect()
    }

    #[test]
    fn a_free_tier_project_has_protection_and_no_required_review() {
        assert_eq!(
            summaries(&project((200, PROTECTED), (200, SETTINGS), (200, "[]"))),
            [
                "protected (merge: Maintainers; push: Maintainers)",
                "no review required",
                "pipeline (project setting)",
            ]
        );
    }

    #[test]
    fn approval_rules_apply_by_branch() {
        let rules = r#"[
            {"name":"security","rule_type":"regular","approvals_required":2,"protected_branches":[]},
            {"name":"releases","rule_type":"regular","approvals_required":3,"protected_branches":[{"name":"release/*"}]},
            {"name":"protected","rule_type":"regular","approvals_required":1,"applies_to_all_protected_branches":true,"protected_branches":[]}
        ]"#;
        assert_eq!(
            summaries(&project((200, PROTECTED), (200, SETTINGS), (200, rules)))[1],
            r#"2 approvals (approval rule "security"); 1 approval (approval rule "protected")"#
        );
        // an unprotected branch is outside a rule for all protected branches.
        assert_eq!(
            summaries(&project((200, "[]"), (200, SETTINGS), (200, rules))),
            [
                "not protected",
                r#"2 approvals (approval rule "security")"#,
                "pipeline (project setting)",
            ]
        );
    }

    #[test]
    fn unreadable_approvals_are_a_gap_and_the_rest_is_still_recorded() {
        let found = summaries(&project((200, PROTECTED), (403, DENIED), (403, DENIED)));
        assert_eq!(
            found[0],
            "protected (merge: Maintainers; push: Maintainers)"
        );
        assert!(found[1].starts_with("gap: approval settings could not be read (permission denied"));
        assert!(found[1].contains("; approval rules could not be read"));
        assert_eq!(found[2], "pipeline (project setting)");
    }

    #[test]
    fn a_rule_for_all_protected_branches_needs_protection_to_be_readable() {
        let rules = r#"[{"name":"protected","approvals_required":1,"applies_to_all_protected_branches":true}]"#;
        let found = summaries(&project((403, DENIED), (200, SETTINGS), (200, rules)));
        assert!(found[0].starts_with("gap: permission denied"));
        assert!(found[1].starts_with("gap: an approval rule applies to all protected branches"));
    }

    #[test]
    fn a_wildcard_rule_protects_the_branches_it_matches() {
        assert!(wildcard_matches("main", "main"));
        assert!(!wildcard_matches("main", "maintenance"));
        assert!(wildcard_matches("*", "main"));
        assert!(wildcard_matches("release/*", "release/1.x"));
        assert!(!wildcard_matches("release/*", "main"));
        assert!(wildcard_matches("*-stable", "16-4-stable"));
        assert!(wildcard_matches("a*b*c", "a-b-b-c"));
        assert!(!wildcard_matches("a*b*c", "a-c"));
    }

    #[test]
    fn entities_are_identified_by_the_ids_gitlab_reports() {
        let derived = project((200, PROTECTED), (200, SETTINGS), (200, "[]"));
        // the group response was not read, so a project's namespace id names it.
        let group = derived.named("gitlab:example").unwrap();
        assert_eq!(
            (group.uid.as_str(), group.native_kind.as_str()),
            ("gitlab.com/organisation/3", "group")
        );
        let listed = derived.statement(&group.uid, aspect::REPOSITORIES).unwrap();
        assert_eq!(summary(listed), "2 repositories");
        assert!(listed.note.as_deref().unwrap().contains("may be missing"));
        let service = derived.named("gitlab:example/service").unwrap();
        assert_eq!(
            (service.uid.as_str(), service.native_kind.as_str()),
            ("gitlab.com/repository/7", "project")
        );
        assert_eq!(
            derived.named("gitlab:example/service@main").unwrap().uid,
            BRANCH
        );
        // an empty project is listed, and has no branch to say anything about.
        let empty = derived.named("gitlab:example/empty").unwrap();
        let about = derived.statement(&empty.uid, aspect::REPOSITORY).unwrap();
        assert_eq!(summary(about), "private, no default branch");
        assert!(derived.named("gitlab:example/empty@main").is_none());
    }
}
