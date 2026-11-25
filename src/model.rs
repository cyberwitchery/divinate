//! what the record is about, and what it says.
//!
//! an [`Entity`] is a thing in the development process, in one of six
//! [`Class`]es. a [`Statement`] says something about one entity: its state, or
//! which entities of a kind exist under it. a [`Relation`] links two entities.
//! sources name their own kinds of entity within the classes, so a tracker, a
//! registry, or a ci server needs no change here.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::hex_digest;

/// kinds of entity that mean the same in every source that has them.
pub mod kind {
    pub const ORGANISATION: &str = "organisation";
    /// a scope between an organisation and its repositories, where a source has one.
    pub const PROJECT: &str = "project";
    pub const REPOSITORY: &str = "repository";
    pub const BRANCH: &str = "branch";
    /// a work item in a tracker: an issue, a ticket.
    pub const TICKET: &str = "ticket";
    /// a proposed change to a branch: a pull request, a merge request.
    pub const CHANGE: &str = "change";
    /// something a scanner reported and someone has to deal with.
    pub const FINDING: &str = "finding";
    pub const USER: &str = "user";
    pub const EVENT: &str = "event";
    /// a version of the software as it was given out, with what was attached to it.
    pub const RELEASE: &str = "release";
}

/// kinds of event that mean the same in every source that has them.
pub mod event {
    pub const OPENED: &str = "opened";
    pub const COMMENT: &str = "comment";
    pub const CLOSED: &str = "closed";
    pub const REOPENED: &str = "reopened";
    pub const MERGE: &str = "merge";
    pub const APPROVAL: &str = "approval";
    pub const CHANGES_REQUESTED: &str = "changes requested";
    /// a reviewer's approval was taken back, by them or by someone else.
    pub const APPROVAL_WITHDRAWN: &str = "approval withdrawn";
    /// a commit was added to a change.
    pub const COMMIT: &str = "commit";

    /// the kinds of event by which an actor takes back an earlier event of
    /// `kind` of their own. an approval stands until its reviewer asks for
    /// changes or the approval is withdrawn.
    #[must_use]
    pub fn revoked_by(kind: &str) -> &'static [&'static str] {
        if kind == APPROVAL {
            &[CHANGES_REQUESTED, APPROVAL_WITHDRAWN]
        } else {
            &[]
        }
    }
    /// a finding someone set aside without fixing it.
    pub const DISMISSED: &str = "dismissed";
    /// a check on a change finished and passed.
    pub const CHECK_PASSED: &str = "check passed";
    /// a check on a change finished and did not pass.
    pub const CHECK_FAILED: &str = "check failed";
    /// a release was given out.
    pub const PUBLISHED: &str = "published";
    /// a branch was updated without merging a change.
    pub const PUSH: &str = "push";
    /// a branch's history was rewritten.
    pub const FORCE_PUSH: &str = "force push";
}

/// what a statement can be about.
pub mod aspect {
    /// the projects under an organisation.
    pub const PROJECTS: &str = "projects";
    /// what a project is: its visibility.
    pub const PROJECT: &str = "project";
    /// the repositories under an organisation or a project.
    pub const REPOSITORIES: &str = "repositories";
    /// what a repository is: its visibility, default branch, and the like.
    pub const REPOSITORY: &str = "repository";
    /// the source's branch protection settings, as reported.
    pub const BRANCH_PROTECTION: &str = "branch protection";
    /// the rules the source applies to a branch, as reported.
    pub const BRANCH_RULES: &str = "branch rules";
    /// what review a change needs before it is merged into a branch.
    pub const REVIEW_POLICY: &str = "review policy";
    /// which checks a change needs before it is merged into a branch.
    pub const REQUIRED_CHECKS: &str = "required checks";

    /// the tickets opened under a scope during a period.
    pub const TICKETS: &str = "tickets";
    /// the changes opened under a scope during a period.
    pub const CHANGES: &str = "changes";
    /// the changes merged under a scope during a period, whenever they were opened.
    pub const MERGED_CHANGES: &str = "merged changes";
    /// the findings opened under a scope during a period.
    pub const FINDINGS: &str = "findings";
    /// the releases published under a scope during a period.
    pub const RELEASES: &str = "releases";
    /// what a release is: its tag, when it was published, and what is attached.
    pub const RELEASE: &str = "release";
    /// every update of a branch during a period: merges and pushes.
    pub const UPDATES: &str = "updates";
    /// what a ticket is: its title, labels, and whether it is open.
    pub const TICKET: &str = "ticket";
    /// what a change is: its title, labels, and whether it is open or merged.
    pub const CHANGE: &str = "change";
    /// what a finding is: its title, severity, and whether it is open.
    pub const FINDING: &str = "finding";
    /// everything that happened to a work item.
    pub const EVENTS: &str = "events";

    /// the order aspects are shown in under one entity.
    pub const ORDER: [&str; 14] = [
        PROJECTS,
        PROJECT,
        REPOSITORIES,
        REPOSITORY,
        TICKETS,
        CHANGES,
        MERGED_CHANGES,
        FINDINGS,
        RELEASES,
        UPDATES,
        BRANCH_PROTECTION,
        BRANCH_RULES,
        REVIEW_POLICY,
        REQUIRED_CHECKS,
    ];
}

/// how two entities can be linked.
pub mod relation {
    /// one entity names another, such as a change naming a ticket.
    pub const REFERS_TO: &str = "refers to";
    /// the actor who did something, or who opened a work item.
    pub const BY: &str = "by";
    /// the branch a change goes into.
    pub const INTO: &str = "into";
    /// how a `by` link is established: the source names the actor.
    pub const RECORDED: &str = "recorded by the source";
    /// a change whose description says it closes a ticket.
    pub const CLOSING_KEYWORD: &str = "closing keyword in the description";
    /// a change the source itself lists as closing a ticket.
    pub const CLOSING_REFERENCE: &str = "closing reference reported by the source";
    /// a link between two work items that the source keeps, such as a change
    /// someone attached to a ticket.
    pub const LINK: &str = "link reported by the source";
    /// one work item mentions another.
    pub const MENTION: &str = "mention";

    /// whether a `refers to` link says the referring item is the work on the
    /// other: it closes it, or the source links the two. a mention does not.
    #[must_use]
    pub fn resolves(basis: &str) -> bool {
        basis == CLOSING_KEYWORD || basis == CLOSING_REFERENCE || basis == LINK
    }
    /// two entities in different sources that are the same thing.
    pub const SAME_AS: &str = "same as";
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
/// the six classes every entity falls into.
pub enum Class {
    /// where things live, nested: an organisation, a repository, a branch, a
    /// tracker project, a registry namespace.
    Scope,
    /// who acts or holds access: a user, a team, a bot, a role.
    Actor,
    /// something a process moves from open to done: a ticket, a change, a finding.
    WorkItem,
    /// something that happened at a time and does not change: an approval, a
    /// transition, a merge, a pipeline run.
    Event,
    /// what the process puts out: a revision, a release, a package, an sbom.
    Product,
    /// what a scope requires or allows, when the source gives it an identity
    /// of its own. otherwise a rule is the state of its scope.
    Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a thing the record makes statements about.
pub struct Entity {
    /// the source, kind, and the source's own stable id. a rename keeps it.
    pub uid: String,
    pub class: Class,
    /// the kind, in the words shared between sources where one exists.
    pub kind: String,
    /// the source's own word for the kind, such as `project` or `group`.
    pub native_kind: String,
    /// how the source currently names it. shown to people, never joined on.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// the entity this one lives under or happened to.
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// when an event happened.
    pub occurred_at: Option<String>,
}

/// build an entity id from a source host, a kind, and the source's own id.
#[must_use]
pub fn uid(source: &str, kind: &str, native_id: &str) -> String {
    format!("{source}/{kind}/{native_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one thing the record says about one entity.
pub struct Statement {
    /// the entity this is about.
    pub about: String,
    pub aspect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// present when the statement lists entities instead of describing one.
    pub population: Option<Population>,
    #[serde(flatten)]
    pub reading: Reading,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// a limit on what a recorded value establishes.
    pub note: Option<String>,
    /// the transcripts this statement was derived from.
    pub transcripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// which entities a population statement lists.
///
/// a recorded population holds every member the source reported, as
/// `{"members": [uid, ..]}`. whether that is every member that exists is what
/// the statement's note and gap say.
pub struct Population {
    /// the kind of entity listed.
    pub of: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// the period covered, for things that happen. absent for things that exist.
    pub interval: Option<Interval>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a half-open period, `from` included and `until` not.
pub struct Interval {
    pub from: String,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "reading", rename_all = "snake_case")]
/// whether the evidence was read.
pub enum Reading {
    Recorded {
        value: Value,
        /// digest of the value, compared between collections to find changes.
        digest: String,
    },
    Gap {
        reason: String,
    },
}

impl Reading {
    /// a recorded reading of a value.
    ///
    /// # Errors
    ///
    /// returns an error when the value cannot be serialized.
    pub fn recorded(value: Value) -> Result<Self> {
        let bytes = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        Ok(Self::Recorded {
            digest: hex_digest(&bytes),
            value,
        })
    }

    /// a gap with its reason.
    #[must_use]
    pub fn gap(reason: impl Into<String>) -> Self {
        Self::Gap {
            reason: reason.into(),
        }
    }

    /// the recorded value, if there is one.
    #[must_use]
    pub fn value(&self) -> Option<&Value> {
        match self {
            Self::Recorded { value, .. } => Some(value),
            Self::Gap { .. } => None,
        }
    }

    /// the digest of the recorded value, if there is one.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        match self {
            Self::Recorded { digest, .. } => Some(digest),
            Self::Gap { .. } => None,
        }
    }

    /// why the evidence was not read, if it was not.
    #[must_use]
    pub fn gap_reason(&self) -> Option<&str> {
        match self {
            Self::Recorded { .. } => None,
            Self::Gap { reason } => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a link between two entities.
pub struct Relation {
    pub from: String,
    pub kind: String,
    pub to: String,
    /// how the link was established, such as `closing reference` or `key in title`.
    pub basis: String,
    pub transcripts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
/// everything one reading says: the entities it met and what it says of them.
pub struct Derived {
    pub entities: Vec<Entity>,
    pub statements: Vec<Statement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relations: Vec<Relation>,
}

impl Derived {
    /// the entity with an id, if this reading met it.
    #[must_use]
    pub fn entity(&self, uid: &str) -> Option<&Entity> {
        self.entities.iter().find(|entity| entity.uid == uid)
    }

    /// the entity with a name, if this reading met it.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<&Entity> {
        self.entities.iter().find(|entity| entity.name == name)
    }

    /// the statement about one aspect of one entity, if there is one.
    #[must_use]
    pub fn statement(&self, about: &str, aspect: &str) -> Option<&Statement> {
        self.statements
            .iter()
            .find(|statement| statement.about == about && statement.aspect == aspect)
    }

    /// how an entity is named, or its id when this reading did not meet it.
    #[must_use]
    pub fn name<'a>(&'a self, uid: &'a str) -> &'a str {
        self.entity(uid).map_or(uid, |entity| &entity.name)
    }

    /// put everything in the order it is stored and shown in: by entity name,
    /// then by aspect.
    #[must_use]
    pub fn sorted(mut self) -> Self {
        self.entities
            .sort_by(|left, right| (&left.name, &left.uid).cmp(&(&right.name, &right.uid)));
        let mut statements = std::mem::take(&mut self.statements);
        statements.sort_by_cached_key(|statement| {
            (
                self.name(&statement.about).to_owned(),
                statement.about.clone(),
                aspect_rank(&statement.aspect),
                statement.aspect.clone(),
            )
        });
        self.statements = statements;
        self.relations.sort_by(|left, right| {
            (&left.from, &left.kind, &left.to, &left.basis).cmp(&(
                &right.from,
                &right.kind,
                &right.to,
                &right.basis,
            ))
        });
        self.relations.dedup();
        self
    }
}

/// where an aspect sorts under its entity.
#[must_use]
pub fn aspect_rank(aspect: &str) -> usize {
    aspect::ORDER
        .iter()
        .position(|known| *known == aspect)
        .unwrap_or(aspect::ORDER.len())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn equal_values_have_equal_digests() {
        let left = Reading::recorded(json!({"b": 1, "a": 2})).unwrap();
        let right = Reading::recorded(json!({"a": 2, "b": 1})).unwrap();
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn a_statement_round_trips_with_its_reading_inline() {
        let statement = Statement {
            about: uid("github.com", kind::BRANCH, "7/main"),
            aspect: aspect::REVIEW_POLICY.into(),
            population: None,
            reading: Reading::recorded(json!({"requirements": []})).unwrap(),
            note: None,
            transcripts: Vec::new(),
        };
        let text = serde_json::to_string(&statement).unwrap();
        assert!(text.contains("\"reading\":\"recorded\""));
        assert!(!text.contains("population"));
        assert_eq!(serde_json::from_str::<Statement>(&text).unwrap(), statement);
    }

    fn entity(
        uid: &str,
        class: Class,
        kind: &str,
        parent: Option<&str>,
        at: Option<&str>,
    ) -> Entity {
        Entity {
            uid: uid.into(),
            class,
            kind: kind.into(),
            native_kind: kind.into(),
            name: uid.into(),
            parent: parent.map(str::to_owned),
            occurred_at: at.map(str::to_owned),
        }
    }

    fn security_ticket_entities() -> Vec<Entity> {
        vec![
            entity("tracker/project/1", Class::Scope, "project", None, None),
            entity("tracker/user/reporter", Class::Actor, "user", None, None),
            entity("tracker/user/engineer", Class::Actor, "user", None, None),
            entity("git/user/author", Class::Actor, "user", None, None),
            entity("git/user/reviewer", Class::Actor, "user", None, None),
            entity(
                "tracker/ticket/9",
                Class::WorkItem,
                "ticket",
                Some("tracker/project/1"),
                None,
            ),
            entity(
                "tracker/event/1",
                Class::Event,
                "opened",
                Some("tracker/ticket/9"),
                Some("2026-03-01T09:00:00Z"),
            ),
            entity(
                "tracker/event/2",
                Class::Event,
                "comment",
                Some("tracker/ticket/9"),
                Some("2026-03-03T10:00:00Z"),
            ),
            entity(
                "tracker/event/3",
                Class::Event,
                "closed",
                Some("tracker/ticket/9"),
                Some("2026-03-20T16:00:00Z"),
            ),
            entity(
                "git/change/42",
                Class::WorkItem,
                "change",
                Some("git/branch/7/main"),
                None,
            ),
            entity(
                "git/event/5",
                Class::Event,
                "approval",
                Some("git/change/42"),
                Some("2026-03-19T11:00:00Z"),
            ),
            entity(
                "git/event/6",
                Class::Event,
                "merge",
                Some("git/change/42"),
                Some("2026-03-19T12:00:00Z"),
            ),
        ]
    }

    /// a security ticket answered and closed, fixed by a reviewed change in
    /// another source.
    fn security_ticket() -> Derived {
        let by = |from: &str, to: &str| Relation {
            from: from.into(),
            kind: relation::BY.into(),
            to: to.into(),
            basis: "recorded by the source".into(),
            transcripts: Vec::new(),
        };
        Derived {
            entities: security_ticket_entities(),
            statements: vec![
                Statement {
                    about: "tracker/project/1".into(),
                    aspect: "tickets".into(),
                    population: Some(Population {
                        of: "ticket".into(),
                        interval: Some(Interval {
                            from: "2026-01-01T00:00:00Z".into(),
                            until: "2026-04-01T00:00:00Z".into(),
                        }),
                    }),
                    reading: Reading::recorded(json!({"members": ["tracker/ticket/9"]})).unwrap(),
                    note: None,
                    transcripts: Vec::new(),
                },
                Statement {
                    about: "tracker/ticket/9".into(),
                    aspect: "ticket".into(),
                    population: None,
                    reading: Reading::recorded(json!({"labels": ["security"], "status": "closed"}))
                        .unwrap(),
                    note: None,
                    transcripts: Vec::new(),
                },
            ],
            relations: vec![
                by("tracker/event/1", "tracker/user/reporter"),
                by("tracker/event/2", "tracker/user/engineer"),
                by("git/change/42", "git/user/author"),
                by("git/event/5", "git/user/reviewer"),
                Relation {
                    from: "git/change/42".into(),
                    kind: relation::REFERS_TO.into(),
                    to: "tracker/ticket/9".into(),
                    basis: "closing reference".into(),
                    transcripts: Vec::new(),
                },
            ],
        }
    }

    /// no source produces this yet. the test shows the model can hold it, and
    /// that the questions a process asks can be read from it.
    #[test]
    fn the_model_holds_a_ticket_its_events_and_the_change_that_fixed_it() {
        let record = security_ticket();
        let text = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<Derived>(&text).unwrap(), record);

        let events = |parent: &str, kind: &str| {
            record
                .entities
                .iter()
                .filter(|entity| entity.parent.as_deref() == Some(parent) && entity.kind == kind)
                .collect::<Vec<_>>()
        };
        let actor = |from: &str| {
            record
                .relations
                .iter()
                .find(|relation| relation.from == from && relation.kind == relation::BY)
                .map(|relation| relation.to.as_str())
        };
        // answered: the first comment by someone other than the reporter.
        let reporter = actor(&events("tracker/ticket/9", "opened")[0].uid);
        let answer = events("tracker/ticket/9", "comment")
            .into_iter()
            .find(|comment| actor(&comment.uid) != reporter)
            .unwrap();
        assert_eq!(answer.occurred_at.as_deref(), Some("2026-03-03T10:00:00Z"));
        // the change that fixed it, and its approval by someone other than its
        // author before the merge.
        let change = record
            .relations
            .iter()
            .find(|relation| {
                relation.kind == relation::REFERS_TO && relation.to == "tracker/ticket/9"
            })
            .map(|relation| relation.from.as_str())
            .unwrap();
        let approval = events(change, "approval")[0];
        let merge = events(change, "merge")[0];
        assert_ne!(actor(&approval.uid), actor(change));
        assert!(approval.occurred_at < merge.occurred_at);
    }
}
