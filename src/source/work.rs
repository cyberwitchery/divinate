//! building the record of work items and events, the same way for every source.
//!
//! a source reads its own tickets, changes, and findings and says what it
//! found in the terms of this module: an [`Item`], what [`Happened`] to it,
//! who did it, and which other items refer to it. [`Work`] turns that into
//! entities, statements, and relations, so every source produces the same
//! shapes. it does the same for what happened to a branch.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::build::{self, Host};
use crate::error::Result;
use crate::model::{
    aspect, event, kind, relation, Class, Derived, Entity, Population, Reading, Relation, Statement,
};
use crate::transcript::Transcript;

/// someone the source names.
pub(crate) struct Actor {
    /// the source's own id for the account.
    pub id: String,
    pub login: String,
    /// the source's word for the kind of account, such as `user` or `bot`.
    pub native_kind: String,
}

/// one ticket or change, as its source listed it.
pub(crate) struct Item {
    /// `ticket`, `change`, or `finding`.
    pub kind: &'static str,
    /// the source's word, such as `issue` or `merge request`.
    pub native_kind: String,
    /// the source's own id, which survives a move or a renumbering.
    pub id: String,
    /// how people refer to it, such as `github:owner/repository#12`.
    pub name: String,
    pub number: u64,
    pub title: Value,
    /// `open`, `closed`, or `merged`, or `unknown` when the source's own
    /// state could not be placed.
    pub state: &'static str,
    pub labels: Vec<String>,
    pub opened_at: Value,
    pub closed_at: Value,
    pub merged_at: Value,
    pub author: Option<Actor>,
    /// for a change, the branch it goes into.
    pub target: Option<Target>,
    /// the text its author gave it, or null where the source has none.
    pub description: Value,
    /// for a change, the paths of the files it touches, or why they could
    /// not be read. `None` where they are not read at all.
    pub files: Option<std::result::Result<Vec<String>, String>>,
    /// the reading the files came from, when there was one.
    pub files_from: Option<String>,
}

/// a release, as its source listed it.
pub(crate) struct Release {
    /// the source's own id.
    pub id: String,
    /// how people refer to it, such as `github:owner/repository release v1.2.0`.
    pub name: String,
    pub tag: Value,
    pub title: Value,
    pub prerelease: Value,
    pub published_at: String,
    pub author: Option<Actor>,
    /// what is attached to it: each with a `name`, and where the source says
    /// so a `size` and a `digest`.
    pub assets: Vec<Value>,
}

/// the branch a change goes into.
pub(crate) struct Target {
    /// the branch name, or null when it was not read.
    branch: Value,
    /// whether that is the default branch of its repository, when known.
    default: Option<bool>,
    /// the branch itself, when its settings were read.
    entity: Option<String>,
}

impl Target {
    /// a branch by name, beside the name of the default branch of its
    /// repository. `read` is the id of the branch's entity, when this reading
    /// read the branch's settings.
    pub fn new(branch: Option<&str>, default: Option<&str>, read: Option<&str>) -> Self {
        Self {
            branch: branch.map_or(Value::Null, Value::from),
            default: branch
                .zip(default)
                .map(|(branch, default)| branch == default),
            entity: read.map(str::to_owned),
        }
    }
}

/// something that happened to an item.
pub(crate) struct Happened {
    /// one of the kinds in [`crate::model::event`].
    pub kind: &'static str,
    /// unique among the source's events, such as `note/123`.
    pub id: String,
    pub at: String,
    pub actor: Option<Actor>,
    /// what the source calls this one event, such as the name of a check.
    pub name: Option<String>,
}

impl Happened {
    pub fn new(kind: &'static str, id: String, at: impl Into<String>) -> Self {
        Self {
            kind,
            id,
            at: at.into(),
            actor: None,
            name: None,
        }
    }

    pub fn by(mut self, actor: Option<Actor>) -> Self {
        self.actor = actor;
        self
    }

    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// another item that refers to this one.
pub(crate) struct Reference {
    pub kind: &'static str,
    pub native_kind: &'static str,
    pub id: String,
    pub name: String,
    /// whether it lives under the scope being read.
    pub same_scope: bool,
    /// how the link was established, one of the bases in [`crate::model::relation`].
    pub basis: &'static str,
}

/// the kinds of event that say how a check on a change ended.
pub(crate) const CHECKS: [&str; 2] = [event::CHECK_PASSED, event::CHECK_FAILED];

/// what could be read of one item beyond its listing.
pub(crate) struct Details<'a> {
    /// what happened to the item, or why that could not be read.
    pub events: std::result::Result<Vec<Happened>, String>,
    /// kinds of event that could not be read while the rest could, and why.
    pub unread: Vec<(&'static str, String)>,
    pub references: Vec<Reference>,
    /// the transcripts the events and references came from.
    pub transcripts: Vec<&'a Transcript>,
}

pub(crate) struct Work<'a> {
    host: &'static Host,
    scope: &'a Entity,
    derived: &'a mut Derived,
    actors: BTreeMap<String, Entity>,
    /// items other items refer to, which this reading may not have read itself.
    mentioned: BTreeMap<String, Entity>,
    /// the items of each population, by its aspect.
    members: BTreeMap<String, Vec<String>>,
}

impl Details<'_> {
    /// nothing was read yet.
    pub fn unread() -> Self {
        Self {
            events: Err("what happened to it was not read".into()),
            unread: Vec::new(),
            references: Vec::new(),
            transcripts: Vec::new(),
        }
    }

    /// the checks on a change could not be read, and why. everything else
    /// that happened to it still stands.
    pub fn without_checks(&mut self, reason: &str) {
        for kind in CHECKS {
            self.unread.push((kind, reason.to_owned()));
        }
    }
}

impl<'a> Work<'a> {
    pub fn new(host: &'static Host, scope: &'a Entity, derived: &'a mut Derived) -> Self {
        Self {
            host,
            scope,
            derived,
            actors: BTreeMap::new(),
            mentioned: BTreeMap::new(),
            members: BTreeMap::new(),
        }
    }

    /// the id of an entity this reading already recorded, by its name.
    pub fn named(&self, name: &str) -> Option<String> {
        self.derived.named(name).map(|entity| entity.uid.clone())
    }

    /// record one item: what it is, who opened it, what happened to it, and
    /// what refers to it. `populations` are the aspects of the populations it
    /// belongs to, such as `changes` and `merged changes`.
    pub fn item(
        &mut self,
        item: Item,
        populations: &[&str],
        listing: &Transcript,
        details: Details,
    ) -> Result<()> {
        let id = self.host.uid(item.kind, &item.id);
        let value = about(&item);
        self.derived.entities.push(Entity {
            uid: id.clone(),
            class: Class::WorkItem,
            kind: item.kind.into(),
            native_kind: item.native_kind,
            name: item.name,
            parent: Some(self.scope.uid.clone()),
            occurred_at: None,
        });
        self.derived.statements.push(Statement {
            about: id.clone(),
            aspect: item.kind.into(),
            population: None,
            reading: Reading::recorded(value)?,
            note: None,
            transcripts: std::iter::once(listing.id.clone())
                .chain(item.files_from)
                .collect(),
        });
        let mut events = Vec::new();
        if let Some(opened_at) = item.opened_at.as_str() {
            let opened = Happened::new(
                event::OPENED,
                format!("opened/{}/{}", item.kind, item.id),
                opened_at,
            );
            let opened = self.event(&id, opened, listing);
            if let Some(author) = &item.author {
                self.by(&opened, author, listing);
            }
            events.push(opened);
        }
        if let Some(author) = &item.author {
            self.by(&id, author, listing);
        }
        if let Some(branch) = item.target.and_then(|target| target.entity) {
            self.derived.relations.push(Relation {
                from: id.clone(),
                kind: relation::INTO.into(),
                to: branch,
                basis: relation::RECORDED.into(),
                transcripts: vec![listing.id.clone()],
            });
        }
        let from = details.transcripts.first().copied().unwrap_or(listing);
        let reading = match details.events {
            Err(reason) => Reading::gap(reason),
            Ok(happened) => {
                for happened in happened {
                    events.push(self.event(&id, happened, from));
                }
                let mut value = json!({ "members": events });
                if !details.unread.is_empty() {
                    value["unread"] = details
                        .unread
                        .into_iter()
                        .map(|(kind, reason)| (kind.to_owned(), Value::String(reason)))
                        .collect::<serde_json::Map<_, _>>()
                        .into();
                }
                Reading::recorded(value)?
            }
        };
        self.derived.statements.push(Statement {
            about: id.clone(),
            aspect: aspect::EVENTS.into(),
            population: Some(Population {
                of: kind::EVENT.into(),
                interval: None,
            }),
            reading,
            note: None,
            transcripts: details
                .transcripts
                .iter()
                .map(|transcript| transcript.id.clone())
                .collect(),
        });
        for reference in details.references {
            self.reference(&id, reference, from);
        }
        for aspect in populations {
            self.members
                .entry((*aspect).to_owned())
                .or_default()
                .push(id.clone());
        }
        Ok(())
    }

    fn event(&mut self, parent: &str, happened: Happened, from: &Transcript) -> String {
        let id = self.host.uid(kind::EVENT, &happened.id);
        self.derived.entities.push(Entity {
            uid: id.clone(),
            class: Class::Event,
            kind: happened.kind.into(),
            native_kind: happened.kind.into(),
            name: happened.name.unwrap_or_else(|| id.clone()),
            parent: Some(parent.into()),
            occurred_at: Some(happened.at),
        });
        if let Some(actor) = &happened.actor {
            self.by(&id, actor, from);
        }
        id
    }

    /// link something to the actor the source names for it.
    fn by(&mut self, from: &str, actor: &Actor, transcript: &Transcript) {
        let entity = Entity {
            uid: self.host.uid(kind::USER, &actor.id),
            class: Class::Actor,
            kind: kind::USER.into(),
            native_kind: actor.native_kind.clone(),
            name: format!("{}:{}", self.host.name, actor.login),
            parent: None,
            occurred_at: None,
        };
        self.derived.relations.push(Relation {
            from: from.into(),
            kind: relation::BY.into(),
            to: entity.uid.clone(),
            basis: relation::RECORDED.into(),
            transcripts: vec![transcript.id.clone()],
        });
        self.actors.insert(entity.uid.clone(), entity);
    }

    fn reference(&mut self, to: &str, reference: Reference, transcript: &Transcript) {
        let from = self.host.uid(reference.kind, &reference.id);
        self.mentioned.insert(
            from.clone(),
            Entity {
                uid: from.clone(),
                class: Class::WorkItem,
                kind: reference.kind.into(),
                native_kind: reference.native_kind.into(),
                name: reference.name,
                parent: reference.same_scope.then(|| self.scope.uid.clone()),
                occurred_at: None,
            },
        );
        self.derived.relations.push(Relation {
            from,
            kind: relation::REFERS_TO.into(),
            to: to.into(),
            basis: reference.basis.into(),
            transcripts: vec![transcript.id.clone()],
        });
    }

    /// record one release: what it is, who published it, and when.
    pub fn release(&mut self, release: Release, aspect: &str, listing: &Transcript) -> Result<()> {
        let id = self.host.uid(kind::RELEASE, &release.id);
        self.derived.entities.push(Entity {
            uid: id.clone(),
            class: Class::Product,
            kind: kind::RELEASE.into(),
            native_kind: kind::RELEASE.into(),
            name: release.name,
            parent: Some(self.scope.uid.clone()),
            occurred_at: None,
        });
        self.derived.statements.push(build::state(
            &id,
            aspect::RELEASE,
            Reading::recorded(json!({
                "tag": release.tag,
                "title": release.title,
                "prerelease": release.prerelease,
                "published_at": release.published_at,
                "assets": release.assets,
            }))?,
            &[listing],
        ));
        let published = Happened::new(
            event::PUBLISHED,
            format!("published/{}", release.id),
            release.published_at,
        );
        let published = self.event(&id, published, listing);
        // whoever published it is named on the event alone. a release has no
        // author for a step to set that person against.
        if let Some(author) = &release.author {
            self.by(&published, author, listing);
        }
        let mut events = build::state(
            &id,
            aspect::EVENTS,
            Reading::recorded(json!({ "members": [published] }))?,
            &[listing],
        );
        events.population = Some(Population {
            of: kind::EVENT.into(),
            interval: None,
        });
        self.derived.statements.push(events);
        self.members.entry(aspect.to_owned()).or_default().push(id);
        Ok(())
    }

    /// record every update of a branch during the period of a listing, or why
    /// the updates could not be read.
    pub fn updates(
        &mut self,
        branch: &Entity,
        happened: std::result::Result<Vec<Happened>, String>,
        note: Option<String>,
        listing: &Transcript,
    ) -> Result<()> {
        let reading = match happened {
            Err(reason) => Reading::gap(reason),
            Ok(happened) => {
                let mut events = Vec::new();
                for happened in happened {
                    events.push(self.event(&branch.uid, happened, listing));
                }
                events.sort();
                Reading::recorded(json!({ "members": events }))?
            }
        };
        let mut statement = build::state(&branch.uid, aspect::UPDATES, reading, &[listing]);
        statement.population = Some(Population {
            of: kind::EVENT.into(),
            interval: build::interval(listing),
        });
        statement.note = note;
        self.derived.statements.push(statement);
        Ok(())
    }

    /// the items of one population, as its listings reported them. the
    /// population is a gap when one of the listings did not complete.
    pub fn population(&mut self, of: &str, aspect: &str, listings: &[&Transcript]) -> Result<()> {
        let members = self.members.get(aspect).map_or(&[][..], Vec::as_slice);
        self.derived.statements.push(build::population(
            &self.scope.uid,
            aspect,
            of,
            listings
                .first()
                .and_then(|listing| build::interval(listing)),
            members,
            listings,
        )?);
        Ok(())
    }

    /// the source answered that it keeps nothing of a kind, and why. that is
    /// an empty population with a note, not a gap.
    pub fn nothing(
        &mut self,
        of: &str,
        aspect: &str,
        listing: &Transcript,
        why: String,
    ) -> Result<()> {
        let mut statement = build::population(
            &self.scope.uid,
            aspect,
            of,
            build::interval(listing),
            &[],
            &[],
        )?;
        statement.note = Some(why);
        statement.transcripts = vec![listing.id.clone()];
        self.derived.statements.push(statement);
        Ok(())
    }

    /// add the actors and the referring items this reading did not read itself.
    pub fn finish(self) {
        let known = self
            .derived
            .entities
            .iter()
            .map(|entity| entity.uid.clone())
            .collect::<BTreeSet<_>>();
        self.derived.entities.extend(self.actors.into_values());
        self.derived.entities.extend(
            self.mentioned
                .into_values()
                .filter(|entity| !known.contains(&entity.uid)),
        );
    }
}

/// what an item is, as its statement says it.
fn about(item: &Item) -> Value {
    let mut value = json!({
        "number": item.number,
        "title": item.title,
        "state": item.state,
        "labels": item.labels,
        "opened_at": item.opened_at,
        "closed_at": item.closed_at,
        "merged_at": item.merged_at,
    });
    if let Some(target) = &item.target {
        value["target_branch"] = target.branch.clone();
        value["targets_default_branch"] = target.default.into();
    }
    if !item.description.is_null() {
        value["description"] = item.description.clone();
    }
    // paths that could not be read are null, so a reader can tell them from
    // a change that touches nothing.
    match &item.files {
        None => {}
        Some(Ok(paths)) => value["paths"] = paths.clone().into(),
        Some(Err(_)) => value["paths"] = Value::Null,
    }
    value
}

/// whether a description says it closes an item numbered `number`: a closing
/// keyword directly before `<marker><number>`, as github and gitlab read it.
pub(crate) fn closes(description: &str, marker: char, number: u64) -> bool {
    const KEYWORDS: [&str; 9] = [
        "close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved",
    ];
    let text = description.to_ascii_lowercase();
    let reference = format!("{marker}{number}");
    let mut rest = text.as_str();
    let mut before = 0;
    while let Some(position) = rest.find(&reference) {
        let end = position + reference.len();
        let whole = !rest[end..].starts_with(|next: char| next.is_ascii_digit());
        let preceding = text[..before + position]
            .trim_end_matches([' ', ':'])
            .rsplit(|character: char| !character.is_ascii_alphabetic())
            .next()
            .unwrap_or_default();
        if whole && KEYWORDS.contains(&preceding) {
            return true;
        }
        before += end;
        rest = &rest[end..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closing_keyword_must_directly_precede_the_reference() {
        assert!(closes(
            "Fixes #61\n\nremoves the due-diligence angle",
            '#',
            61
        ));
        assert!(closes("this resolves: #61.", '#', 61));
        assert!(closes("see #7, closes #61", '#', 61));
        assert!(!closes("Fixes #610", '#', 61));
        assert!(!closes("related to #61", '#', 61));
        assert!(!closes("prefixes #61", '#', 61));
        assert!(!closes("fixes the thing in #61", '#', 61));
    }
}
