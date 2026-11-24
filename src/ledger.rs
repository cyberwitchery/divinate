//! views of the record.
//!
//! [`ledger`] shows every aspect of every entity across collections. [`show`]
//! spells out one collection. both read stored collections and add nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::facts::summary;
use crate::model::{aspect_rank, Class, Entity, Reading, Statement};
use crate::record::Collection;

const RECORDED: char = '■';
const CHANGED: char = '▣';
const GAP: char = '⬚';
const LEGEND: &str = "■ recorded   ▣ changed since previous   ⬚ not available: reported as a gap";

/// how one statement compares with the same statement in the previous collection.
fn mark(statement: &Statement, previous: Option<&Collection>) -> char {
    let Reading::Recorded { digest, .. } = &statement.reading else {
        return GAP;
    };
    let before = previous
        .and_then(|collection| {
            collection
                .contents
                .derived
                .statement(&statement.about, &statement.aspect)
        })
        .and_then(|statement| statement.reading.digest());
    match before {
        Some(before) if before != digest => CHANGED,
        _ => RECORDED,
    }
}

/// the entities a view lists. tickets, changes, and their events are read
/// through `check`, not listed row by row.
fn scopes(collection: &Collection) -> impl Iterator<Item = &Entity> {
    collection
        .contents
        .derived
        .entities
        .iter()
        .filter(|entity| entity.class == Class::Scope)
}

/// render the last `last` collections of one scope as a ledger.
///
/// rows are aspects, grouped by entity. columns are collections, oldest
/// first. a cell is empty when a collection says nothing about that aspect.
/// an entity keeps its rows when it is renamed, under its latest name.
#[must_use]
pub fn ledger(collections: &[Collection], last: usize) -> String {
    let first = collections.len().saturating_sub(last);
    let shown = &collections[first..];
    let mut names = BTreeMap::new();
    for collection in shown {
        for entity in scopes(collection) {
            names.insert(entity.uid.as_str(), entity.name.as_str());
        }
    }
    let rows = shown
        .iter()
        .flat_map(|collection| &collection.contents.derived.statements)
        .filter_map(|statement| {
            let about = statement.about.as_str();
            let aspect = statement.aspect.as_str();
            Some((*names.get(about)?, about, aspect_rank(aspect), aspect))
        })
        .collect::<BTreeSet<_>>();
    let labels = column_labels(shown);
    let width = labels.iter().map(String::len).max().unwrap_or(0) + 2;
    let label_width = rows
        .iter()
        .map(|(name, _, _, aspect)| name.len().max(aspect.len() + 2))
        .max()
        .unwrap_or(0)
        .max("evidence".len());

    let mut out = format!("{:<label_width$}", "evidence");
    for label in &labels {
        let _ = write!(out, "{label:>width$}");
    }
    out.push('\n');
    let mut current = "";
    for (name, about, _, aspect) in rows {
        if about != current {
            let _ = writeln!(out, "{name}");
            current = about;
        }
        let _ = write!(out, "{:<label_width$}", format!("  {aspect}"));
        for (index, collection) in shown.iter().enumerate() {
            let previous = (first + index)
                .checked_sub(1)
                .map(|position| &collections[position]);
            let cell = collection
                .contents
                .derived
                .statement(about, aspect)
                .map_or(' ', |statement| mark(statement, previous));
            let _ = write!(out, "{cell:>width$}");
        }
        out.push('\n');
    }
    let _ = write!(out, "\n{LEGEND}\n");
    out
}

/// label columns by date, and by time as well when two share a date.
fn column_labels(collections: &[Collection]) -> Vec<String> {
    let date = |collection: &Collection| {
        collection
            .contents
            .started_at
            .get(5..10)
            .unwrap_or("?")
            .to_owned()
    };
    let dates = collections.iter().map(date).collect::<Vec<_>>();
    let unique = dates.iter().collect::<BTreeSet<_>>().len() == dates.len();
    if unique {
        return dates;
    }
    collections
        .iter()
        .zip(dates)
        .map(|(collection, date)| {
            let time = collection.contents.started_at.get(11..16).unwrap_or("?");
            format!("{date} {time}")
        })
        .collect()
}

/// render one collection in full: every statement, what it says, and its limits.
#[must_use]
pub fn show(collection: &Collection, previous: Option<&Collection>) -> String {
    let contents = &collection.contents;
    let mut out = format!(
        "{} · collected {} · {}\n{} records, {} gaps\n",
        contents.scope,
        contents.started_at,
        collection.id,
        collection.recorded(),
        collection.gaps(),
    );
    let width = contents
        .derived
        .statements
        .iter()
        .map(|statement| statement.aspect.len())
        .max()
        .unwrap_or(0);
    let listed = scopes(collection)
        .map(|entity| entity.uid.as_str())
        .collect::<BTreeSet<_>>();
    let mut current = "";
    for statement in &contents.derived.statements {
        if !listed.contains(statement.about.as_str()) {
            continue;
        }
        if statement.about != current {
            let _ = write!(out, "\n{}\n", contents.derived.name(&statement.about));
            current = &statement.about;
        }
        let _ = writeln!(
            out,
            "  {} {:<width$}  {}",
            mark(statement, previous),
            statement.aspect,
            summary(statement)
        );
        if let Some(note) = &statement.note {
            let _ = writeln!(out, "    {:<width$}  note: {note}", "");
        }
    }
    let _ = write!(out, "\n{LEGEND}\n");
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::{aspect, kind, Derived};
    use crate::record::CollectionContents;

    const BRANCH: &str = "github.com/branch/7/main";

    fn collection(started_at: &str, name: &str, statements: Vec<Statement>) -> Collection {
        Collection {
            id: format!("col_{started_at}"),
            contents: CollectionContents {
                tool: "divinate/test".into(),
                derivation: "2".into(),
                scope: "github:example".into(),
                started_at: started_at.into(),
                completed_at: started_at.into(),
                transcripts: Vec::new(),
                derived: Derived {
                    entities: vec![Entity {
                        uid: BRANCH.into(),
                        class: Class::Scope,
                        kind: kind::BRANCH.into(),
                        native_kind: "branch".into(),
                        name: name.into(),
                        parent: None,
                        occurred_at: None,
                    }],
                    statements,
                    relations: Vec::new(),
                },
            },
        }
    }

    fn statement(aspect: &str, reading: Reading) -> Statement {
        Statement {
            about: BRANCH.into(),
            aspect: aspect.into(),
            population: None,
            reading,
            note: None,
            transcripts: Vec::new(),
        }
    }

    fn checks(context: &str) -> Statement {
        let value = json!({"checks": [{"context": context, "source": "branch protection"}]});
        statement(aspect::REQUIRED_CHECKS, Reading::recorded(value).unwrap())
    }

    fn cells(ledger: &str, aspect: &str) -> String {
        let row = ledger
            .lines()
            .find(|line| line.trim_start().starts_with(aspect))
            .unwrap();
        row.trim_start()[aspect.len()..]
            .chars()
            .filter(|character| *character != ' ')
            .collect()
    }

    const NAME: &str = "github:example/service@main";

    #[test]
    fn a_cell_is_recorded_changed_a_gap_or_empty() {
        let denied = statement(aspect::BRANCH_PROTECTION, Reading::gap("permission denied"));
        let collections = [
            collection("2026-03-02T09:00:00Z", NAME, vec![checks("ci")]),
            collection("2026-04-06T09:00:00Z", NAME, vec![checks("ci"), denied]),
            collection("2026-05-04T09:00:00Z", NAME, vec![checks("lint")]),
        ];
        let rendered = ledger(&collections, 8);
        assert!(rendered
            .lines()
            .next()
            .unwrap()
            .ends_with("03-02  04-06  05-04"));
        assert_eq!(cells(&rendered, aspect::REQUIRED_CHECKS), "■■▣");
        assert_eq!(cells(&rendered, aspect::BRANCH_PROTECTION), "⬚");
    }

    #[test]
    fn a_change_is_measured_against_a_collection_that_is_not_shown() {
        let collections = [
            collection("2026-03-02T09:00:00Z", NAME, vec![checks("ci")]),
            collection("2026-04-06T09:00:00Z", NAME, vec![checks("lint")]),
        ];
        assert_eq!(
            cells(&ledger(&collections, 1), aspect::REQUIRED_CHECKS),
            "▣"
        );
    }

    #[test]
    fn a_renamed_entity_keeps_one_row_under_its_latest_name() {
        let collections = [
            collection("2026-03-02T09:00:00Z", NAME, vec![checks("ci")]),
            collection(
                "2026-04-06T09:00:00Z",
                "github:example/api@main",
                vec![checks("ci")],
            ),
        ];
        let rendered = ledger(&collections, 8);
        assert!(rendered.contains("github:example/api@main\n"));
        assert!(!rendered.contains("github:example/service@main"));
        assert_eq!(cells(&rendered, aspect::REQUIRED_CHECKS), "■■");
    }

    #[test]
    fn collections_on_one_day_are_labelled_with_their_time() {
        let collections = [
            collection("2026-03-02T09:00:00Z", NAME, vec![checks("ci")]),
            collection("2026-03-02T14:30:00Z", NAME, vec![checks("ci")]),
        ];
        let rendered = ledger(&collections, 8);
        assert!(rendered.lines().next().unwrap().contains("03-02 14:30"));
    }

    #[test]
    fn show_spells_out_each_statement() {
        let denied = statement(aspect::BRANCH_PROTECTION, Reading::gap("permission denied"));
        let latest = collection("2026-04-06T09:00:00Z", NAME, vec![denied, checks("ci")]);
        let rendered = show(&latest, None);
        assert!(rendered.contains("1 records, 1 gaps"));
        assert!(rendered.contains("github:example/service@main\n"));
        assert!(rendered.contains("⬚ branch protection  gap: permission denied"));
        assert!(rendered.contains("■ required checks    ci (branch protection)"));
    }

    #[test]
    fn work_items_are_not_rows() {
        let mut ticket = statement(aspect::TICKET, Reading::recorded(json!({})).unwrap());
        ticket.about = "github.com/ticket/1".into();
        let mut read = collection("2026-03-02T09:00:00Z", "example@main", vec![ticket]);
        read.contents.derived.entities.push(Entity {
            uid: "github.com/ticket/1".into(),
            class: Class::WorkItem,
            kind: kind::TICKET.into(),
            native_kind: "issue".into(),
            name: "example#1".into(),
            parent: None,
            occurred_at: None,
        });
        assert!(!ledger(&[read], 8).contains("example#1"));
    }
}
