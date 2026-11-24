//! checking a process someone has promised to follow against the record.
//!
//! a [`Process`] is written by the person who made the promise. it selects
//! work items and lists the steps each must show, and it can say what every
//! branch must require. [`check`] reads one collection and says, for every
//! item and step and for every branch and rule, whether the promise was kept.
//! it adds nothing to the record, and another reader can apply their own
//! process to the same collection.

mod check;
mod render;

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::Duration;

pub use check::check;
pub use render::{render, summary};

use crate::error::{Error, Result};
use crate::model::Interval;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// a process, as its owner wrote it down.
pub struct Process {
    /// what the process is called.
    pub process: String,
    #[serde(default)]
    /// which work items the steps apply to.
    pub items: Option<Selection>,
    #[serde(default)]
    /// what each item must show.
    pub steps: Vec<Step>,
    #[serde(default)]
    /// what every branch that was read must require.
    pub branches: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// which work items a process applies to.
pub struct Selection {
    /// the kind of work item: `ticket`, `change`, or `finding`.
    pub kind: String,
    #[serde(default)]
    /// only items carrying this label.
    pub label: Option<String>,
    #[serde(default)]
    /// which items of the period: those opened in it, or those merged in it.
    pub when: When,
    #[serde(default)]
    /// only changes into this branch: a branch name, or `default branch` for
    /// the default branch of each repository.
    pub into: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// what puts an item into the period of a collection.
pub enum When {
    #[default]
    Opened,
    Merged,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// one thing an item must show: an event, optionally in time, in order, by
/// someone else, or on a linked item.
pub struct Step {
    pub name: String,
    #[serde(default)]
    /// look for the event on the items of this kind that close the item or
    /// that the source links to it, instead of on the item itself.
    pub linked: Option<String>,
    /// the kind of event that must exist, such as `comment` or `approval`, or
    /// several kinds of which one must exist.
    pub event: Events,
    #[serde(default)]
    pub by: Option<By>,
    #[serde(default, rename = "at least")]
    /// how many such events there must be, each by a different actor: a
    /// number, or `required` for what the branch the change goes into
    /// requires. one when not given.
    pub at_least: Option<Count>,
    #[serde(default)]
    /// the kind of event it must come after, such as `commit`: the last one
    /// counts.
    pub after: Option<String>,
    #[serde(default)]
    /// `required checks`: one such event for each check the branch the change
    /// goes into requires, named as the check is.
    pub of: Option<String>,
    #[serde(default)]
    /// how long after the item was opened the event may come, such as `7d` or `12h`.
    pub within: Option<String>,
    #[serde(default)]
    /// the kind of event it must come before, such as `merge`.
    pub before: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(try_from = "NumberOrWord")]
/// how many events a step asks for.
pub enum Count {
    Number(usize),
    /// as many as the review policy of the branch requires.
    Required,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NumberOrWord {
    Number(usize),
    Word(String),
}

impl TryFrom<NumberOrWord> for Count {
    type Error = String;

    fn try_from(written: NumberOrWord) -> std::result::Result<Self, String> {
        match written {
            NumberOrWord::Number(0) => Err("`at least` must be one or more".into()),
            NumberOrWord::Number(count) => Ok(Self::Number(count)),
            NumberOrWord::Word(word) if word == "required" => Ok(Self::Required),
            NumberOrWord::Word(word) => Err(format!(
                "`at least` is a number or `required`, not {word:?}"
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(from = "OneOrMany")]
/// one or more kinds of event.
pub struct Events(pub Vec<String>);

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Events {
    fn from(written: OneOrMany) -> Self {
        match written {
            OneOrMany::One(kind) => Self(vec![kind]),
            OneOrMany::Many(kinds) => Self(kinds),
        }
    }
}

impl Events {
    /// the kinds, as words: `closed or dismissed`.
    #[must_use]
    pub fn words(&self) -> String {
        self.0.join(" or ")
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
/// who must have caused the event.
pub enum By {
    #[serde(rename = "someone else")]
    /// anyone but the actor who opened the item the event is on.
    SomeoneElse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// one thing every branch must show. exactly one of the three is set.
pub struct Rule {
    pub name: String,
    #[serde(default)]
    /// a change needs at least this many approvals before it is merged.
    pub approvals: Option<u64>,
    #[serde(default)]
    /// a change needs at least this many checks to pass before it is merged.
    pub checks: Option<u64>,
    #[serde(default)]
    /// the branch saw no update of these kinds, such as `push`.
    pub without: Option<Events>,
}

/// read a process definition from a yaml file.
///
/// # Errors
///
/// returns an error when the file cannot be read, is not a process
/// definition, or asks for something this build cannot check.
pub fn load(path: &Path) -> Result<Process> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let process: Process = serde_saphyr::from_str(&text).map_err(|source| Error::Yaml {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if process.steps.is_empty() && process.branches.is_empty() {
        return Err(Error::Invalid(
            "a process needs `steps` for work items or rules for `branches`".into(),
        ));
    }
    if process.items.is_none() && !process.steps.is_empty() {
        return Err(Error::Invalid(
            "`steps` need `items` to say which work items they apply to".into(),
        ));
    }
    for step in &process.steps {
        if step.within.is_some() && step.before.is_some() {
            return Err(Error::Invalid(format!(
                "step {:?}: use `within` or `before`, not both",
                step.name
            )));
        }
        if let Some(within) = &step.within {
            duration(within)?;
        }
        match step.of.as_deref() {
            None => {}
            Some("required checks") if step.within.is_none() && step.at_least.is_none() => {}
            Some("required checks") => {
                return Err(Error::Invalid(format!(
                    "step {:?}: `of` cannot be used with `within` or `at least`",
                    step.name
                )));
            }
            Some(other) => {
                return Err(Error::Invalid(format!(
                    "step {:?}: `of` takes `required checks`, not {other:?}",
                    step.name
                )));
            }
        }
    }
    for rule in &process.branches {
        let set = [
            rule.approvals.is_some(),
            rule.checks.is_some(),
            rule.without.is_some(),
        ];
        if set.iter().filter(|set| **set).count() != 1 {
            return Err(Error::Invalid(format!(
                "branch rule {:?}: use exactly one of `approvals`, `checks`, and `without`",
                rule.name
            )));
        }
    }
    Ok(process)
}

/// parse `<number>d` or `<number>h`.
fn duration(value: &str) -> Result<Duration> {
    let invalid = || Error::Invalid(format!("{value:?} is not a duration such as 7d or 12h"));
    let split = value.len().checked_sub(1).ok_or_else(invalid)?;
    let count = value[..split].parse::<i64>().map_err(|_| invalid())?;
    match &value[split..] {
        "d" => Ok(Duration::days(count)),
        "h" => Ok(Duration::hours(count)),
        _ => Err(invalid()),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", content = "reason", rename_all = "snake_case")]
/// what the record shows for one step of one item.
pub enum Outcome {
    Kept,
    /// the step was not kept, and why.
    Broken(String),
    /// the step can still be kept: its time has not run out, or the item is open.
    Pending(String),
    /// the record cannot say, and what is missing.
    CannotTell(String),
    /// the step does not apply to this item, and why.
    NotApplicable(String),
}

impl Outcome {
    /// the outcome in a word or two.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Kept => "kept",
            Self::Broken(_) => "broken",
            Self::Pending(_) => "pending",
            Self::CannotTell(_) => "cannot tell",
            Self::NotApplicable(_) => "n/a",
        }
    }

    pub(super) fn detail(&self) -> Option<&str> {
        match self {
            Self::Kept => None,
            Self::Broken(detail)
            | Self::Pending(detail)
            | Self::CannotTell(detail)
            | Self::NotApplicable(detail) => Some(detail),
        }
    }

    /// which outcome stands for several: the one that most needs attention.
    pub(super) fn weight(&self) -> u8 {
        match self {
            Self::Broken(_) => 4,
            Self::CannotTell(_) => 3,
            Self::Pending(_) => 2,
            Self::Kept => 1,
            Self::NotApplicable(_) => 0,
        }
    }
}

#[derive(Debug, Serialize)]
/// a process checked against one collection.
pub struct Report {
    pub process: String,
    pub scope: String,
    /// the time of the reading. a deadline after it has not been missed yet.
    pub as_of: String,
    /// how many items the collection read and how many the process selects,
    /// or why the collection cannot say which items exist.
    #[serde(serialize_with = "selection")]
    pub selected: std::result::Result<Selected, String>,
    pub steps: Vec<String>,
    pub rows: Vec<Row>,
    /// the names of the branch rules.
    pub rules: Vec<String>,
    /// one row per branch that was read, with the outcome of each rule.
    pub branches: Vec<Row>,
}

/// write the selection as itself, or as the reason it could not be made.
fn selection<S: serde::Serializer>(
    selected: &std::result::Result<Selected, String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match selected {
        Ok(selected) => selected.serialize(serializer),
        Err(reason) => serde_json::json!({ "cannot_tell": reason }).serialize(serializer),
    }
}

#[derive(Debug, Serialize)]
/// the items a process applies to.
pub struct Selected {
    pub kind: String,
    pub label: Option<String>,
    pub when: When,
    /// the branch the changes must go into, when the process names one.
    pub into: Option<String>,
    pub read: usize,
    pub interval: Option<Interval>,
}

#[derive(Debug, Serialize)]
/// one item and the outcome of each step, in the order the steps were written.
pub struct Row {
    pub item: String,
    pub outcomes: Vec<Outcome>,
}
