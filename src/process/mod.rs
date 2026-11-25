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

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::Duration;

pub use check::{check, check_with};
pub use render::{coverage, render, summary};

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
    #[serde(default)]
    /// what the selected items must show together, as a pack judges it.
    pub overall: Vec<Overall>,
    #[serde(default)]
    /// numbers worked out over the selected items.
    pub measures: Vec<Measure>,
    #[serde(default)]
    /// the frameworks the rules of this process map to, by a short name.
    pub frameworks: Frameworks,
}

/// frameworks by the short name mappings use for them.
pub type Frameworks = BTreeMap<String, Framework>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// a framework: a standard, a regulation, a policy.
pub struct Framework {
    #[serde(default)]
    /// its full name.
    pub title: Option<String>,
    /// the requirements it has, by their id, each with a title.
    pub targets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// what a rule contributes to one requirement of a framework.
pub struct Mapping {
    /// the short name of the framework.
    pub framework: String,
    /// the id of the requirement.
    pub target: String,
    pub strength: Strength,
    #[serde(default)]
    /// what the rule does not establish of the requirement, even when kept.
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// how much of a requirement a rule answers.
pub enum Strength {
    /// the rule answers the requirement.
    Full,
    /// the rule answers a part of it.
    Partial,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// one thing all selected items must show together.
pub struct Overall {
    pub name: String,
    /// the check of a pack that judges it, as `<pack>/<check>`.
    pub uses: String,
    #[serde(default)]
    /// what the check is told, as the pack defines it.
    pub with: Option<serde_json::Value>,
    #[serde(default, rename = "ref")]
    /// where the requirement comes from, such as a section of a policy.
    pub reference: Option<String>,
    #[serde(default)]
    /// the requirements of a framework this contributes to.
    pub maps: Vec<Mapping>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// a number over the selected items. either `share` is set, or `from` and `to`.
pub struct Measure {
    pub name: String,
    #[serde(default)]
    /// the check of a pack that works the number out, as `<pack>/<check>`.
    pub uses: Option<String>,
    #[serde(default)]
    /// what the check is told, as the pack defines it.
    pub with: Option<serde_json::Value>,
    #[serde(default, rename = "ref")]
    /// where the requirement comes from, such as a section of a policy.
    pub reference: Option<String>,
    #[serde(default)]
    /// the requirements of a framework this contributes to.
    pub maps: Vec<Mapping>,
    #[serde(default)]
    /// the name of a step: the share of items that kept it, among those that
    /// kept or broke it.
    pub share: Option<String>,
    #[serde(default)]
    /// the kind of event a time is counted from, such as `opened`.
    pub from: Option<String>,
    #[serde(default)]
    /// the kind of event a time is counted to, such as `closed`. the result
    /// is the median over the items that have both.
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// which work items a process applies to.
pub struct Selection {
    /// the kind of work item: `ticket`, `change`, or `finding`.
    pub kind: String,
    #[serde(default)]
    /// only items carrying a label that matches one of these patterns.
    pub label: Option<Patterns>,
    #[serde(default)]
    /// which items of the period: those opened in it, or those merged in it.
    pub when: When,
    #[serde(default)]
    /// only changes into this branch: a branch name, or `default branch` for
    /// the default branch of each repository.
    pub into: Option<String>,
    #[serde(default)]
    /// only changes that touch a file whose path matches one of these
    /// patterns, such as `src/auth/**`.
    pub paths: Option<Patterns>,
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
    #[serde(default, rename = "ref")]
    /// where the requirement comes from, such as a section of a policy.
    pub reference: Option<String>,
    #[serde(default)]
    /// the requirements of a framework this contributes to.
    pub maps: Vec<Mapping>,
    #[serde(default)]
    /// instead of an event: the check of a pack that judges each item, as
    /// `<pack>/<check>`.
    pub uses: Option<String>,
    #[serde(default)]
    /// what the check is told, as the pack defines it.
    pub with: Option<serde_json::Value>,
    #[serde(default)]
    /// look for the event on the items of this kind that close the item or
    /// that the source links to it, instead of on the item itself.
    pub linked: Option<String>,
    #[serde(default)]
    /// the kind of event that must exist, such as `comment` or `approval`, or
    /// several kinds of which one must exist.
    pub event: Events,
    #[serde(default)]
    /// instead of an event: the item carries a label that matches one of
    /// these patterns.
    pub label: Option<Patterns>,
    #[serde(default)]
    /// instead of an event: a file attached to the release has a name that
    /// matches one of these patterns.
    pub asset: Option<Patterns>,
    #[serde(default)]
    /// one such event for each of these names, such as the name of a check.
    pub named: Option<Patterns>,
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

#[derive(Debug, Default, Deserialize)]
#[serde(from = "OneOrMany")]
/// one or more kinds of event.
pub struct Events(pub Vec<String>);

/// one or more patterns, written the same way. in a pattern `*` stands for
/// any run of characters and `?` for one. in a path `*` stops at a `/` and
/// `**` does not.
pub type Patterns = Events;

/// whether a text matches a pattern. `separator` is the character a single
/// `*` does not cross, for paths.
#[must_use]
pub fn matches(pattern: &str, text: &str, separator: Option<char>) -> bool {
    let (pattern, text) = (
        pattern.chars().collect::<Vec<_>>(),
        text.chars().collect::<Vec<_>>(),
    );
    glob(&pattern, &text, separator)
}

fn glob(pattern: &[char], text: &[char], separator: Option<char>) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((&'*', rest)) => {
            let deep = rest.first() == Some(&'*');
            let rest = if deep { &rest[1..] } else { rest };
            // `**/` also matches no directory at all.
            if deep && rest.first() == separator.as_ref() && glob(&rest[1..], text, separator) {
                return true;
            }
            (0..=text.len())
                .take_while(|&taken| taken == 0 || deep || Some(text[taken - 1]) != separator)
                .any(|taken| glob(rest, &text[taken..], separator))
        }
        Some((&'?', rest)) => text
            .split_first()
            .is_some_and(|(first, text)| Some(*first) != separator && glob(rest, text, separator)),
        Some((expected, rest)) => text
            .split_first()
            .is_some_and(|(first, text)| first == expected && glob(rest, text, separator)),
    }
}

impl Events {
    /// whether one of the patterns matches a text.
    #[must_use]
    pub fn match_any(&self, text: &str, separator: Option<char>) -> bool {
        self.0
            .iter()
            .any(|pattern| matches(pattern, text, separator))
    }
}

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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(try_from = "OneOrMany")]
/// who must have caused the event.
pub enum By {
    /// anyone but the actor who opened the item the event is on.
    SomeoneElse,
    /// one of these accounts, and not the actor who opened the item.
    Accounts(Vec<String>),
}

impl TryFrom<OneOrMany> for By {
    type Error = String;

    fn try_from(written: OneOrMany) -> std::result::Result<Self, String> {
        match written {
            OneOrMany::One(word) if word == "someone else" => Ok(Self::SomeoneElse),
            OneOrMany::One(word) => Err(format!(
                "`by` is `someone else` or a list of accounts, not {word:?}"
            )),
            OneOrMany::Many(accounts) if accounts.is_empty() => {
                Err("`by` needs at least one account".into())
            }
            OneOrMany::Many(accounts) => Ok(Self::Accounts(accounts)),
        }
    }
}

impl By {
    /// the condition in words, to follow the name of an event.
    #[must_use]
    pub fn words(&self) -> String {
        match self {
            Self::SomeoneElse => " by someone else".into(),
            Self::Accounts(accounts) => format!(" by {}", accounts.join(" or ")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// one thing every branch must show. exactly one of the three is set.
pub struct Rule {
    pub name: String,
    #[serde(default, rename = "ref")]
    /// where the requirement comes from, such as a section of a policy.
    pub reference: Option<String>,
    #[serde(default)]
    /// the requirements of a framework this contributes to.
    pub maps: Vec<Mapping>,
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
    parse(&text, path)
}

/// read a process definition from yaml text. `origin` says where the text
/// came from, for an error.
///
/// # Errors
///
/// returns an error when the text is not a process definition, or asks for
/// something this build cannot check.
pub fn parse(text: &str, origin: &Path) -> Result<Process> {
    parse_with(text, origin, &Frameworks::new())
}

/// read a process definition from yaml text, with frameworks it can map to
/// beside those it declares itself, such as those of the pack that ships it.
///
/// # Errors
///
/// returns an error when the text is not a process definition, or asks for
/// something this build cannot check.
pub fn parse_with(text: &str, origin: &Path, shared: &Frameworks) -> Result<Process> {
    let mut process: Process = serde_saphyr::from_str(text).map_err(|source| Error::Yaml {
        path: origin.to_path_buf(),
        source: Box::new(source),
    })?;
    for (name, framework) in shared {
        process
            .frameworks
            .entry(name.clone())
            .or_insert_with(|| framework.clone());
    }
    let about_items =
        !process.steps.is_empty() || !process.overall.is_empty() || !process.measures.is_empty();
    if !about_items && process.branches.is_empty() {
        return Err(Error::Invalid(
            "a process needs `steps` for work items or rules for `branches`".into(),
        ));
    }
    if process.items.is_none() && about_items {
        return Err(Error::Invalid(
            "`steps`, `overall`, and `measures` need `items` to say which work items they apply to"
                .into(),
        ));
    }
    validate(&process)?;
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

impl Process {
    /// every rule by its name, with what it maps to.
    pub(crate) fn mapped(&self) -> impl Iterator<Item = (&str, &[Mapping])> {
        let steps = self.steps.iter().map(|step| (&step.name, &step.maps));
        let rules = self.branches.iter().map(|rule| (&rule.name, &rule.maps));
        let overall = self
            .overall
            .iter()
            .map(|overall| (&overall.name, &overall.maps));
        let measures = self
            .measures
            .iter()
            .map(|measure| (&measure.name, &measure.maps));
        steps
            .chain(rules)
            .chain(overall)
            .chain(measures)
            .map(|(name, maps)| (name.as_str(), maps.as_slice()))
    }
}

/// refuse a mapping to a framework or requirement the process does not declare.
fn mapped_to_declared(process: &Process) -> Result<()> {
    for (rule, maps) in process.mapped() {
        for mapping in maps {
            let known = process
                .frameworks
                .get(&mapping.framework)
                .is_some_and(|framework| framework.targets.contains_key(&mapping.target));
            if !known {
                return Err(Error::Invalid(format!(
                    "{rule:?} maps to {:?} of {:?}, which `frameworks` does not declare",
                    mapping.target, mapping.framework
                )));
            }
        }
    }
    Ok(())
}

/// refuse a definition whose measures or steps ask for something that
/// cannot be checked.
fn validate(process: &Process) -> Result<()> {
    mapped_to_declared(process)?;
    for measure in &process.measures {
        let timed = measure.from.is_some() && measure.to.is_some();
        let known = |step: &String| process.steps.iter().any(|known| &known.name == step);
        if measure.uses.is_some() {
            if measure.share.is_some() || measure.from.is_some() || measure.to.is_some() {
                return Err(Error::Invalid(format!(
                    "measure {:?}: `uses` stands alone",
                    measure.name
                )));
            }
            continue;
        }
        match &measure.share {
            Some(step) if measure.from.is_none() && measure.to.is_none() && known(step) => {}
            Some(step) if !known(step) => {
                return Err(Error::Invalid(format!(
                    "measure {:?}: there is no step named {step:?}",
                    measure.name
                )));
            }
            None if timed && process.items.is_some() => {}
            _ => {
                return Err(Error::Invalid(format!(
                    "measure {:?}: use `share` with the name of a step, `from` and `to` with kinds of event, or `uses` with the check of a pack",
                    measure.name
                )));
            }
        }
    }
    for step in &process.steps {
        let asked = [
            !step.event.0.is_empty(),
            step.label.is_some(),
            step.asset.is_some(),
            step.uses.is_some(),
        ];
        if asked.iter().filter(|asked| **asked).count() != 1 {
            return Err(Error::Invalid(format!(
                "step {:?}: use exactly one of `event`, `label`, `asset`, and `uses`",
                step.name
            )));
        }
        if step.with.is_some() && step.uses.is_none() {
            return Err(Error::Invalid(format!(
                "step {:?}: `with` goes with `uses`",
                step.name
            )));
        }
        let timed = step.within.is_some() || step.before.is_some() || step.after.is_some();
        let counted = step.at_least.is_some() || step.of.is_some() || step.named.is_some();
        if step.event.0.is_empty() && (timed || counted || step.by.is_some()) {
            return Err(Error::Invalid(format!(
                "step {:?}: `label`, `asset`, and `uses` stand alone, or with `linked`",
                step.name
            )));
        }
        if step.named.is_some()
            && (step.within.is_some() || step.at_least.is_some() || step.of.is_some())
        {
            return Err(Error::Invalid(format!(
                "step {:?}: `named` cannot be used with `within`, `at least`, or `of`",
                step.name
            )));
        }
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
    Ok(())
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    /// what the selected items show together.
    pub overall: Vec<Found>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    /// the numbers the process asks for.
    pub measures: Vec<Measured>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    /// where each step, rule, and measure comes from, where the process says so.
    pub references: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    /// the packs that judged a part of this, with their versions.
    pub packs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    /// the frameworks the process maps to, with what its rules contribute to
    /// each requirement.
    pub frameworks: Vec<Covered>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one framework, and what a process contributes to its requirements.
pub struct Covered {
    /// the short name of the framework.
    pub framework: String,
    pub title: Option<String>,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one requirement of a framework.
pub struct Target {
    pub id: String,
    pub title: String,
    /// the rules that contribute to it. none when the process has no rule
    /// for it.
    pub contributions: Vec<Contribution>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one rule's part in a requirement.
pub struct Contribution {
    /// the name of the step, rule, or measure.
    pub rule: String,
    pub strength: Strength,
    pub limitation: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
/// what a pack found of all selected items together.
pub struct Found {
    pub name: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Serialize, PartialEq)]
/// one number over the selected items.
pub struct Measured {
    pub name: String,
    /// the number, or nothing when no item counts towards it.
    pub value: Option<f64>,
    /// `percent` or `hours`.
    pub unit: String,
    /// how many items the number rests on, and how many were left out.
    pub basis: String,
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
    /// the patterns a label must match, when the process names any.
    pub label: Option<Vec<String>>,
    pub when: When,
    /// the branch the changes must go into, when the process names one.
    pub into: Option<String>,
    /// the patterns a changed path must match, when the process names any.
    pub paths: Option<Vec<String>>,
    pub read: usize,
    pub interval: Option<Interval>,
}

#[derive(Debug, Serialize)]
/// one item and the outcome of each step, in the order the steps were written.
pub struct Row {
    pub item: String,
    pub outcomes: Vec<Outcome>,
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn a_star_stops_at_a_separator_and_two_do_not() {
        let path = |pattern, text| matches(pattern, text, Some('/'));
        assert!(path("src/*.rs", "src/main.rs"));
        assert!(!path("src/*.rs", "src/source/work.rs"));
        assert!(path("src/**", "src/source/work.rs"));
        assert!(path("**/*.rs", "main.rs"));
        assert!(path("**/*.rs", "src/source/work.rs"));
        assert!(path("src/**/work.rs", "src/work.rs"));
        assert!(path(".gitlab-ci.yml", ".gitlab-ci.yml"));
        assert!(!path("*.yml", "ci/build.yml"));
        assert!(path("ci/?uild.yml", "ci/build.yml"));
        assert!(!path("src", "src/main.rs"));
    }

    #[test]
    fn without_a_separator_a_star_matches_anything() {
        assert!(matches(
            "scan-*",
            "scan-kyverno-policies: [production]",
            None
        ));
        assert!(matches("sensitivity::*", "sensitivity::high", None));
        assert!(!matches("sast", "sast-extra", None));
        assert!(matches("*", "", None));
    }
}
