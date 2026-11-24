//! one process against one collection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use time::{Duration, OffsetDateTime};

use super::{duration, Count, Outcome, Process, Report, Row, Rule, Selected, Step, When};
use crate::error::Result;
use crate::model::{aspect, event, kind, relation, Class, Derived, Entity, Statement};
use crate::record::Collection;
use crate::{format_time, parse_time};
/// check a process against one collection.
///
/// `earlier` are collections made before it. those of the same scope say
/// what a branch required at earlier times, so a change is held to the policy
/// read closest after its merge, and a policy that changed around the merge
/// is not guessed at.
///
/// # Errors
///
/// returns an error when a time in the record or a duration in the process
/// cannot be parsed.
pub fn check<'a>(
    process: &Process,
    collection: &'a Collection,
    earlier: &'a [Collection],
) -> Result<Report> {
    let derived = &collection.contents.derived;
    let index = Index::new(collection, earlier)?;
    let mut report = Report {
        process: process.process.clone(),
        scope: collection.contents.scope.clone(),
        as_of: collection.contents.completed_at.clone(),
        selected: Err("the process selects no work items".into()),
        steps: process.steps.iter().map(|step| step.name.clone()).collect(),
        rows: Vec::new(),
        rules: process
            .branches
            .iter()
            .map(|rule| rule.name.clone())
            .collect(),
        branches: Vec::new(),
    };
    report.branches = branch_rows(process, derived, &index);
    let Some(items) = &process.items else {
        return Ok(report);
    };
    report.selected = Err(format!("this collection did not read {}s", items.kind));
    let merged = items.when == When::Merged;
    // the items are whatever the collection's populations of this kind list.
    // if one of them could not be read, nothing can be said about "every" item.
    let populations = derived
        .statements
        .iter()
        .filter_map(|statement| Some((statement, statement.population.as_ref()?)))
        .filter(|(statement, population)| {
            population.of == items.kind && (statement.aspect == aspect::MERGED_CHANGES) == merged
        })
        .collect::<Vec<_>>();
    let mut members = Vec::new();
    for (statement, _) in &populations {
        let Some(value) = statement.reading.value() else {
            let reason = statement.reading.gap_reason().unwrap_or_default();
            report.selected = Err(format!("the {}s could not be read ({reason})", items.kind));
            return Ok(report);
        };
        members.extend(
            value["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str),
        );
    }
    let Some((_, population)) = populations.first() else {
        return Ok(report);
    };
    report.selected = Ok(Selected {
        kind: items.kind.clone(),
        label: items.label.clone(),
        when: items.when,
        into: items.into.clone(),
        read: members.len(),
        interval: population.interval.clone(),
    });
    let mut selected = members
        .iter()
        .filter_map(|uid| derived.entity(uid))
        .filter(|item| {
            items.label.as_ref().is_none_or(|label| {
                derived
                    .statement(&item.uid, &item.kind)
                    .and_then(|statement| statement.reading.value())
                    .and_then(|value| value["labels"].as_array())
                    .is_some_and(|labels| labels.iter().any(|found| found.as_str() == Some(label)))
            })
        })
        .collect::<Vec<_>>();
    selected.sort_by_key(|item| index.opened(item));
    for item in selected {
        // a change into another branch is left out. one whose branch was not
        // read stays in, and nothing can be said of it.
        let targeted = items
            .into
            .as_deref()
            .map(|into| index.goes_into(item, into));
        if targeted == Some(Some(false)) {
            continue;
        }
        let mut outcomes = Vec::new();
        for step in &process.steps {
            outcomes.push(match targeted {
                Some(None) => {
                    Outcome::CannotTell(format!("the branch {} goes into was not read", item.name))
                }
                _ => index.step(step, item)?,
            });
        }
        report.rows.push(Row {
            item: item.name.clone(),
            outcomes,
        });
    }
    Ok(report)
}

/// one row per branch the collection read, with the outcome of each rule.
fn branch_rows(process: &Process, derived: &Derived, index: &Index) -> Vec<Row> {
    if process.branches.is_empty() {
        return Vec::new();
    }
    let mut branches = derived
        .entities
        .iter()
        .filter(|entity| entity.kind == kind::BRANCH)
        .collect::<Vec<_>>();
    branches.sort_by_key(|branch| &branch.name);
    branches
        .into_iter()
        .map(|branch| Row {
            item: branch.name.clone(),
            outcomes: process
                .branches
                .iter()
                .map(|rule| index.rule(rule, branch))
                .collect(),
        })
        .collect()
}

/// the record, arranged for the questions a step asks.
struct Index<'a> {
    derived: &'a Derived,
    now: OffsetDateTime,
    /// the events of each work item, in the order they happened.
    events: BTreeMap<&'a str, Vec<&'a Entity>>,
    /// who the source names for each event and work item.
    actors: BTreeMap<&'a str, &'a str>,
    /// the items that close an item, or that the source links to it.
    closing: BTreeMap<&'a str, Vec<&'a str>>,
    /// the branch each change goes into, where the record has read the branch.
    into: BTreeMap<&'a str, &'a str>,
    /// every reading of this scope up to this collection, oldest first.
    samples: Vec<(OffsetDateTime, &'a Derived)>,
}

impl<'a> Index<'a> {
    fn new(collection: &'a Collection, earlier: &'a [Collection]) -> Result<Self> {
        let derived = &collection.contents.derived;
        let now = parse_time(&collection.contents.completed_at)?;
        let mut samples = Vec::new();
        for sample in earlier
            .iter()
            .filter(|earlier| earlier.contents.scope == collection.contents.scope)
            .chain([collection])
        {
            let read_at = parse_time(&sample.contents.completed_at)?;
            samples.push((read_at, &sample.contents.derived));
        }
        samples.sort_by_key(|(read_at, _)| *read_at);
        let mut events = BTreeMap::<&str, Vec<&Entity>>::new();
        for entity in &derived.entities {
            if let (Class::Event, Some(parent)) = (entity.class, entity.parent.as_deref()) {
                events.entry(parent).or_default().push(entity);
            }
        }
        for events in events.values_mut() {
            events.sort_by_key(|event| event.occurred_at.clone());
        }
        let mut actors = BTreeMap::new();
        let mut closing = BTreeMap::<&str, Vec<&str>>::new();
        let mut into = BTreeMap::new();
        for link in &derived.relations {
            if link.kind == relation::BY {
                actors.insert(link.from.as_str(), link.to.as_str());
            } else if link.kind == relation::INTO {
                into.insert(link.from.as_str(), link.to.as_str());
            } else if link.kind == relation::REFERS_TO && relation::resolves(&link.basis) {
                closing.entry(&link.to).or_default().push(&link.from);
            }
        }
        Ok(Self {
            derived,
            now,
            events,
            actors,
            closing,
            into,
            samples,
        })
    }

    fn opened(&self, item: &Entity) -> Option<String> {
        self.events
            .get(item.uid.as_str())?
            .iter()
            .find(|event| event.kind == event::OPENED)?
            .occurred_at
            .clone()
    }

    /// whether a change goes into a branch: one with a name, or the default
    /// branch of its repository. `None` when the record does not say.
    fn goes_into(&self, item: &Entity, into: &str) -> Option<bool> {
        let value = self
            .derived
            .statement(&item.uid, &item.kind)?
            .reading
            .value()?;
        if into == "default branch" {
            value["targets_default_branch"].as_bool()
        } else {
            Some(value["target_branch"].as_str()? == into)
        }
    }

    /// one step for one item: on the item itself, or on each item that closes
    /// it or is linked to it.
    fn step(&self, step: &Step, item: &Entity) -> Result<Outcome> {
        let Some(linked) = &step.linked else {
            return self.on(step, item);
        };
        let mut outcome =
            Outcome::NotApplicable(format!("no {linked} closes it or is linked to it"));
        for uid in self.closing.get(item.uid.as_str()).into_iter().flatten() {
            let Some(target) = self
                .derived
                .entity(uid)
                .filter(|target| &target.kind == linked)
            else {
                continue;
            };
            let found = match self.on(step, target)? {
                Outcome::Kept => Outcome::Kept,
                Outcome::Broken(detail) => Outcome::Broken(format!("{}: {detail}", target.name)),
                Outcome::Pending(detail) => Outcome::Pending(format!("{}: {detail}", target.name)),
                Outcome::CannotTell(detail) => Outcome::CannotTell(detail),
                Outcome::NotApplicable(detail) => {
                    Outcome::NotApplicable(format!("{}: {detail}", target.name))
                }
            };
            if found.weight() >= outcome.weight() {
                outcome = found;
            }
        }
        Ok(outcome)
    }

    /// one rule for one branch: what its policy requires, or what happened to it.
    fn rule(&self, rule: &Rule, branch: &Entity) -> Outcome {
        let (aspect, what) = if rule.approvals.is_some() {
            (aspect::REVIEW_POLICY, "review policy")
        } else if rule.checks.is_some() {
            (aspect::REQUIRED_CHECKS, "required checks")
        } else {
            (aspect::UPDATES, "updates")
        };
        let Some(statement) = self.derived.statement(&branch.uid, aspect) else {
            return Outcome::CannotTell(format!("its {what} were not read in this collection"));
        };
        let Some(value) = statement.reading.value() else {
            let reason = statement.reading.gap_reason().unwrap_or_default();
            return Outcome::CannotTell(format!("its {what} could not be read ({reason})"));
        };
        if let Some(needed) = rule.approvals {
            let required = value["requirements"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|requirement| requirement["required_approvals"].as_u64())
                .max()
                .unwrap_or(0);
            return at_least(required, needed, "approval");
        }
        if let Some(needed) = rule.checks {
            let required = value["checks"].as_array().map_or(0, Vec::len);
            return at_least(u64::try_from(required).unwrap_or(u64::MAX), needed, "check");
        }
        let unwanted = rule.without.as_ref().map_or(&[][..], |kinds| &kinds.0);
        let found = self
            .events
            .get(branch.uid.as_str())
            .into_iter()
            .flatten()
            .filter(|event| unwanted.contains(&event.kind))
            .collect::<Vec<_>>();
        match (found.first(), &statement.note) {
            (Some(first), _) => Outcome::Broken(format!(
                "{} of them, the first a {} at {}",
                found.len(),
                first.kind,
                first.occurred_at.as_deref().unwrap_or("an unknown time")
            )),
            // nothing found in a reading that does not reach the whole period
            // is not a finding of nothing.
            (None, Some(note)) => Outcome::CannotTell(note.clone()),
            (None, None) => Outcome::Kept,
        }
    }

    /// one step on the item the event must be on.
    fn on(&self, step: &Step, target: &Entity) -> Result<Outcome> {
        let read = self.derived.statement(&target.uid, aspect::EVENTS);
        let Some(read) = read else {
            return Ok(Outcome::CannotTell(format!(
                "{} was not read in this collection",
                target.name
            )));
        };
        if let Some(reason) = read.reading.gap_reason() {
            return Ok(Outcome::CannotTell(format!(
                "what happened to {} could not be read ({reason})",
                target.name
            )));
        }
        // some kinds of event can be unread while the rest was read.
        let mut asked = step.event.0.iter().chain(&step.before).chain(&step.after);
        let unread = read.reading.value().map(|value| &value["unread"]);
        if let Some((kind, reason)) =
            asked.find_map(|kind| Some((kind, unread?[kind.as_str()].as_str()?)))
        {
            return Ok(Outcome::CannotTell(format!(
                "whether {} had a {kind} could not be read ({reason})",
                target.name
            )));
        }
        let events = self
            .events
            .get(target.uid.as_str())
            .map_or(&[][..], Vec::as_slice);
        let closed = events.iter().any(|event| event.kind == event::CLOSED);
        // with `before`, only what happened before that event counts.
        let bound = match &step.before {
            None => None,
            Some(before) => match events.iter().find(|event| &event.kind == before) {
                Some(bound) => Some(at(bound)?),
                None if closed => {
                    return Ok(Outcome::NotApplicable(format!("closed without a {before}")))
                }
                None => return Ok(Outcome::Pending(format!("no {before} yet"))),
            },
        };
        let matching = self.matching(step, target, events, bound)?;
        let mut wanted = step.event.words();
        if step.by.is_some() {
            wanted.push_str(" by someone else");
        }
        if let Some(after) = &step.after {
            let _ = write!(wanted, " after the last {after}");
        }
        if step.of.is_some() {
            return Ok(self.each_required_check(step, target, &matching));
        }
        let (needed, caveat) = match step.at_least {
            None => (1, None),
            Some(Count::Number(needed)) => (needed, None),
            Some(Count::Required) => match self.required_approvals(target) {
                Ok(required) => required,
                Err(outcome) => return Ok(outcome),
            },
        };
        if needed != 1 {
            let _ = write!(wanted, " ({needed} needed)");
        }
        let outcome = if let Some(within) = &step.within {
            let Some(opened) = events.iter().find(|event| event.kind == event::OPENED) else {
                return Ok(Outcome::CannotTell(format!(
                    "{} has no recorded opening time",
                    target.name
                )));
            };
            let opened = at(opened)?;
            let deadline = opened + duration(within)?;
            // the event that completes the count is the one that must be in time.
            match needed.checked_sub(1).and_then(|last| matching.get(last)) {
                _ if needed == 0 => Outcome::Kept,
                Some(last) if at(last)? <= deadline => Outcome::Kept,
                Some(last) => {
                    Outcome::Broken(format!("{wanted} after {}", elapsed(at(last)? - opened)))
                }
                None if self.now < deadline => {
                    Outcome::Pending(format!("{wanted} due by {}", format_time(deadline)?))
                }
                None => Outcome::Broken(format!("no {wanted} within {within}")),
            }
        } else if matching.len() >= needed {
            Outcome::Kept
        } else if let Some(before) = &step.before {
            if matching.is_empty() {
                Outcome::Broken(format!("{before} without {wanted} before it"))
            } else {
                Outcome::Broken(format!(
                    "{before} with {} {wanted} before it",
                    matching.len()
                ))
            }
        } else if closed {
            Outcome::Broken(format!("closed without {wanted}"))
        } else {
            Outcome::Pending(format!("no {wanted} yet"))
        };
        // a count met against a policy that was only partly read is not known
        // to be enough.
        Ok(match (outcome, caveat) {
            (Outcome::Kept, Some(caveat)) => Outcome::CannotTell(caveat),
            (outcome, _) => outcome,
        })
    }

    /// the events a step counts on one item: of its kinds, before the bound,
    /// after the last event the step names, by the actors it allows, still
    /// standing, and one per actor.
    fn matching(
        &self,
        step: &Step,
        target: &Entity,
        events: &[&'a Entity],
        bound: Option<OffsetDateTime>,
    ) -> Result<Vec<&'a Entity>> {
        let mut timed = Vec::new();
        for event in events {
            let time = at(event)?;
            if bound.is_none_or(|bound| time < bound) {
                timed.push((time, *event));
            }
        }
        let floor = step.after.as_ref().and_then(|after| {
            timed
                .iter()
                .filter(|(_, event)| &event.kind == after)
                .map(|(time, _)| *time)
                .max()
        });
        let author = self.actors.get(target.uid.as_str());
        let actor = |event: &Entity| self.actors.get(event.uid.as_str()).copied();
        // an actor takes an event back with a later one, such as a request
        // for changes after an approval.
        let taken_back = |time: OffsetDateTime, event: &Entity| {
            let revoking = event::revoked_by(&event.kind);
            actor(event).is_some_and(|who| {
                timed.iter().any(|(later, other)| {
                    *later > time
                        && revoking.contains(&other.kind.as_str())
                        && actor(other) == Some(who)
                })
            })
        };
        let mut seen = BTreeSet::new();
        Ok(timed
            .iter()
            .filter(|(_, event)| step.event.0.contains(&event.kind))
            .filter(|(time, _)| floor.is_none_or(|floor| *time > floor))
            // an event with no named actor cannot be shown to be someone else's.
            .filter(|(_, event)| {
                step.by.is_none() || actor(event).is_some_and(|who| Some(&who) != author)
            })
            .filter(|(time, event)| !taken_back(*time, event))
            // several events by one actor count once.
            .filter(|(_, event)| actor(event).is_none_or(|who| seen.insert(who)))
            .map(|(_, event)| *event)
            .collect())
    }

    /// the branch a change goes into, and one statement about it. an outcome
    /// when the record has not read the branch or the statement.
    fn of_branch(
        &self,
        target: &Entity,
        aspect: &str,
    ) -> std::result::Result<&'a Statement, Outcome> {
        let unread = |what: &str| {
            Outcome::CannotTell(format!(
                "{what} of the branch {} goes into was not read",
                target.name
            ))
        };
        let branch = self
            .into
            .get(target.uid.as_str())
            .ok_or_else(|| unread("the policy"))?;
        // a merged change is held to the policy read closest after its merge.
        let merged = self
            .events
            .get(target.uid.as_str())
            .into_iter()
            .flatten()
            .find(|event| event.kind == event::MERGE)
            .and_then(|merge| at(merge).ok());
        let position = merged.map_or(self.samples.len().saturating_sub(1), |merged| {
            self.samples
                .partition_point(|(read_at, _)| *read_at < merged)
                .min(self.samples.len().saturating_sub(1))
        });
        let read = |position: usize| {
            let (read_at, derived) = self.samples.get(position)?;
            Some((*read_at, derived.statement(branch, aspect)?))
        };
        let (read_at, statement) =
            read(position).ok_or_else(|| unread(&format!("the {aspect}")))?;
        if let Some(reason) = statement.reading.gap_reason() {
            return Err(Outcome::CannotTell(format!(
                "the {aspect} of the branch {} goes into could not be read ({reason})",
                target.name
            )));
        }
        // the reading before the merge shows whether the policy changed around it.
        let before = position.checked_sub(1).and_then(read);
        match before {
            Some((earlier, before)) if before.reading.digest() != statement.reading.digest() => {
                let time = |time| format_time(time).unwrap_or_default();
                Err(Outcome::CannotTell(format!(
                    "the {aspect} changed between {} and {}, and {} was merged in between",
                    time(earlier),
                    time(read_at),
                    target.name
                )))
            }
            _ => Ok(statement),
        }
    }

    /// how many approvals the branch a change goes into requires, as the
    /// collection read it, and what the reading leaves open.
    fn required_approvals(
        &self,
        target: &Entity,
    ) -> std::result::Result<(usize, Option<String>), Outcome> {
        let policy = self.of_branch(target, aspect::REVIEW_POLICY)?;
        let required = policy
            .reading
            .value()
            .and_then(|value| value["requirements"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|requirement| requirement["required_approvals"].as_u64())
            .max()
            .unwrap_or(0);
        Ok((
            usize::try_from(required).unwrap_or(usize::MAX),
            policy.note.clone(),
        ))
    }

    /// whether each check the branch requires has an event of the step's
    /// kinds that carries its name.
    fn each_required_check(&self, step: &Step, target: &Entity, matching: &[&Entity]) -> Outcome {
        let policy = match self.of_branch(target, aspect::REQUIRED_CHECKS) {
            Ok(policy) => policy,
            Err(outcome) => return outcome,
        };
        let required = policy
            .reading
            .value()
            .and_then(|value| value["checks"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|check| check["context"].as_str())
            .collect::<BTreeSet<_>>();
        let missing = required
            .iter()
            .filter(|name| !matching.iter().any(|event| event.name == **name))
            .copied()
            .collect::<Vec<_>>();
        let when = step
            .before
            .as_ref()
            .map_or_else(String::new, |before| format!(" before the {before}"));
        match (missing.is_empty(), &policy.note) {
            (false, _) => Outcome::Broken(format!(
                "no {} for {}{when}",
                step.event.words(),
                missing.join(", ")
            )),
            (true, Some(note)) => Outcome::CannotTell(note.clone()),
            (true, None) if required.is_empty() => {
                Outcome::NotApplicable("the branch requires no checks".into())
            }
            (true, None) => Outcome::Kept,
        }
    }
}

fn at(event: &Entity) -> Result<OffsetDateTime> {
    parse_time(event.occurred_at.as_deref().unwrap_or_default())
}

fn at_least(required: u64, needed: u64, what: &str) -> Outcome {
    if required >= needed {
        Outcome::Kept
    } else if required == 0 {
        Outcome::Broken(format!("no {what} is required"))
    } else {
        Outcome::Broken(format!("{required} {what}s required, not {needed}"))
    }
}

fn elapsed(duration: Duration) -> String {
    if duration.whole_days() >= 1 {
        format!("{} days", duration.whole_days())
    } else {
        format!("{} hours", duration.whole_hours())
    }
}
