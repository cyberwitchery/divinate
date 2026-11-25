//! one process against one collection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use time::{Duration, OffsetDateTime};

use super::{
    duration, By, Contribution, Count, Covered, Found, Measure, Measured, Outcome, Patterns,
    Process, Report, Row, Rule, Selected, Selection, Step, Target, When,
};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::model::{aspect, event, kind, relation, Class, Derived, Entity, Interval, Statement};
use crate::pack::{Asked, NoPacks, Packs, Shape};
use crate::record::Collection;
use crate::{format_time, parse_time};
/// check a process that uses no packs against one collection.
///
/// # Errors
///
/// returns an error when a time in the record or a duration in the process
/// cannot be parsed, or the process uses a pack.
pub fn check<'a>(
    process: &Process,
    collection: &'a Collection,
    earlier: &'a [Collection],
) -> Result<Report> {
    check_with(process, collection, earlier, &NoPacks)
}

/// check a process against one collection.
///
/// `earlier` are collections made before it. those of the same scope say
/// what a branch required at earlier times, so a change is held to the policy
/// read closest after its merge, and a policy that changed around the merge
/// is not guessed at. `packs` run the checks the process takes from packs.
///
/// # Errors
///
/// returns an error when a time in the record or a duration in the process
/// cannot be parsed, or a pack cannot be run or answers with something else
/// than it was asked for.
pub fn check_with<'a>(
    process: &Process,
    collection: &'a Collection,
    earlier: &'a [Collection],
    packs: &dyn Packs,
) -> Result<Report> {
    let derived = &collection.contents.derived;
    let mut index = Index::new(collection, earlier)?;
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
        overall: Vec::new(),
        measures: Vec::new(),
        references: references(process),
        packs: Vec::new(),
        frameworks: covered(process),
    };
    report.branches = branch_rows(process, derived, &index);
    let Some(items) = &process.items else {
        return Ok(report);
    };
    let (members, interval) = match members(items, derived) {
        Ok(found) => found,
        Err(reason) => {
            report.selected = Err(reason);
            return Ok(report);
        }
    };
    let about = json!({
        "scope": report.scope,
        "as_of": report.as_of,
        "interval": interval,
    });
    report.selected = Ok(Selected {
        kind: items.kind.clone(),
        label: items.label.as_ref().map(|label| label.0.clone()),
        when: items.when,
        into: items.into.clone(),
        paths: items.paths.as_ref().map(|paths| paths.0.clone()),
        read: members.len(),
        interval,
    });
    let chosen = index.chosen(items, &members);
    // what a pack is shown: the items of which something can be said.
    let shown = chosen
        .iter()
        .filter(|(_, unknown)| unknown.is_none())
        .map(|(item, _)| *item)
        .collect::<Vec<_>>();
    let mut asked = Asked::new(packs);
    for step in &process.steps {
        index.judge(step, &shown, &about, &mut asked)?;
    }
    for (item, unknown) in &chosen {
        let mut outcomes = Vec::new();
        for step in &process.steps {
            outcomes.push(match unknown {
                Some(reason) => Outcome::CannotTell(reason.clone()),
                None => index.step(step, item)?,
            });
        }
        report.rows.push(Row {
            item: item.name.clone(),
            outcomes,
        });
    }
    let all = chosen.iter().map(|(item, _)| *item).collect::<Vec<_>>();
    together(
        process,
        &index,
        &shown,
        &all,
        &about,
        &mut asked,
        &mut report,
    )?;
    report.packs = asked.used();
    Ok(report)
}

/// what the selected items show together: the outcomes of `overall`, and the
/// numbers of `measures`. packs are shown the items of which something can be
/// said, and the measures of this crate count all of them.
fn together(
    process: &Process,
    index: &Index,
    shown: &[&Entity],
    all: &[&Entity],
    about: &Value,
    asked: &mut Asked,
    report: &mut Report,
) -> Result<()> {
    let described = shown
        .iter()
        .map(|item| index.described(item, true))
        .collect::<Vec<_>>();
    for overall in &process.overall {
        let answer = asked.check(
            &overall.uses,
            Shape::AllItems,
            overall.with.as_ref(),
            about,
            &described,
        )?;
        report.overall.push(Found {
            name: overall.name.clone(),
            outcome: answered(&overall.uses, &answer)?,
        });
    }
    for measure in &process.measures {
        report.measures.push(match &measure.uses {
            None => index.measure(measure, report, all)?,
            Some(uses) => {
                let answer = asked.check(
                    uses,
                    Shape::Number,
                    measure.with.as_ref(),
                    about,
                    &described,
                )?;
                Measured {
                    name: measure.name.clone(),
                    value: answer["value"].as_f64(),
                    unit: answer["unit"].as_str().unwrap_or_default().to_owned(),
                    basis: answer["basis"].as_str().unwrap_or_default().to_owned(),
                }
            }
        });
    }
    Ok(())
}

/// the frameworks a process declares, with what its rules contribute to each
/// of their requirements.
fn covered(process: &Process) -> Vec<Covered> {
    process
        .frameworks
        .iter()
        .map(|(name, framework)| Covered {
            framework: name.clone(),
            title: framework.title.clone(),
            targets: framework
                .targets
                .iter()
                .map(|(id, title)| Target {
                    id: id.clone(),
                    title: title.clone(),
                    contributions: process
                        .mapped()
                        .flat_map(|(rule, maps)| maps.iter().map(move |mapping| (rule, mapping)))
                        .filter(|(_, mapping)| &mapping.framework == name && &mapping.target == id)
                        .map(|(rule, mapping)| Contribution {
                            rule: rule.to_owned(),
                            strength: mapping.strength,
                            limitation: mapping.limitation.clone(),
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
}

/// where each part of a process comes from, by its name.
fn references(process: &Process) -> BTreeMap<String, String> {
    let steps = process
        .steps
        .iter()
        .map(|step| (&step.name, &step.reference));
    let rules = process
        .branches
        .iter()
        .map(|rule| (&rule.name, &rule.reference));
    let overall = process
        .overall
        .iter()
        .map(|overall| (&overall.name, &overall.reference));
    let measures = process
        .measures
        .iter()
        .map(|measure| (&measure.name, &measure.reference));
    steps
        .chain(rules)
        .chain(overall)
        .chain(measures)
        .filter_map(|(name, reference)| Some((name.clone(), reference.clone()?)))
        .collect()
}

/// the outcome a pack answered with.
fn answered(uses: &str, answer: &Value) -> Result<Outcome> {
    let reason = || {
        answer["reason"]
            .as_str()
            .unwrap_or("the pack gave no reason")
            .to_owned()
    };
    Ok(match answer["outcome"].as_str() {
        Some("kept") => Outcome::Kept,
        Some("broken") => Outcome::Broken(reason()),
        Some("pending") => Outcome::Pending(reason()),
        Some("cannot_tell") => Outcome::CannotTell(reason()),
        Some("not_applicable") => Outcome::NotApplicable(reason()),
        other => {
            return Err(Error::Pack(format!(
                "{uses} answered with the outcome {other:?}, which is none of kept, broken, pending, cannot_tell, and not_applicable"
            )))
        }
    })
}

/// the items a process is about: whatever the collection's populations of
/// that kind list, with the period they cover. if one of them could not be
/// read, nothing can be said about "every" item.
fn members<'a>(
    items: &Selection,
    derived: &'a Derived,
) -> std::result::Result<(Vec<&'a str>, Option<Interval>), String> {
    let merged = items.when == When::Merged;
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
            return Err(format!("the {}s could not be read ({reason})", items.kind));
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
        return Err(format!("this collection did not read {}s", items.kind));
    };
    Ok((members, population.interval.clone()))
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
    /// what packs found, by the name of the step and the item it is about.
    judged: BTreeMap<(String, String), Outcome>,
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
            judged: BTreeMap::new(),
        })
    }

    /// the items a process selects, oldest first, each with the reason
    /// nothing can be said of it when the record does not hold what the
    /// selection asks about.
    fn chosen(&self, items: &Selection, members: &[&'a str]) -> Vec<(&'a Entity, Option<String>)> {
        let derived = self.derived;
        let mut selected = members
            .iter()
            .filter_map(|uid| derived.entity(uid))
            .filter(|item| {
                items.label.as_ref().is_none_or(|label| {
                    derived
                        .statement(&item.uid, &item.kind)
                        .and_then(|statement| statement.reading.value())
                        .and_then(|value| value["labels"].as_array())
                        .is_some_and(|labels| {
                            labels
                                .iter()
                                .filter_map(Value::as_str)
                                .any(|found| label.match_any(found, None))
                        })
                })
            })
            .collect::<Vec<_>>();
        selected.sort_by_key(|item| self.opened(item));
        let mut chosen = Vec::new();
        for item in selected {
            // a change into another branch is left out. one whose branch was
            // not read stays in, and nothing can be said of it.
            let targeted = items.into.as_deref().map(|into| self.goes_into(item, into));
            // so is a change that touches none of the paths. one whose files
            // were not read stays in as well.
            let touching = items.paths.as_ref().map(|paths| self.touches(item, paths));
            chosen.push(match (targeted, touching) {
                (Some(Some(false)), _) | (_, Some(Some(false))) => continue,
                (Some(None), _) => (
                    item,
                    Some(format!("the branch {} goes into was not read", item.name)),
                ),
                (_, Some(None)) => (
                    item,
                    Some(format!("the files {} touches were not read", item.name)),
                ),
                _ => (item, None),
            });
        }
        chosen
    }

    /// the items a step is about: the items themselves, or for a step with
    /// `linked` the items of that kind that close them.
    fn targets(&self, step: &Step, items: &[&'a Entity]) -> Vec<&'a Entity> {
        let Some(linked) = &step.linked else {
            return items.to_vec();
        };
        let mut seen = BTreeSet::new();
        items
            .iter()
            .flat_map(|item| self.closing.get(item.uid.as_str()).into_iter().flatten())
            .filter_map(|uid| self.derived.entity(uid))
            .filter(|target| &target.kind == linked && seen.insert(target.uid.as_str()))
            .collect()
    }

    /// let a pack judge the items of a step that uses one, and keep what it found.
    fn judge(
        &mut self,
        step: &Step,
        items: &[&'a Entity],
        about: &Value,
        asked: &mut Asked,
    ) -> Result<()> {
        let Some(uses) = &step.uses else {
            return Ok(());
        };
        let described = self
            .targets(step, items)
            .into_iter()
            .map(|target| self.described(target, true))
            .collect::<Vec<_>>();
        let answer = asked.check(uses, Shape::EachItem, step.with.as_ref(), about, &described)?;
        for result in answer["results"].as_array().into_iter().flatten() {
            if let Some(item) = result["item"].as_str() {
                self.judged.insert(
                    (step.name.clone(), item.to_owned()),
                    answered(uses, result)?,
                );
            }
        }
        Ok(())
    }

    /// what the record holds about one item, as a pack is shown it: what it
    /// is, what happened to it, and the items that close it.
    fn described(&self, item: &Entity, with_links: bool) -> Value {
        let name = |uid: &&str| self.derived.name(uid).to_owned();
        let state = self
            .derived
            .statement(&item.uid, &item.kind)
            .and_then(|statement| statement.reading.value());
        let read = self.derived.statement(&item.uid, aspect::EVENTS);
        let events = read.and_then(|read| read.reading.value()).map(|_| {
            self.events
                .get(item.uid.as_str())
                .into_iter()
                .flatten()
                .map(|event| {
                    json!({
                        "kind": event.kind,
                        "at": event.occurred_at,
                        // an event with no name of its own is named by its id.
                        "name": (event.name != event.uid).then_some(&event.name),
                        "by": self.actors.get(event.uid.as_str()).map(name),
                    })
                })
                .collect::<Vec<_>>()
        });
        let mut described = json!({
            "id": item.uid,
            "kind": item.kind,
            "name": item.name,
            "author": self.actors.get(item.uid.as_str()).map(name),
            "state": state,
            "events": events,
            // why the events, or some kinds of them, are not in the record.
            "unread": read.map(|read| match read.reading.gap_reason() {
                Some(reason) => json!({ "events": reason }),
                None => read.reading.value().map_or(Value::Null, |value| value["unread"].clone()),
            }),
        });
        if with_links {
            described["closed_by"] = self
                .closing
                .get(item.uid.as_str())
                .into_iter()
                .flatten()
                .filter_map(|uid| self.derived.entity(uid))
                .map(|closing| self.described(closing, false))
                .collect();
        }
        described
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

    /// whether a change touches a file whose path matches one of the
    /// patterns. `None` when the record does not hold its files.
    fn touches(&self, item: &Entity, paths: &Patterns) -> Option<bool> {
        let value = self
            .derived
            .statement(&item.uid, &item.kind)?
            .reading
            .value()?;
        Some(
            value["paths"]
                .as_array()?
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|path| paths.match_any(path, Some('/'))),
        )
    }

    /// one number over the items the process selected.
    fn measure(&self, measure: &Measure, report: &Report, chosen: &[&Entity]) -> Result<Measured> {
        if let Some(step) = &measure.share {
            let position = report.steps.iter().position(|name| name == step);
            let outcomes = report
                .rows
                .iter()
                .filter_map(|row| row.outcomes.get(position?));
            let (mut kept, mut broken, mut other) = (0_u32, 0_u32, 0_u32);
            for outcome in outcomes {
                match outcome {
                    Outcome::Kept => kept += 1,
                    Outcome::Broken(_) => broken += 1,
                    _ => other += 1,
                }
            }
            let counted = kept + broken;
            return Ok(Measured {
                name: measure.name.clone(),
                value: (counted > 0).then(|| f64::from(kept) * 100.0 / f64::from(counted)),
                unit: "percent".into(),
                basis: format!(
                    "{kept} of {counted} kept; {other} pending, unknown, or not applicable left out"
                ),
            });
        }
        let (from, to) = (
            measure.from.as_deref().unwrap_or_default(),
            measure.to.as_deref().unwrap_or_default(),
        );
        let mut hours = Vec::new();
        for item in chosen {
            let events = self
                .events
                .get(item.uid.as_str())
                .map_or(&[][..], Vec::as_slice);
            let Some(start) = events.iter().find(|event| event.kind == from) else {
                continue;
            };
            let start = at(start)?;
            for event in events.iter().filter(|event| event.kind == to) {
                let end = at(event)?;
                if end >= start {
                    hours.push((end - start).as_seconds_f64() / 3600.0);
                    break;
                }
            }
        }
        hours.sort_by(f64::total_cmp);
        let middle = hours.len() / 2;
        let median = match hours.len() {
            0 => None,
            count if count % 2 == 1 => Some(hours[middle]),
            _ => Some(f64::midpoint(hours[middle - 1], hours[middle])),
        };
        Ok(Measured {
            name: measure.name.clone(),
            value: median,
            unit: "hours".into(),
            basis: format!(
                "median from {from} to {to} over {} of {} items",
                hours.len(),
                chosen.len()
            ),
        })
    }

    /// whether the item carries what a step asks for instead of an event: a
    /// label, or for a release an attached file.
    fn carries(&self, step: &Step, target: &Entity) -> Option<Outcome> {
        let (wanted, field, what) = match (&step.label, &step.asset) {
            (Some(label), _) => (label, "labels", "label"),
            (None, Some(asset)) => (asset, "assets", "attached file"),
            (None, None) => return None,
        };
        let value = self
            .derived
            .statement(&target.uid, &target.kind)
            .and_then(|statement| statement.reading.value());
        let Some(value) = value else {
            return Some(Outcome::CannotTell(format!(
                "{} was not read in this collection",
                target.name
            )));
        };
        let Some(found) = value[field].as_array() else {
            return Some(Outcome::NotApplicable(format!(
                "a {} has no {what}s",
                target.kind
            )));
        };
        let carried = found
            .iter()
            .filter_map(|entry| entry.as_str().or_else(|| entry["name"].as_str()))
            .any(|name| wanted.match_any(name, None));
        let wanted = wanted.0.join(" or ");
        Some(if carried {
            Outcome::Kept
        } else if value["state"] == "open" {
            Outcome::Pending(format!("no {what} {wanted} yet"))
        } else {
            Outcome::Broken(format!("no {what} {wanted}"))
        })
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
        if let Some(outcome) = self.carries(step, target) {
            return Ok(outcome);
        }
        if step.uses.is_some() {
            let found = self.judged.get(&(step.name.clone(), target.uid.clone()));
            return Ok(found.cloned().unwrap_or_else(|| {
                Outcome::CannotTell(format!("the pack gave no result for {}", target.name))
            }));
        }
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
        if let Some(outcome) = unread(step, read, target) {
            return Ok(outcome);
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
        if let Some(by) = &step.by {
            wanted.push_str(&by.words());
        }
        if let Some(after) = &step.after {
            let _ = write!(wanted, " after the last {after}");
        }
        if step.of.is_some() {
            return Ok(self.each_required_check(step, target, &matching));
        }
        if let Some(names) = &step.named {
            return Ok(each_named(names, step, &matching, &wanted, closed));
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
        let outcome = self.counted(step, target, events, &matching, needed, &wanted, closed)?;
        // a count met against a policy that was only partly read is not known
        // to be enough.
        Ok(match (outcome, caveat) {
            (Outcome::Kept, Some(caveat)) => Outcome::CannotTell(caveat),
            (outcome, _) => outcome,
        })
    }

    /// whether enough of the events a step counts are there, and in time.
    #[allow(clippy::too_many_arguments)]
    fn counted(
        &self,
        step: &Step,
        target: &Entity,
        events: &[&Entity],
        matching: &[&Entity],
        needed: usize,
        wanted: &str,
        closed: bool,
    ) -> Result<Outcome> {
        Ok(if let Some(within) = &step.within {
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
                step.by.as_ref().is_none_or(|by| {
                    actor(event).is_some_and(|who| {
                        Some(&who) != author
                            && match by {
                                By::SomeoneElse => true,
                                By::Accounts(accounts) => self.is_one_of(who, accounts),
                            }
                    })
                })
            })
            .filter(|(time, event)| !taken_back(*time, event))
            // several events by one actor count once. a check has no actor,
            // and each one counts.
            .filter(|(_, event)| actor(event).is_none_or(|who| seen.insert(who)))
            .map(|(_, event)| *event)
            .collect())
    }

    /// whether an actor is one of the accounts a step names. the record names
    /// an actor as `<source>:<account>`.
    fn is_one_of(&self, actor: &str, accounts: &[String]) -> bool {
        let name = self.derived.name(actor);
        let account = name.split_once(':').map_or(name, |(_, account)| account);
        accounts
            .iter()
            .any(|wanted| wanted.eq_ignore_ascii_case(account))
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

/// some kinds of event can be unread while the rest was read. a step that
/// asks about one of them cannot be answered.
fn unread(step: &Step, read: &Statement, target: &Entity) -> Option<Outcome> {
    let mut asked = step.event.0.iter().chain(&step.before).chain(&step.after);
    let unread = read.reading.value().map(|value| &value["unread"]);
    let (kind, reason) = asked.find_map(|kind| Some((kind, unread?[kind.as_str()].as_str()?)))?;
    Some(Outcome::CannotTell(format!(
        "whether {} had a {kind} could not be read ({reason})",
        target.name
    )))
}

/// whether each name a step lists has an event of the step's kinds that
/// carries it.
fn each_named(
    names: &Patterns,
    step: &Step,
    matching: &[&Entity],
    wanted: &str,
    closed: bool,
) -> Outcome {
    let missing = names
        .0
        .iter()
        .filter(|name| {
            !matching
                .iter()
                .any(|event| super::matches(name, &event.name, None))
        })
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if missing.is_empty() {
        Outcome::Kept
    } else if let Some(before) = &step.before {
        Outcome::Broken(format!(
            "{before} without {wanted} named {missing} before it"
        ))
    } else if closed {
        Outcome::Broken(format!("closed without {wanted} named {missing}"))
    } else {
        Outcome::Pending(format!("no {wanted} named {missing} yet"))
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
