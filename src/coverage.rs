//! collection coverage for a proposition, subject, and interval.
//!
//! [`assess`] composes authoritative collection runs and returns uncovered
//! intervals. complete runs require terminal pagination. retention-limited runs
//! contribute only their observed intervals.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::Result;
use crate::model::{CollectionOutcome, CollectionRun, Corpus, Proposition, TimeRange};
use crate::parse_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the population a claim needs covered: a proposition, a subject, and an interval.
pub struct CoverageRequirement {
    pub proposition: Proposition,
    pub repository: String,
    pub branch: Option<String>,
    pub interval: TimeRange,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether authoritative collection covered the whole required interval.
pub enum CoverageOutcome {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// why one collection run did or did not contribute coverage.
pub enum RunDisposition {
    Used,
    ScopeMismatch,
    NotAuthoritative,
    PaginationIncomplete,
    PermissionDenied,
    RetentionLimited,
    Interrupted,
    Failed,
    NotAttempted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// one run's disposition, its reason, and the interval it contributed.
pub struct RunAssessment {
    pub collection_run_id: String,
    pub disposition: RunDisposition,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// what this run added, which may be narrower than what it requested.
    pub contributed_interval: Option<TimeRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// required, covered, and uncovered intervals.
pub struct CoverageDecision {
    pub requirement: CoverageRequirement,
    pub outcome: CoverageOutcome,
    /// the merged intervals authoritative collection actually reached.
    pub covered_intervals: Vec<TimeRange>,
    /// intervals without authoritative coverage.
    pub uncovered_intervals: Vec<TimeRange>,
    pub collection_runs: Vec<RunAssessment>,
}

/// assess whether authoritative collection runs cover a required population and interval.
///
/// intervals are half-open. complete adjacent or overlapping runs may compose. a
/// retention-limited run contributes only its explicitly observed interval.
///
/// # Errors
///
/// returns an error when a collection or requirement contains an invalid timestamp.
pub fn assess(
    corpus: &Corpus,
    requirement: CoverageRequirement,
    known_at: OffsetDateTime,
) -> Result<CoverageDecision> {
    let required = parsed_range(&requirement.interval)?;
    if required.from >= required.until {
        return Err(crate::error::Error::Invalid(
            "coverage interval must have positive duration".into(),
        ));
    }
    let mut contributions = Vec::new();
    let mut assessments = Vec::new();

    for run in &corpus.collections {
        if parse_timestamp(&run.completed_at)? > known_at {
            continue;
        }
        if run.subject.id != requirement.repository
            || run.requested_scope.proposition != requirement.proposition
            || run.requested_scope.branch != requirement.branch
        {
            continue;
        }

        let (disposition, reason, contribution) = assess_run(run, &requirement, required)?;
        if let Some(interval) = contribution {
            contributions.push(interval);
        }
        assessments.push(RunAssessment {
            collection_run_id: run.id.clone(),
            disposition,
            reason,
            contributed_interval: contribution.map(serialized_range).transpose()?,
        });
    }

    let covered = merge_intervals(contributions);
    let gaps = gaps(required, &covered);
    let outcome = if gaps.is_empty() {
        CoverageOutcome::Complete
    } else {
        CoverageOutcome::Incomplete
    };

    Ok(CoverageDecision {
        requirement,
        outcome,
        covered_intervals: covered
            .into_iter()
            .map(serialized_range)
            .collect::<Result<_>>()?,
        uncovered_intervals: gaps
            .into_iter()
            .map(serialized_range)
            .collect::<Result<_>>()?,
        collection_runs: assessments,
    })
}

fn assess_run(
    run: &CollectionRun,
    requirement: &CoverageRequirement,
    required: Interval,
) -> Result<(RunDisposition, String, Option<Interval>)> {
    if !run.authority.contains(&requirement.proposition) {
        return Ok((
            RunDisposition::NotAuthoritative,
            format!(
                "collector did not claim authority for {:?}",
                requirement.proposition
            ),
            None,
        ));
    }
    let unavailable = match run.outcome {
        CollectionOutcome::PermissionDenied => Some((
            RunDisposition::PermissionDenied,
            "collector attempted the population but source access was denied",
        )),
        CollectionOutcome::Interrupted => Some((
            RunDisposition::Interrupted,
            "collection was interrupted before it completed",
        )),
        CollectionOutcome::Failed => Some((
            RunDisposition::Failed,
            "collection failed before coverage was established",
        )),
        CollectionOutcome::NotAttempted => Some((
            RunDisposition::NotAttempted,
            "the required population was not collected",
        )),
        CollectionOutcome::Partial
        | CollectionOutcome::Complete
        | CollectionOutcome::RetentionLimited => None,
    };
    if let Some((disposition, fallback)) = unavailable {
        return Ok((disposition, limitation_reason(run, fallback), None));
    }
    if !run.enumeration.terminal_page_reached || run.enumeration.next_token_present {
        return Ok((
            RunDisposition::PaginationIncomplete,
            format!(
                "enumeration stopped after {} item(s) and {} page(s); terminal pagination state was not reached",
                run.enumeration.items_fetched, run.enumeration.pages_fetched
            ),
            None,
        ));
    }
    if run.outcome == CollectionOutcome::Partial {
        return Ok((
            RunDisposition::PaginationIncomplete,
            "collection reported a partial result".into(),
            None,
        ));
    }

    let Some(observed_scope) = &run.observed_scope else {
        return Ok((
            RunDisposition::ScopeMismatch,
            "collection recorded no observed scope".into(),
            None,
        ));
    };
    if observed_scope.proposition != requirement.proposition
        || observed_scope.branch != requirement.branch
    {
        return Ok((
            RunDisposition::ScopeMismatch,
            "observed scope does not match the required population".into(),
            None,
        ));
    }
    let observed = parsed_range(&observed_scope.interval)?;
    let Some(overlap) = intersection(required, observed) else {
        return Ok((
            RunDisposition::ScopeMismatch,
            "observed interval does not overlap the required interval".into(),
            None,
        ));
    };
    if run.outcome == CollectionOutcome::RetentionLimited {
        return Ok((
            RunDisposition::RetentionLimited,
            limitation_reason(
                run,
                "source retention limited the observed interval; only that interval contributes coverage",
            ),
            Some(overlap),
        ));
    }
    Ok((
        RunDisposition::Used,
        "complete authoritative enumeration contributes coverage".into(),
        Some(overlap),
    ))
}

fn limitation_reason(run: &CollectionRun, fallback: &str) -> String {
    run.limitations
        .first()
        .map_or_else(|| fallback.into(), |item| item.detail.clone())
}

#[derive(Debug, Clone, Copy)]
struct Interval {
    from: OffsetDateTime,
    until: OffsetDateTime,
}

fn parsed_range(range: &TimeRange) -> Result<Interval> {
    Ok(Interval {
        from: parse_timestamp(&range.from)?,
        until: parse_timestamp(&range.until)?,
    })
}

fn serialized_range(range: Interval) -> Result<TimeRange> {
    Ok(TimeRange {
        from: format_time(range.from)?,
        until: format_time(range.until)?,
    })
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| crate::error::Error::Invalid(format!("cannot format timestamp: {error}")))
}

fn intersection(left: Interval, right: Interval) -> Option<Interval> {
    let from = left.from.max(right.from);
    let until = left.until.min(right.until);
    (from < until).then_some(Interval { from, until })
}

fn merge_intervals(mut intervals: Vec<Interval>) -> Vec<Interval> {
    intervals.sort_by_key(|item| item.from);
    let mut merged: Vec<Interval> = Vec::new();
    for interval in intervals {
        if let Some(last) = merged.last_mut() {
            if interval.from <= last.until {
                last.until = last.until.max(interval.until);
                continue;
            }
        }
        merged.push(interval);
    }
    merged
}

fn gaps(required: Interval, covered: &[Interval]) -> Vec<Interval> {
    let mut cursor = required.from;
    let mut result = Vec::new();
    for interval in covered {
        if cursor < interval.from {
            result.push(Interval {
                from: cursor,
                until: interval.from,
            });
        }
        cursor = cursor.max(interval.until);
    }
    if cursor < required.until {
        result.push(Interval {
            from: cursor,
            until: required.until,
        });
    }
    result
}
