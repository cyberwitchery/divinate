//! findings: what github's code, dependency, and secret scanning reported.

use serde_json::Value;

use super::capture::{CODE_SCANNING, DEPENDABOT, SECRET_SCANNING};
use super::work::actor;
use crate::error::Result;
use crate::model::{event, kind, Entity};
use crate::source::build::{self, find, Span};
use crate::source::work::{Details, Happened, Item, Work};
use crate::transcript::{Termination, Transcript};

/// one of github's scanners: where its alerts are read from, what the record
/// calls its findings, and where an alert keeps what it is about.
struct Scanner {
    resource: &'static str,
    /// the aspect of the population, such as `code scanning findings`.
    aspect: &'static str,
    native_kind: &'static str,
    /// the word for it in an item's name and id.
    slug: &'static str,
    title: fn(&Value) -> Value,
    severity: fn(&Value) -> Value,
}

const SCANNERS: [Scanner; 3] = [
    Scanner {
        resource: CODE_SCANNING,
        aspect: "code scanning findings",
        native_kind: "code scanning alert",
        slug: "code-scanning",
        title: |alert| alert["rule"]["description"].clone(),
        severity: |alert| {
            let rule = &alert["rule"];
            if rule["security_severity_level"].is_string() {
                rule["security_severity_level"].clone()
            } else {
                rule["severity"].clone()
            }
        },
    },
    Scanner {
        resource: DEPENDABOT,
        aspect: "dependency findings",
        native_kind: "dependabot alert",
        slug: "dependabot",
        title: |alert| alert["security_advisory"]["summary"].clone(),
        severity: |alert| alert["security_advisory"]["severity"].clone(),
    },
    Scanner {
        resource: SECRET_SCANNING,
        aspect: "secret findings",
        native_kind: "secret scanning alert",
        slug: "secret-scanning",
        title: |alert| alert["secret_type_display_name"].clone(),
        severity: |_| Value::Null,
    },
];

/// derive the findings of one repository opened in the period, one population
/// per scanner. github keeps every alert, so what happened to each is in the
/// alert itself.
pub(super) fn derive(
    repository: &Entity,
    repository_id: u64,
    transcripts: &[Transcript],
    work: &mut Work,
) -> Result<()> {
    for scanner in &SCANNERS {
        let Some(listing) = find(transcripts, scanner.resource) else {
            continue;
        };
        let period = Span::of(listing);
        for alert in build::items(listing) {
            let (true, Some(number)) =
                (period.holds(&alert["created_at"]), alert["number"].as_u64())
            else {
                continue;
            };
            let id = format!("{repository_id}/{}/{number}", scanner.slug);
            let fixed = [&alert["fixed_at"], &alert["resolved_at"]]
                .into_iter()
                .find(|at| at.is_string());
            let dismissed = &alert["dismissed_at"];
            let mut events = Vec::new();
            if let Some(at) = fixed.and_then(Value::as_str) {
                let by = actor(&alert["resolved_by"]);
                events.push(Happened::new(event::CLOSED, format!("closed/{id}"), at).by(by));
            } else if let Some(at) = dismissed.as_str() {
                let by = actor(&alert["dismissed_by"]);
                events.push(Happened::new(event::DISMISSED, format!("dismissed/{id}"), at).by(by));
            }
            let item = Item {
                kind: kind::FINDING,
                native_kind: scanner.native_kind.into(),
                id,
                name: format!("{} {}#{number}", repository.name, scanner.slug),
                number,
                title: (scanner.title)(&alert),
                state: match alert["state"].as_str() {
                    Some("open") => "open",
                    _ => "closed",
                },
                labels: (scanner.severity)(&alert)
                    .as_str()
                    .map(str::to_owned)
                    .into_iter()
                    .collect(),
                opened_at: alert["created_at"].clone(),
                closed_at: fixed.unwrap_or(dismissed).clone(),
                merged_at: Value::Null,
                author: None,
                target: None,
            };
            let mut details = Details::unread();
            details.events = Ok(events);
            details.transcripts.push(listing);
            work.item(item, &[scanner.aspect], listing, details)?;
        }
        match not_set_up(listing) {
            Some(why) => work.nothing(kind::FINDING, scanner.aspect, listing, why)?,
            None => work.population(kind::FINDING, scanner.aspect, &[listing])?,
        }
    }
    Ok(())
}

/// github answers with an error when a scanner is not set up. that is an
/// answer about the repository, not a failed reading.
fn not_set_up(listing: &Transcript) -> Option<String> {
    let (Termination::PermissionDenied { diagnostic } | Termination::NotFound { diagnostic }) =
        &listing.contents.termination
    else {
        return None;
    };
    let said = diagnostic.to_ascii_lowercase();
    [
        "disabled",
        "not enabled",
        "no analysis found",
        "must be enabled",
    ]
    .iter()
    .any(|phrase| said.contains(phrase))
    .then(|| format!("the scanner is not set up ({diagnostic})"))
}
