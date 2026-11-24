//! a checked process, in words.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::{Report, Row, When};

const LABELS: [&str; 5] = ["kept", "broken", "pending", "cannot tell", "n/a"];

/// render a report: the items against the steps and the branches against the
/// rules, a count per column, and the reason for everything that is not kept.
#[must_use]
pub fn render(report: &Report) -> String {
    let mut out = format!(
        "{} · {} · as of {}\n",
        report.process, report.scope, report.as_of
    );
    if !report.steps.is_empty() {
        match &report.selected {
            Err(reason) => {
                let _ = writeln!(out, "cannot tell: {reason}");
            }
            Ok(selected) => {
                let when = match selected.when {
                    When::Opened => "opened",
                    When::Merged => "merged",
                };
                let period = selected
                    .interval
                    .as_ref()
                    .map_or_else(String::new, |interval| {
                        format!(" {when} {} to {}", interval.from, interval.until)
                    });
                let mut chosen = selected.label.as_ref().map_or_else(String::new, |label| {
                    format!(", {} labelled {label:?}", report.rows.len())
                });
                if let Some(into) = &selected.into {
                    let _ = write!(chosen, ", {} into {into}", report.rows.len());
                }
                let _ = writeln!(
                    out,
                    "{}s{period}: {} read{chosen}",
                    selected.kind, selected.read
                );
                table(&mut out, "item", &report.steps, &report.rows);
            }
        }
    }
    if !report.rules.is_empty() {
        table(&mut out, "branch", &report.rules, &report.branches);
    }
    let mut reasons = String::new();
    for (columns, rows) in [
        (&report.steps, &report.rows),
        (&report.rules, &report.branches),
    ] {
        for row in rows {
            for (column, outcome) in columns.iter().zip(&row.outcomes) {
                if let Some(detail) = outcome.detail() {
                    let _ = writeln!(
                        reasons,
                        "  {} · {column}: {}, {detail}",
                        row.item,
                        outcome.label()
                    );
                }
            }
        }
    }
    if !reasons.is_empty() {
        let _ = write!(out, "\nnot kept\n{reasons}");
    }
    out
}

/// one table: a row per item or branch, a column per step or rule, and a
/// count per column.
fn table(out: &mut String, what: &str, columns: &[String], rows: &[Row]) {
    out.push('\n');
    if rows.is_empty() {
        let _ = writeln!(out, "no {what} to check");
        return;
    }
    let first = rows
        .iter()
        .map(|row| row.item.len())
        .max()
        .unwrap_or(0)
        .max(what.len());
    let widths = columns
        .iter()
        .map(|column| column.len().max("cannot tell".len()))
        .collect::<Vec<_>>();
    let _ = write!(out, "{what:<first$}");
    for (column, width) in columns.iter().zip(&widths) {
        let _ = write!(out, "  {column:<width$}");
    }
    out.push('\n');
    for row in rows {
        let _ = write!(out, "{:<first$}", row.item);
        for (outcome, width) in row.outcomes.iter().zip(&widths) {
            let _ = write!(out, "  {:<width$}", outcome.label());
        }
        out.push('\n');
    }
    out.push('\n');
    let width = columns.iter().map(String::len).max().unwrap_or(0);
    for (position, column) in columns.iter().enumerate() {
        let _ = writeln!(out, "{column:<width$}  {}", counted(rows, position));
    }
}

/// how often each outcome occurs in one column: `5 kept, 1 broken`.
fn counted(rows: &[Row], position: usize) -> String {
    let mut counts = BTreeMap::<&str, usize>::new();
    for row in rows {
        *counts.entry(row.outcomes[position].label()).or_default() += 1;
    }
    let counted = LABELS
        .iter()
        .filter_map(|label| Some(format!("{} {label}", counts.get(label)?)))
        .collect::<Vec<_>>();
    if counted.is_empty() {
        "nothing to check".into()
    } else {
        counted.join(", ")
    }
}

/// render several reports of one process as one table: a row per collection,
/// a column per step and rule, each cell the counts of its outcomes. the
/// reports may be of one scope over time, or of several scopes.
#[must_use]
pub fn summary(reports: &[Report]) -> String {
    let Some(first) = reports.first() else {
        return "no collection to check\n".into();
    };
    let columns = first.steps.iter().chain(&first.rules).collect::<Vec<_>>();
    let cells = reports
        .iter()
        .map(|report| {
            let mut cells = Vec::new();
            for position in 0..report.steps.len() {
                cells.push(match &report.selected {
                    Err(reason) => format!("cannot tell: {reason}"),
                    Ok(_) => counted(&report.rows, position),
                });
            }
            for position in 0..report.rules.len() {
                cells.push(counted(&report.branches, position));
            }
            cells
        })
        .collect::<Vec<_>>();
    let mut out = format!("{}\n", first.process);
    for (report, cells) in reports.iter().zip(&cells) {
        let _ = writeln!(out, "\n{} · as of {}", report.scope, report.as_of);
        let width = columns.iter().map(|column| column.len()).max().unwrap_or(0);
        for (column, cell) in columns.iter().zip(cells) {
            let _ = writeln!(out, "  {column:<width$}  {cell}");
        }
    }
    out
}
