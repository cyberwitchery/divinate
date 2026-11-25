//! from transcripts to statements, and from statements to words.

use serde_json::Value;

use crate::error::Result;
use crate::model::{aspect, Derived, Reading, Statement};
use crate::transcript::Transcript;

/// derive everything a collection says from its transcripts.
///
/// the result depends on the transcripts alone, so it can be recomputed from
/// a stored record.
///
/// # Errors
///
/// returns an error when a retained body is not what its resource returns.
pub fn derive(transcripts: &[Transcript]) -> Result<Derived> {
    let source = crate::source::for_transcripts(transcripts)?;
    Ok(source.derive(transcripts)?.sorted())
}

/// describe a statement in one line.
#[must_use]
pub fn summary(statement: &Statement) -> String {
    let value = match &statement.reading {
        Reading::Gap { reason } => return format!("gap: {reason}"),
        Reading::Recorded { value, .. } => value,
    };
    if let Some(population) = &statement.population {
        return population_summary(&population.of, items(value, "members").len());
    }
    match statement.aspect.as_str() {
        aspect::PROJECT => value["visibility"]
            .as_str()
            .unwrap_or("visibility unknown")
            .to_owned(),
        aspect::REPOSITORY => repository_summary(value),
        aspect::BRANCH_PROTECTION => protection_summary(value),
        aspect::BRANCH_RULES => rules_summary(value),
        aspect::REVIEW_POLICY => review_summary(value),
        aspect::REQUIRED_CHECKS => checks_summary(value),
        _ => "recorded".into(),
    }
}

fn items<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value[name].as_array().map_or(&[], Vec::as_slice)
}

fn population_summary(of: &str, count: usize) -> String {
    let plural = match of.strip_suffix('y') {
        Some(stem) => format!("{stem}ies"),
        None => format!("{of}s"),
    };
    match count {
        0 => format!("no {plural}"),
        1 => format!("1 {of}"),
        count => format!("{count} {plural}"),
    }
}

fn repository_summary(value: &Value) -> String {
    let mut parts = vec![value["visibility"]
        .as_str()
        .unwrap_or("visibility unknown")
        .to_owned()];
    match value["default_branch"].as_str() {
        Some(branch) => parts.push(format!("default branch {branch}")),
        None => parts.push("no default branch".into()),
    }
    for flag in ["archived", "fork"] {
        if value[flag] == Value::Bool(true) {
            parts.push(flag.into());
        }
    }
    parts.join(", ")
}

fn protection_summary(value: &Value) -> String {
    if value["protected"] != Value::Bool(true) {
        return "not protected".into();
    }
    // some sources say who may merge and push to a protected branch.
    let allowed = ["merge", "push"]
        .iter()
        .filter_map(|action| {
            let names = items(value, action)
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            (!names.is_empty()).then(|| format!("{action}: {}", names.join(", ")))
        })
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        "protected".into()
    } else {
        format!("protected ({})", allowed.join("; "))
    }
}

fn rules_summary(value: &Value) -> String {
    let mut types = items(value, "rules")
        .iter()
        .filter_map(|rule| rule["type"].as_str())
        .collect::<Vec<_>>();
    types.dedup();
    if types.is_empty() {
        "no rules".into()
    } else {
        types.join(", ")
    }
}

fn review_summary(value: &Value) -> String {
    let requirements = items(value, "requirements");
    if requirements.is_empty() {
        return "no review required".into();
    }
    requirements
        .iter()
        .map(|requirement| {
            let source = requirement["source"].as_str().unwrap_or("unknown source");
            match requirement["required_approvals"].as_u64() {
                Some(1) => format!("1 approval ({source})"),
                Some(count) => format!("{count} approvals ({source})"),
                None => format!("approvals not reported ({source})"),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn checks_summary(value: &Value) -> String {
    let checks = items(value, "checks");
    if checks.is_empty() {
        return "none required".into();
    }
    checks
        .iter()
        .map(|check| {
            format!(
                "{} ({})",
                check["context"].as_str().unwrap_or("unnamed"),
                check["source"].as_str().unwrap_or("unknown source")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::Population;

    fn statement(aspect: &str, reading: Reading) -> Statement {
        Statement {
            about: "github.com/branch/7/main".into(),
            aspect: aspect.into(),
            population: None,
            reading,
            note: None,
            transcripts: Vec::new(),
        }
    }

    fn recorded(aspect: &str, value: Value) -> Statement {
        statement(aspect, Reading::recorded(value).unwrap())
    }

    #[test]
    fn a_gap_is_summarised_by_its_reason() {
        let gap = statement(
            aspect::BRANCH_PROTECTION,
            Reading::gap("permission denied: HTTP 403"),
        );
        assert_eq!(summary(&gap), "gap: permission denied: HTTP 403");
    }

    #[test]
    fn review_and_check_summaries_name_their_source() {
        let review = recorded(
            aspect::REVIEW_POLICY,
            json!({"requirements": [{"source": "branch protection", "required_approvals": 1}]}),
        );
        assert_eq!(summary(&review), "1 approval (branch protection)");
        let checks = recorded(
            aspect::REQUIRED_CHECKS,
            json!({"checks": [{"context": "success", "source": "ruleset 26609762"}]}),
        );
        assert_eq!(summary(&checks), "success (ruleset 26609762)");
    }

    #[test]
    fn a_population_is_summarised_by_its_size() {
        let mut listed = recorded(aspect::REPOSITORIES, json!({"members": ["a", "b"]}));
        listed.population = Some(Population {
            of: "repository".into(),
            interval: None,
        });
        assert_eq!(summary(&listed), "2 repositories");
        assert_eq!(population_summary("ticket", 1), "1 ticket");
        assert_eq!(population_summary("change", 0), "no changes");
    }

    #[test]
    fn a_repository_is_summarised_by_what_it_is() {
        let repository = recorded(
            aspect::REPOSITORY,
            json!({"visibility": "public", "default_branch": "main", "archived": true, "fork": false}),
        );
        assert_eq!(
            summary(&repository),
            "public, default branch main, archived"
        );
    }
}
