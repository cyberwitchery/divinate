#[path = "../common.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PACK_ID: &str = "cyberwitchery.github";
const PACK_VERSION: &str = "0.1.0";

fn main() {
    let request = common::request();
    match common::operation(&request) {
        "describe" => common::reply(describe()),
        "collect" => common::reply(collect(common::input(&request))),
        "normalize" => common::reply(normalize(common::input(&request))),
        "evaluate" => common::reply(evaluate(common::input(&request))),
        _ => common::fail("unsupported operation"),
    }
}

fn describe() -> Value {
    json!({
        "id": PACK_ID,
        "version": PACK_VERSION,
        "protocol_version": 1,
        "collectors": [
            "branch-protection", "check-runs", "commit-statuses",
            "repository-mutations", "pull-request-reviews"
        ],
        "evaluators": ["required-status-checks", "current-revision-checks"],
        "evaluator_inputs": {
            "required-status-checks": ["github:branch-protection"],
            "current-revision-checks": ["github:check-runs", "github:commit-statuses"]
        },
        "evaluator_propositions": {
            "required-status-checks": ["branch_configuration"],
            "current-revision-checks": ["revision_checks"]
        },
        "source_contracts": [
            "github-branch-protection/v1", "github-check-runs/v1",
            "github-commit-statuses/v1", "github-repository-mutations/v1",
            "github-pull-request-reviews/v1"
        ],
        "configuration_schema": {}
    })
}

fn collect(input: &Value) -> Value {
    let collector = common::required_str(input, "collector");
    let (adapter, resource) = match collector {
        "branch-protection" => ("github-branch-protection/v1", "branch_protection"),
        "check-runs" => ("github-check-runs/v1", "check_runs"),
        "commit-statuses" => ("github-commit-statuses/v1", "commit_statuses"),
        "repository-mutations" => ("github-repository-mutations/v1", "repository_mutations"),
        "pull-request-reviews" => ("github-pull-request-reviews/v1", "pull_request_reviews"),
        _ => common::fail("unsupported collector"),
    };
    let context = input.get("context").unwrap_or(&Value::Null);
    json!({
        "adapter": adapter,
        "subject": common::context_subject(context),
        "observed_at": common::required_str(context, "observed_at"),
        "acquisition": {
            "provider": "github",
            "resource": resource,
            "per_page": 100,
            "max_pages": 10
        }
    })
}

fn normalize(input: &Value) -> Value {
    let payload = common::source_payload(input);
    let subject = common::source_subject(input);
    let branch = subject.get("branch").and_then(Value::as_str).unwrap_or("");
    let revision = subject
        .get("revision")
        .and_then(Value::as_str)
        .unwrap_or("");
    match common::adapter(input) {
        "github-branch-protection/v1" => normalize_branch(&payload, branch),
        "github-check-runs/v1" => normalize_checks(&payload, revision),
        "github-commit-statuses/v1" => normalize_statuses(&payload, revision),
        "github-repository-mutations/v1" => normalize_mutations(&payload, branch),
        "github-pull-request-reviews/v1" => normalize_reviews(&payload, branch),
        _ => common::fail("unsupported adapter"),
    }
}

fn normalize_branch(payload: &Value, branch: &str) -> Value {
    let data = if let Some(protected) = payload.get("protected").and_then(Value::as_bool) {
        if protected {
            json!({"branch": branch, "protected": true})
        } else {
            json!({
                "allows_deletions": false, "allows_force_pushes": false,
                "dismisses_stale_reviews": false, "enforces_admins": false,
                "requires_code_owner_reviews": false, "requires_last_push_approval": false,
                "required_approving_review_count": 0, "required_status_checks": [],
                "requires_strict_status_checks": false
            })
        }
    } else {
        let reviews = payload
            .get("required_pull_request_reviews")
            .unwrap_or(&Value::Null);
        let status = payload
            .get("required_status_checks")
            .unwrap_or(&Value::Null);
        let mut contexts = status
            .get("contexts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        for check in status
            .get("checks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(context) = check.get("context").and_then(Value::as_str) {
                contexts.insert(context.to_owned());
            }
        }
        json!({
            "allows_deletions": nested_bool(payload, "allow_deletions", "enabled"),
            "allows_force_pushes": nested_bool(payload, "allow_force_pushes", "enabled"),
            "dismisses_stale_reviews": reviews.get("dismiss_stale_reviews").and_then(Value::as_bool).unwrap_or(false),
            "enforces_admins": nested_bool(payload, "enforce_admins", "enabled"),
            "requires_code_owner_reviews": reviews.get("require_code_owner_reviews").and_then(Value::as_bool).unwrap_or(false),
            "requires_last_push_approval": reviews.get("require_last_push_approval").and_then(Value::as_bool).unwrap_or(false),
            "required_approving_review_count": reviews.get("required_approving_review_count").and_then(Value::as_u64).unwrap_or(0),
            "required_status_checks": contexts,
            "requires_strict_status_checks": status.get("strict").and_then(Value::as_bool).unwrap_or(false)
        })
    };
    common::normalized(
        "github:branch-protection",
        data,
        "configured_intent",
        "configuration_snapshot",
    )
}

fn nested_bool(value: &Value, outer: &str, inner: &str) -> bool {
    value
        .get(outer)
        .and_then(|item| item.get(inner))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn normalize_checks(payload: &Value, revision: &str) -> Value {
    let runs = payload
        .get("check_runs")
        .and_then(Value::as_array)
        .unwrap_or_else(|| common::fail("github check-runs response has no check_runs array"));
    let mut checks = runs
        .iter()
        .map(|run| {
            json!({
                "name": common::required_str(run, "name"),
                "status": run.get("status"), "conclusion": run.get("conclusion"),
                "head_sha": run.get("head_sha")
            })
        })
        .collect::<Vec<_>>();
    checks.sort_by_key(|item| {
        (
            item["name"].as_str().unwrap_or("").to_owned(),
            item["head_sha"].as_str().unwrap_or("").to_owned(),
        )
    });
    common::normalized(
        "github:check-runs",
        json!({"revision": revision, "total_count": payload.get("total_count"), "checks": checks}),
        "observed_state",
        "policy_check",
    )
}

fn normalize_statuses(payload: &Value, revision: &str) -> Value {
    let statuses = payload
        .get("statuses")
        .and_then(Value::as_array)
        .unwrap_or_else(|| common::fail("github combined-status response has no statuses array"));
    let mut normalized = statuses
        .iter()
        .map(|status| {
            json!({
                "context": common::required_str(status, "context"), "state": status.get("state")
            })
        })
        .collect::<Vec<_>>();
    normalized.sort_by_key(|item| item["context"].as_str().unwrap_or("").to_ascii_lowercase());
    common::normalized(
        "github:commit-statuses",
        json!({"revision": revision, "total_count": payload.get("total_count"), "statuses": normalized}),
        "observed_state",
        "policy_check",
    )
}

#[derive(Default)]
struct GithubHistory {
    activities: Vec<Value>,
    associations: BTreeMap<String, Vec<Value>>,
    pulls: BTreeMap<u64, Value>,
    reviews: BTreeMap<u64, Vec<Value>>,
    associations_complete: BTreeSet<String>,
    reviews_complete: BTreeSet<u64>,
}

fn history(payload: &Value, branch: &str) -> GithubHistory {
    let transcript = common::transcript(payload);
    let from = parse_time(&transcript.contents.requested_scope.from);
    let until = parse_time(&transcript.contents.requested_scope.until);
    let mut result = GithubHistory::default();
    for exchange in &transcript.contents.exchanges {
        let path = exchange.request.url.split('?').next().unwrap_or("");
        let body = common::json_body(exchange);
        if path.ends_with("/activity") {
            result.activities.extend(
                array(&body, "github activity response is not an array")
                    .iter()
                    .cloned(),
            );
        } else if path.contains("/commits/") && path.ends_with("/pulls") {
            let sha = path
                .split("/commits/")
                .nth(1)
                .and_then(|part| part.split('/').next())
                .unwrap_or("");
            if !exchange.response.headers.contains_key("link")
                || !exchange.response.headers["link"].contains("rel=\"next\"")
            {
                result.associations_complete.insert(sha.to_owned());
            }
            for pull in array(&body, "github commit pull-request response is not an array") {
                result
                    .associations
                    .entry(sha.to_owned())
                    .or_default()
                    .push(pull.clone());
                if let Some(number) = pull.get("number").and_then(Value::as_u64) {
                    result.pulls.insert(number, pull.clone());
                }
            }
        } else if path.contains("/pulls/") && path.ends_with("/reviews") {
            let number = path
                .split("/pulls/")
                .nth(1)
                .and_then(|part| part.split('/').next())
                .and_then(|part| part.parse::<u64>().ok())
                .unwrap_or_else(|| common::fail("github review URL has no pull-request number"));
            if !exchange.response.headers.contains_key("link")
                || !exchange.response.headers["link"].contains("rel=\"next\"")
            {
                result.reviews_complete.insert(number);
            }
            result.reviews.entry(number).or_default().extend(
                array(&body, "github pull-request review response is not an array")
                    .iter()
                    .cloned(),
            );
        }
    }
    let reference = format!("refs/heads/{branch}");
    result.activities.retain(|activity| {
        activity.get("ref").and_then(Value::as_str) == Some(&reference)
            && activity
                .get("timestamp")
                .and_then(Value::as_str)
                .is_some_and(|time| {
                    let time = parse_time(time);
                    time >= from && time < until
                })
    });
    result.activities.sort_by_key(|item| {
        (
            item["timestamp"].as_str().unwrap_or("").to_owned(),
            item["id"].to_string(),
        )
    });
    result
}

fn matching_pull<'a>(
    activity: &Value,
    history: &'a GithubHistory,
    branch: &str,
) -> (Option<&'a Value>, bool) {
    let commit = activity.get("after").and_then(Value::as_str).unwrap_or("");
    match activity.get("activity_type").and_then(Value::as_str) {
        Some("push" | "force_push") => return (None, false),
        Some("pr_merge" | "merge_queue_merge") => {}
        _ => return (None, true),
    }
    if !history.associations_complete.contains(commit) {
        return (None, true);
    }
    let candidates = history
        .associations
        .get(commit)
        .into_iter()
        .flatten()
        .filter(|pull| {
            pull.pointer("/base/ref").and_then(Value::as_str) == Some(branch)
                && pull.get("merged_at").and_then(Value::as_str).is_some()
        })
        .collect::<Vec<_>>();
    let exact = candidates
        .iter()
        .copied()
        .filter(|pull| pull.get("merge_commit_sha").and_then(Value::as_str) == Some(commit))
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        (Some(exact[0]), false)
    } else {
        (None, true)
    }
}

fn normalize_mutations(payload: &Value, branch: &str) -> Value {
    let history = history(payload, branch);
    let events = history.activities.iter().map(|activity| {
        let commit = common::required_str(activity, "after");
        let (pull, ambiguous) = matching_pull(activity, &history, branch);
        json!({
            "event_id": format!("github-activity:{}", activity.get("id").unwrap_or(&Value::Null)),
            "kind": if pull.is_some() || ambiguous { "pull_request_merge" } else { "direct_push" },
            "occurred_at": common::required_str(activity, "timestamp"),
            "commit": commit,
            "pull_request": pull.and_then(|item| item.get("number")).and_then(Value::as_u64)
        })
    }).collect::<Vec<_>>();
    common::normalized(
        "github:repository-mutations",
        json!({"branch": branch, "events": events}),
        "observed_operation",
        "mutation_history",
    )
}

fn normalize_reviews(payload: &Value, branch: &str) -> Value {
    let history = history(payload, branch);
    let mut records = Vec::new();
    for (number, pull) in &history.pulls {
        if pull.pointer("/base/ref").and_then(Value::as_str) != Some(branch)
            || pull.get("merged_at").and_then(Value::as_str).is_none()
        {
            continue;
        }
        let mut reviews = history.reviews.get(number).into_iter().flatten().map(|review| json!({
            "actor": review.pointer("/user/login").and_then(Value::as_str).unwrap_or_else(|| common::fail("github review has no actor")),
            "submitted_at": review.get("submitted_at"),
            "state": common::required_str(review, "state").to_ascii_lowercase()
        })).collect::<Vec<_>>();
        reviews.sort_by_key(|item| {
            (
                item["submitted_at"].as_str().unwrap_or("").to_owned(),
                item["actor"].as_str().unwrap_or("").to_owned(),
                item["state"].as_str().unwrap_or("").to_owned(),
            )
        });
        records.push(json!({
            "number": number,
            "author": pull.pointer("/user/login").and_then(Value::as_str).unwrap_or_else(|| common::fail("github pull request has no author")),
            "merge_commit_sha": common::required_str(pull, "merge_commit_sha"),
            "merged_at": common::required_str(pull, "merged_at"),
            "approvals": reviews
            ,"enumeration_complete": history.reviews_complete.contains(number)
        }));
    }
    common::normalized(
        "github:pull-request-reviews",
        json!({"pull_requests": records}),
        "observed_operation",
        "review_record",
    )
}

fn evaluate(input: &Value) -> Value {
    match common::required_str(input, "evaluator") {
        "required-status-checks" => json!([evaluate_required_checks(input)]),
        "current-revision-checks" => json!([evaluate_current_checks(input)]),
        _ => common::fail("unsupported evaluator"),
    }
}

fn assertion_base(assertion_type: &str, claim: &str, evaluation: &Value) -> Value {
    let target = evaluation.get("target").unwrap_or(&Value::Null);
    json!({
        "assertion_type": assertion_type, "claim": claim,
        "subject": {"repository": target.get("repository"), "branch": target.get("branch"), "release": null, "from": target.get("from"), "until": target.get("until")},
        "outcome": "insufficient_evidence", "evaluated_at": target_or(evaluation, "evaluated_at"),
        "validity": {"basis": "point_in_time", "at": target_or(evaluation, "evaluated_at"), "from": null, "through": null, "fresh_until": null},
        "support": [], "contradictions": [], "considered": [], "missing": [], "identity_joins": [], "reasoning": [], "limitations": [], "coverage": []
    })
}

fn target_or<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn latest<'a>(evaluation: &'a Value, key: &str) -> Vec<&'a Value> {
    let target = evaluation.get("target").unwrap_or(&Value::Null);
    let mut matching = evaluation
        .pointer("/corpus/observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("claim_key").and_then(Value::as_str) == Some(key)
                && item.pointer("/subject/id") == target.get("repository")
                && item.pointer("/subject/branch") == target.get("branch")
        })
        .collect::<Vec<_>>();
    let observed_at = matching
        .iter()
        .filter_map(|item| item.get("observed_at").and_then(Value::as_str))
        .max();
    matching.retain(|item| item.get("observed_at").and_then(Value::as_str) == observed_at);
    matching
}

fn use_evidence(observation: &Value, reason: &str) -> Value {
    json!({"observation_id": observation.get("id"), "source_id": observation.pointer("/provenance/source_id"), "reason": reason})
}

fn complete(evaluation: &Value, observations: &[&Value]) -> bool {
    if observations.is_empty() {
        return false;
    }
    let runs = evaluation
        .pointer("/corpus/collections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|run| run.get("id").and_then(Value::as_str).map(|id| (id, run)))
        .collect::<BTreeMap<_, _>>();
    observations.iter().all(|observation| {
        observation
            .get("collection_run_id")
            .and_then(Value::as_str)
            .and_then(|id| runs.get(id))
            .is_some_and(|run| {
                run.get("outcome").and_then(Value::as_str) == Some("complete")
                    && run
                        .get("authority")
                        .and_then(Value::as_array)
                        .is_some_and(|items| {
                            items.iter().any(|item| {
                                item.as_str() == Some("revision_checks")
                                    || item.as_str() == Some("branch_configuration")
                            })
                        })
                    && run
                        .pointer("/enumeration/terminal_page_reached")
                        .and_then(Value::as_bool)
                        == Some(true)
                    && run
                        .pointer("/enumeration/next_token_present")
                        .and_then(Value::as_bool)
                        == Some(false)
            })
    })
}

fn evaluate_required_checks(evaluation: &Value) -> Value {
    let observations = latest(evaluation, "github:branch-protection");
    let mut result = assertion_base(
        "github_required_status_checks_configured",
        "the protected branch requires named status checks",
        evaluation,
    );
    if observations.is_empty() {
        result["missing"] = json!([{"requirement":"current github branch protection configuration","subject":evaluation.pointer("/target/repository"),"reason":"no authoritative branch protection snapshot is available"}]);
        return result;
    }
    let observation = observations[observations.len() - 1];
    let use_item = use_evidence(
        observation,
        "GitHub reported the branch's required status checks",
    );
    if observation
        .pointer("/data/required_status_checks")
        .and_then(Value::as_array)
        .is_some_and(|checks| !checks.is_empty())
    {
        result["outcome"] = json!(if complete(evaluation, &observations) {
            "supported"
        } else {
            "insufficient_evidence"
        });
        result["support"] = json!([use_item]);
    } else {
        result["outcome"] = json!("contradicted");
        result["contradictions"] = json!([use_item]);
    }
    result
}

fn evaluate_current_checks(evaluation: &Value) -> Value {
    let check_observations = latest(evaluation, "github:check-runs");
    let status_observations = latest(evaluation, "github:commit-statuses");
    let mut result = assertion_base("github_current_revision_checks_passed", "GitHub check runs and commit statuses for the current revision were completely enumerated and had acceptable terminal outcomes", evaluation);
    result["limitations"] = json!([
        "this assertion covers observed results, not satisfaction of configured required contexts",
        "this point-in-time result does not establish historical CI policy enforcement"
    ]);
    let checks = observed_records(&check_observations, "/data/checks");
    let statuses = observed_records(&status_observations, "/data/statuses");
    let failed_checks = checks.iter().filter(|item| check_failed(item)).count();
    let failed_statuses = statuses
        .iter()
        .filter(|item| {
            matches!(
                item.get("state").and_then(Value::as_str),
                Some("failure" | "error")
            )
        })
        .count();
    let unresolved_checks = checks.iter().filter(|item| check_unresolved(item)).count();
    let unresolved_statuses = statuses
        .iter()
        .filter(|item| {
            !matches!(
                item.get("state").and_then(Value::as_str),
                Some("success" | "failure" | "error")
            )
        })
        .count();
    let check_revisions = check_observations
        .iter()
        .filter_map(|item| item.pointer("/subject/revision").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let status_revisions = status_observations
        .iter()
        .filter_map(|item| item.pointer("/subject/revision").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let same_revision = check_revisions.len() == 1 && check_revisions == status_revisions;
    let uses = check_observations
        .iter()
        .map(|item| use_evidence(item, "GitHub reported check runs for the current revision"))
        .chain(status_observations.iter().map(|item| {
            use_evidence(
                item,
                "GitHub reported classic commit statuses for the current revision",
            )
        }))
        .collect::<Vec<_>>();
    let ids = check_observations
        .iter()
        .chain(status_observations.iter())
        .filter_map(|item| item.get("id"))
        .cloned()
        .collect::<Vec<_>>();
    if same_revision && (failed_checks > 0 || failed_statuses > 0) {
        result["outcome"] = json!("contradicted");
        result["contradictions"] = json!(uses);
        result["reasoning"] = json!([{"code":"github_revision_result_failure","conclusion":format!("GitHub reported {} and {}; {} and {} had failing terminal outcomes", quantity(checks.len(), "check run", "check runs"), quantity(statuses.len(), "classic commit status", "classic commit statuses"), quantity(failed_checks, "check run", "check runs"), quantity(failed_statuses, "commit status", "commit statuses")),"evidence_ids":ids}]);
    } else if checks.is_empty() && statuses.is_empty()
        || unresolved_checks > 0
        || unresolved_statuses > 0
        || !complete(evaluation, &check_observations)
        || !complete(evaluation, &status_observations)
        || !same_revision
    {
        let reason = if check_observations.is_empty() || status_observations.is_empty() {
            "GitHub check-run or commit-status evidence was unavailable"
        } else if !same_revision {
            "check-run and commit-status evidence did not resolve to the same revision"
        } else if checks.is_empty() && statuses.is_empty() {
            "GitHub completely enumerated check runs and classic commit statuses but reported no CI results"
        } else if !complete(evaluation, &check_observations)
            || !complete(evaluation, &status_observations)
        {
            match (
                complete(evaluation, &check_observations),
                complete(evaluation, &status_observations),
            ) {
                (false, true) => "GitHub check-run enumeration was incomplete",
                (true, false) => "GitHub commit-status enumeration was incomplete",
                (false, false) => "GitHub check-run and commit-status enumeration was incomplete",
                (true, true) => unreachable!(),
            }
        } else {
            "GitHub reported pending, transitional, or unrecognized outcomes"
        };
        result["considered"] = json!(uses);
        result["missing"] = json!([{"requirement":"complete terminal GitHub check runs and commit statuses","subject":evaluation.pointer("/target/repository"),"reason":reason}]);
        result["reasoning"] = json!([{"code":"github_revision_results_incomplete","conclusion":reason,"evidence_ids":ids}]);
    } else {
        result["outcome"] = json!("supported");
        result["support"] = json!(uses);
        result["reasoning"] = json!([{"code":"github_revision_results_acceptable","conclusion":format!("GitHub reported {} check runs and {} classic commit statuses; both enumerations were complete and every result had an acceptable terminal outcome", checks.len(), statuses.len()),"evidence_ids":ids}]);
        result["identity_joins"] = json!([{"left_observation_id":check_observations[0].get("id"),"right_observation_id":status_observations[0].get("id"),"fields":{"revision":check_revisions.iter().next()}}]);
    }
    result
}

fn array<'a>(value: &'a Value, error: &str) -> &'a Vec<Value> {
    value.as_array().unwrap_or_else(|| common::fail(error))
}
fn parse_time(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|_| common::fail("provider response contains an invalid timestamp"))
}

fn quantity(count: usize, singular: &str, plural: &str) -> String {
    match count {
        0 => format!("no {plural}"),
        1 => format!("1 {singular}"),
        _ => format!("{count} {plural}"),
    }
}

fn check_failed(item: &Value) -> bool {
    item.get("status").and_then(Value::as_str) == Some("completed")
        && matches!(
            item.get("conclusion").and_then(Value::as_str),
            Some(
                "failure"
                    | "cancelled"
                    | "timed_out"
                    | "action_required"
                    | "stale"
                    | "startup_failure"
            )
        )
}

fn observed_records<'a>(observations: &[&'a Value], path: &str) -> Vec<&'a Value> {
    observations
        .iter()
        .flat_map(|item| {
            item.pointer(path)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect()
}

fn check_unresolved(item: &Value) -> bool {
    item.get("status").and_then(Value::as_str) != Some("completed")
        || !matches!(
            item.get("conclusion").and_then(Value::as_str),
            Some(
                "success"
                    | "neutral"
                    | "skipped"
                    | "failure"
                    | "cancelled"
                    | "timed_out"
                    | "action_required"
                    | "stale"
                    | "startup_failure"
            )
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(pulls: Value) -> Value {
        common::historical_payload("github:owner/repository", "main", vec![
            ("https://api.github.com/repos/owner/repository/activity?ref=main", json!([{"id":1,"ref":"refs/heads/main","timestamp":"2026-09-11T12:00:00Z","after":"integrated","activity_type":"pr_merge"}])),
            ("https://api.github.com/repos/owner/repository/commits/integrated/pulls?per_page=100", pulls),
            ("https://api.github.com/repos/owner/repository/pulls/42/reviews?per_page=100", json!([{"user":{"login":"reviewer"},"state":"APPROVED","submitted_at":"2026-09-11T11:00:00Z"}]))
        ])
    }

    #[test]
    fn merge_squash_and_rebase_use_provider_integration_revision() {
        for shape in ["merge", "squash", "rebase"] {
            let payload = payload(
                json!([{"number":42,"base":{"ref":"main"},"user":{"login":"author"},"merge_commit_sha":"integrated","merged_at":"2026-09-11T12:00:00Z","merge_method":shape}]),
            );
            let mutations = normalize_mutations(&payload, "main");
            assert_eq!(mutations["data"]["events"][0]["pull_request"], 42);
            let reviews = normalize_reviews(&payload, "main");
            assert_eq!(
                reviews["data"]["pull_requests"][0]["merge_commit_sha"],
                "integrated"
            );
            assert_eq!(
                reviews["data"]["pull_requests"][0]["approvals"][0]["state"],
                "approved"
            );
        }
    }

    #[test]
    fn absent_association_is_direct_but_ambiguous_association_is_not() {
        let mut direct = payload(json!([]));
        let mut activity: Value = serde_json::from_str(
            direct["contents"]["exchanges"][0]["response"]["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        activity[0]["activity_type"] = json!("push");
        direct["contents"]["exchanges"][0]["response"]["body"] = json!(activity.to_string());
        assert_eq!(
            normalize_mutations(&direct, "main")["data"]["events"][0]["kind"],
            "direct_push"
        );
        let ambiguous = payload(
            json!([{"number":42,"base":{"ref":"main"},"merge_commit_sha":"different","merged_at":"2026-09-11T12:00:00Z"}]),
        );
        let mutations = normalize_mutations(&ambiguous, "main");
        assert_eq!(mutations["data"]["events"][0]["kind"], "pull_request_merge");
        assert!(mutations["data"]["events"][0]["pull_request"].is_null());
    }
}
