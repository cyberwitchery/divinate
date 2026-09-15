#[path = "../common.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PACK_ID: &str = "cyberwitchery.azure-devops";
const PACK_VERSION: &str = "0.1.0";
const MINIMUM_REVIEWERS: &str = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd";
const BUILD_VALIDATION: &str = "0609b952-1397-4640-95ec-e00a01b2c241";

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
        "id": PACK_ID, "version": PACK_VERSION, "protocol_version": 1,
        "collectors": ["branch-policy", "repository-mutations", "pull-request-reviews"],
        "evaluators": ["blocking-policy", "approving-review", "build-validation"],
        "evaluator_inputs": {
            "blocking-policy": ["azure-devops:branch-policy"],
            "approving-review": ["azure-devops:branch-policy"],
            "build-validation": ["azure-devops:branch-policy"]
        },
        "evaluator_propositions": {
            "blocking-policy": ["branch_configuration"],
            "approving-review": ["branch_configuration"],
            "build-validation": ["branch_configuration"]
        },
        "source_contracts": [
            "azure-devops-branch-policy/v1", "azure-devops-repository-mutations/v1",
            "azure-devops-pull-request-reviews/v1"
        ],
        "configuration_schema": {}
    })
}

fn collect(input: &Value) -> Value {
    let collector = common::required_str(input, "collector");
    let (adapter, resource) = match collector {
        "branch-policy" => ("azure-devops-branch-policy/v1", "branch_policy"),
        "repository-mutations" => (
            "azure-devops-repository-mutations/v1",
            "repository_mutations",
        ),
        "pull-request-reviews" => (
            "azure-devops-pull-request-reviews/v1",
            "pull_request_reviews",
        ),
        _ => common::fail("unsupported collector"),
    };
    let context = input.get("context").unwrap_or(&Value::Null);
    json!({
        "adapter": adapter, "subject": common::context_subject(context),
        "observed_at": common::required_str(context, "observed_at"),
        "acquisition": {"provider":"azure_devops", "resource":resource, "max_pages":10}
    })
}

fn normalize(input: &Value) -> Value {
    let payload = common::source_payload(input);
    let subject = common::source_subject(input);
    let branch = subject.get("branch").and_then(Value::as_str).unwrap_or("");
    match common::adapter(input) {
        "azure-devops-branch-policy/v1" => normalize_branch_payload(&payload, branch),
        "azure-devops-repository-mutations/v1" => normalize_mutations(&payload, branch),
        "azure-devops-pull-request-reviews/v1" => normalize_reviews(&payload, branch),
        _ => common::fail("unsupported adapter"),
    }
}

fn normalize_branch_payload(payload: &Value, branch: &str) -> Value {
    if let Some(policies) = payload.get("value").and_then(Value::as_array) {
        let mut normalized = policies.iter().map(normalized_policy).collect::<Vec<_>>();
        normalized.sort_by_key(|item| item["id"].as_u64().unwrap_or(0));
        common::normalized(
            "azure-devops:branch-policy",
            json!({"branch":branch,"policies":normalized}),
            "configured_intent",
            "configuration_snapshot",
        )
    } else {
        common::normalized(
            "azure-devops:repository-binding",
            json!({
                "repository_id": common::required_str(payload, "id"),
                "repository_name": common::required_str(payload, "name")
            }),
            "configured_intent",
            "configuration_snapshot",
        )
    }
}

fn normalized_policy(policy: &Value) -> Value {
    let id = policy.get("id").and_then(Value::as_u64).unwrap_or_else(|| {
        common::fail("azure devops branch-policy response contains an invalid policy")
    });
    let settings = policy.get("settings").unwrap_or(&Value::Null);
    let mut scopes = settings.get("scope").and_then(Value::as_array).into_iter().flatten().map(|scope| json!({
        "repository_id":scope.get("repositoryId"), "ref_name":scope.get("refName"), "match_kind":scope.get("matchKind")
    })).collect::<Vec<_>>();
    scopes.sort_by_key(|scope| {
        (
            scope["repository_id"].as_str().unwrap_or("").to_owned(),
            scope["ref_name"].as_str().unwrap_or("").to_owned(),
            scope["match_kind"].as_str().unwrap_or("").to_owned(),
        )
    });
    json!({
        "id":id, "type_id":policy.pointer("/type/id"), "type_name":policy.pointer("/type/displayName"),
        "enabled":policy.get("isEnabled").and_then(Value::as_bool).unwrap_or(false),
        "blocking":policy.get("isBlocking").and_then(Value::as_bool).unwrap_or(false),
        "minimum_approver_count":settings.get("minimumApproverCount"),
        "creator_vote_counts":settings.get("creatorVoteCounts"), "reset_on_source_push":settings.get("resetOnSourcePush"),
        "reset_rejections_on_source_push":settings.get("resetRejectionsOnSourcePush"), "block_last_pusher_vote":settings.get("blockLastPusherVote"),
        "build_definition_id":settings.get("buildDefinitionId"), "status_name":settings.get("statusName"), "scopes":scopes
    })
}

#[derive(Default)]
struct AzureHistory {
    pushes: Vec<Value>,
    pulls: BTreeMap<u64, Value>,
    threads: BTreeMap<u64, Vec<Value>>,
    pull_population_complete: bool,
    threads_complete: BTreeSet<u64>,
}

fn history(payload: &Value, branch: &str) -> AzureHistory {
    let transcript = common::transcript(payload);
    let from = parse_time(&transcript.contents.requested_scope.from);
    let until = parse_time(&transcript.contents.requested_scope.until);
    let mut result = AzureHistory::default();
    for exchange in &transcript.contents.exchanges {
        let path = exchange
            .request
            .url
            .split('?')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = common::json_body(exchange);
        let values = body.get("value").and_then(Value::as_array);
        if path.contains("/pushes") {
            result.pushes.extend(
                values
                    .unwrap_or_else(|| {
                        common::fail("azure devops pushes response has no value array")
                    })
                    .iter()
                    .cloned(),
            );
        } else if path.ends_with("/pullrequests") {
            result.pull_population_complete = values.is_some_and(|items| items.len() < 100)
                && !exchange
                    .response
                    .headers
                    .contains_key("x-ms-continuationtoken");
            for pull in values.unwrap_or_else(|| {
                common::fail("azure devops pull-request response has no value array")
            }) {
                if let Some(number) = pull.get("pullRequestId").and_then(Value::as_u64) {
                    result.pulls.insert(number, pull.clone());
                }
            }
        } else if path.ends_with("/threads") && path.contains("/pullrequests/") {
            let number = path
                .split("/pullrequests/")
                .nth(1)
                .and_then(|part| part.split('/').next())
                .and_then(|part| part.parse().ok())
                .unwrap_or_else(|| common::fail("azure thread URL has no pull-request number"));
            if !exchange
                .response
                .headers
                .contains_key("x-ms-continuationtoken")
            {
                result.threads_complete.insert(number);
            }
            result.threads.entry(number).or_default().extend(
                values
                    .unwrap_or_else(|| {
                        common::fail("azure devops pull-request thread response has no value array")
                    })
                    .iter()
                    .cloned(),
            );
        }
    }
    let reference = format!("refs/heads/{branch}");
    result.pushes.retain(|push| {
        push.get("date")
            .and_then(Value::as_str)
            .is_some_and(|date| {
                let date = parse_time(date);
                date >= from && date < until
            })
            && push
                .get("refUpdates")
                .and_then(Value::as_array)
                .is_some_and(|updates| {
                    updates.iter().any(|update| {
                        update.get("name").and_then(Value::as_str) == Some(&reference)
                    })
                })
    });
    result
        .pulls
        .retain(|_, pull| pull.get("targetRefName").and_then(Value::as_str) == Some(&reference));
    result.pushes.sort_by_key(|push| {
        (
            push["date"].as_str().unwrap_or("").to_owned(),
            push["pushId"].as_u64().unwrap_or(0),
        )
    });
    result
}

fn normalize_mutations(payload: &Value, branch: &str) -> Value {
    let history = history(payload, branch);
    let reference = format!("refs/heads/{branch}");
    let mut events = Vec::new();
    for push in &history.pushes {
        for update in push
            .get("refUpdates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|update| update.get("name").and_then(Value::as_str) == Some(&reference))
        {
            let commit = common::required_str(update, "newObjectId");
            let candidates = history
                .pulls
                .values()
                .filter(|pull| {
                    pull.pointer("/lastMergeCommit/commitId")
                        .and_then(Value::as_str)
                        == Some(commit)
                })
                .collect::<Vec<_>>();
            events.push(json!({
                "event_id":format!("azure-push:{}:{commit}", push.get("pushId").unwrap_or(&Value::Null)),
                "kind":if candidates.is_empty() && history.pull_population_complete { "direct_push" } else { "pull_request_merge" },
                "occurred_at":common::required_str(push, "date"), "commit":commit,
                "pull_request":if candidates.len() == 1 { candidates[0].get("pullRequestId") } else { None }
            }));
        }
    }
    common::normalized(
        "azure-devops:repository-mutations",
        json!({"branch":branch,"events":events}),
        "observed_operation",
        "mutation_history",
    )
}

fn normalize_reviews(payload: &Value, branch: &str) -> Value {
    let history = history(payload, branch);
    let transcript = common::transcript(payload);
    let from = parse_time(&transcript.contents.requested_scope.from);
    let until = parse_time(&transcript.contents.requested_scope.until);
    let mut records = Vec::new();
    for (number, pull) in &history.pulls {
        let integrated = parse_time(common::required_str(pull, "closedDate"));
        if integrated < from || integrated >= until {
            continue;
        }
        let author = pull
            .pointer("/createdBy/id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| common::fail("azure devops pull request has no author"));
        let mut votes = history
            .threads
            .get(number)
            .into_iter()
            .flatten()
            .filter_map(|thread| {
                let properties = thread.get("properties")?;
                let vote = property(properties, "CodeReviewVoteResult")?;
                let actor = property(properties, "CodeReviewVotedByTfId")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        let identity =
                            property(properties, "CodeReviewVotedByIdentity")?.as_str()?;
                        thread.get("identities")?.get(identity)?.get("id")?.as_str()
                    })
                    .unwrap_or("unknown");
                let state = if actor == "unknown" || actor.is_empty() {
                    "unknown"
                } else {
                    vote_state(vote)
                };
                Some(
                    json!({"actor":actor,"submitted_at":thread.get("publishedDate"),"state":state}),
                )
            })
            .collect::<Vec<_>>();
        votes.sort_by_key(|vote| {
            (
                vote["submitted_at"].as_str().unwrap_or("").to_owned(),
                vote["actor"].as_str().unwrap_or("").to_owned(),
                vote["state"].as_str().unwrap_or("").to_owned(),
            )
        });
        records.push(json!({
            "number":number, "author":author,
            "merge_commit_sha":pull.pointer("/lastMergeCommit/commitId").and_then(Value::as_str).unwrap_or_else(|| common::fail("azure devops pull request has no integration revision")),
            "merged_at":common::required_str(pull, "closedDate"), "approvals":votes,
            "enumeration_complete":history.threads_complete.contains(number)
        }));
    }
    common::normalized(
        "azure-devops:pull-request-reviews",
        json!({"pull_requests":records}),
        "observed_operation",
        "review_record",
    )
}

fn property<'a>(properties: &'a Value, name: &str) -> Option<&'a Value> {
    let value = properties.get(name)?;
    value.get("$value").or(Some(value))
}

fn vote_state(value: &Value) -> &'static str {
    match value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    {
        Some(5 | 10) => "approved",
        Some(-5 | -10) => "changes_requested",
        Some(0) => "pending",
        _ => "unknown",
    }
}

fn evaluate(input: &Value) -> Value {
    let evaluator = common::required_str(input, "evaluator");
    let (assertion_type, claim, predicate): (&str, String, fn(&Value) -> bool) = match evaluator {
        "blocking-policy" => (
            "azure_devops_blocking_branch_policy_configured",
            "the Azure DevOps branch has at least one enabled blocking policy".into(),
            |policy| enabled_blocking(policy),
        ),
        "approving-review" => (
            "configured_independent_review",
            format!(
                "changes to {} are configured to require approval before merge",
                input
                    .pointer("/target/branch")
                    .and_then(Value::as_str)
                    .unwrap_or("the branch")
            ),
            |policy| {
                enabled_blocking(policy)
                    && policy.get("type_id").and_then(Value::as_str) == Some(MINIMUM_REVIEWERS)
                    && policy
                        .get("minimum_approver_count")
                        .and_then(Value::as_u64)
                        .is_some_and(|count| count > 0)
            },
        ),
        "build-validation" => (
            "azure_devops_blocking_build_validation_configured",
            "the Azure DevOps branch has enabled blocking build validation".into(),
            |policy| {
                enabled_blocking(policy)
                    && policy.get("type_id").and_then(Value::as_str) == Some(BUILD_VALIDATION)
            },
        ),
        _ => common::fail("unsupported evaluator"),
    };
    let target = input.get("target").unwrap_or(&Value::Null);
    let mut result = json!({
        "assertion_type":assertion_type,"claim":claim,
        "subject":{"repository":target.get("repository"),"branch":target.get("branch"),"release":null,"from":if evaluator == "approving-review" { None } else { target.get("from") },"until":if evaluator == "approving-review" { None } else { target.get("until") }},
        "outcome":"insufficient_evidence","evaluated_at":input.get("evaluated_at"),
        "validity":{"basis":"point_in_time","at":input.get("evaluated_at"),"from":null,"through":null,"fresh_until":null},
        "support":[],"contradictions":[],"considered":[],"missing":[],"identity_joins":[],"reasoning":[],
        "limitations":["current configuration does not establish historical policy enforcement"],"coverage":[]
    });
    let observations = latest(input);
    let uses = observations.iter().map(|observation| json!({"observation_id":observation.get("id"),"source_id":observation.pointer("/provenance/source_id"),"reason":"Azure DevOps reported the policies applying to this branch"})).collect::<Vec<_>>();
    if !complete(input, &observations) {
        result["considered"] = json!(uses);
        result["missing"] = json!([{"requirement":"complete current Azure DevOps branch-policy configuration","subject":target.get("repository"),"reason":"no complete authoritative branch-policy enumeration is available"}]);
        return json!([result]);
    }
    let policies = observations
        .iter()
        .flat_map(|item| {
            item.pointer("/data/policies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    let matching = policies.iter().filter(|policy| predicate(policy)).count();
    result["reasoning"] = json!([{"code":format!("azure_devops_{}",evaluator.replace('-', "_")),"conclusion":format!("Azure DevOps reported {} applicable policies; {matching} satisfied this current-configuration predicate",policies.len()),"evidence_ids":observations.iter().filter_map(|item| item.get("id")).collect::<Vec<_>>()}]);
    if matching > 0 {
        result["outcome"] = json!("supported");
        result["support"] = json!(uses);
    } else {
        result["outcome"] = json!("contradicted");
        result["contradictions"] = json!(uses);
    }
    json!([result])
}

fn enabled_blocking(policy: &Value) -> bool {
    policy.get("enabled").and_then(Value::as_bool) == Some(true)
        && policy.get("blocking").and_then(Value::as_bool) == Some(true)
}

fn latest(evaluation: &Value) -> Vec<&Value> {
    let target = evaluation.get("target").unwrap_or(&Value::Null);
    let mut matching = evaluation
        .pointer("/corpus/observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("claim_key").and_then(Value::as_str) == Some("azure-devops:branch-policy")
                && item.pointer("/subject/id") == target.get("repository")
                && item.pointer("/subject/branch") == target.get("branch")
                && item.pointer("/data/branch") == target.get("branch")
        })
        .collect::<Vec<_>>();
    let at = matching
        .iter()
        .filter_map(|item| item.get("observed_at").and_then(Value::as_str))
        .max();
    matching.retain(|item| item.get("observed_at").and_then(Value::as_str) == at);
    matching
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
                            items
                                .iter()
                                .any(|item| item.as_str() == Some("branch_configuration"))
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

fn parse_time(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|_| common::fail("provider response contains an invalid timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_update_joins_completed_pr_and_timestamped_vote() {
        let payload = common::historical_payload("azure-devops:org/project/repository", "develop", vec![
            ("https://dev.azure.com/org/project/_apis/git/repositories/id", json!({"id":"id","name":"repository"})),
            ("https://dev.azure.com/org/project/_apis/git/repositories/id/pushes?", json!({"value":[{"pushId":1,"date":"2026-09-11T12:00:00Z","refUpdates":[{"name":"refs/heads/develop","newObjectId":"integrated"}]}]})),
            ("https://dev.azure.com/org/project/_apis/git/repositories/id/pullrequests?", json!({"value":[{"pullRequestId":42,"targetRefName":"refs/heads/develop","closedDate":"2026-09-11T12:00:00Z","createdBy":{"id":"author"},"lastMergeCommit":{"commitId":"integrated"}}]})),
            ("https://dev.azure.com/org/project/_apis/git/repositories/id/pullRequests/42/threads?", json!({"value":[{"publishedDate":"2026-09-11T11:00:00Z","identities":{"1":{"id":"reviewer"}},"properties":{"CodeReviewVoteResult":{"$value":"10"},"CodeReviewVotedByIdentity":{"$value":"1"}}}]}))
        ]);
        let mutations = normalize_mutations(&payload, "develop");
        assert_eq!(mutations["data"]["events"][0]["pull_request"], 42);
        let reviews = normalize_reviews(&payload, "develop");
        assert_eq!(
            reviews["data"]["pull_requests"][0]["approvals"][0]["actor"],
            "reviewer"
        );
        assert_eq!(
            reviews["data"]["pull_requests"][0]["approvals"][0]["state"],
            "approved"
        );
        assert_eq!(
            reviews["data"]["pull_requests"][0]["approvals"][0]["submitted_at"],
            "2026-09-11T11:00:00Z"
        );
        assert_eq!(
            normalize_mutations(&payload, "other")["data"]["events"],
            json!([])
        );
    }

    #[test]
    fn provider_vote_values_are_explicit() {
        for (vote, state) in [
            (10, "approved"),
            (5, "approved"),
            (0, "pending"),
            (-5, "changes_requested"),
            (-10, "changes_requested"),
            (20, "unknown"),
        ] {
            assert_eq!(vote_state(&json!(vote)), state);
            assert_eq!(vote_state(&json!(vote.to_string())), state);
        }
    }
}
