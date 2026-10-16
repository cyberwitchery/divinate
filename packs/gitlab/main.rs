#[path = "../common.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PACK_ID: &str = "cyberwitchery.gitlab";
const PACK_VERSION: &str = "0.1.0";
const APPROVED_NOTE: &str = "approved this merge request";

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
        "collectors": ["branch-protection", "repository-mutations", "merge-request-reviews"],
        "evaluators": ["protected-branch", "no-direct-push", "approving-review", "force-push-disabled"],
        "evaluator_inputs": {
            "protected-branch": ["gitlab:branch-protection"],
            "no-direct-push": ["gitlab:branch-protection"],
            "approving-review": ["gitlab:branch-protection"],
            "force-push-disabled": ["gitlab:branch-protection"]
        },
        "evaluator_propositions": {
            "protected-branch": ["branch_configuration"],
            "no-direct-push": ["branch_configuration"],
            "approving-review": ["branch_configuration"],
            "force-push-disabled": ["branch_configuration"]
        },
        "source_contracts": [
            "gitlab-branch-protection/v1", "gitlab-repository-mutations/v1",
            "gitlab-merge-request-reviews/v1"
        ],
        "configuration_schema": {}
    })
}

fn collect(input: &Value) -> Value {
    let collector = common::required_str(input, "collector");
    let (adapter, resource) = match collector {
        "branch-protection" => ("gitlab-branch-protection/v1", "branch_protection"),
        "repository-mutations" => ("gitlab-repository-mutations/v1", "repository_mutations"),
        "merge-request-reviews" => ("gitlab-merge-request-reviews/v1", "merge_request_reviews"),
        _ => common::fail("unsupported collector"),
    };
    let context = input.get("context").unwrap_or(&Value::Null);
    json!({
        "adapter": adapter, "subject": common::context_subject(context),
        "observed_at": common::required_str(context, "observed_at"),
        "acquisition": {"provider":"gitlab", "resource":resource, "max_pages":20}
    })
}

fn normalize(input: &Value) -> Value {
    let payload = common::source_payload(input);
    let subject = common::source_subject(input);
    let branch = subject.get("branch").and_then(Value::as_str).unwrap_or("");
    match common::adapter(input) {
        "gitlab-branch-protection/v1" => normalize_branch_protection(&payload, branch),
        "gitlab-repository-mutations/v1" => normalize_mutations(&payload, branch),
        "gitlab-merge-request-reviews/v1" => normalize_reviews(&payload, branch),
        _ => common::fail("unsupported adapter"),
    }
}

/// the request path below the project prefix, such as `/protected_branches`.
fn resource_path(exchange: &divinate::acquisition::HttpExchange, prefix: &str) -> String {
    exchange
        .request
        .url
        .split('?')
        .next()
        .unwrap_or("")
        .strip_prefix(prefix)
        .unwrap_or("")
        .to_owned()
}

fn project_prefix(transcript: &divinate::acquisition::AcquisitionTranscript) -> String {
    transcript.contents.initial_request.url.clone()
}

fn list_items<'a>(
    transcript: &'a divinate::acquisition::AcquisitionTranscript,
    path: &'a str,
) -> impl Iterator<Item = Value> + 'a {
    let prefix = project_prefix(transcript);
    transcript
        .contents
        .exchanges
        .iter()
        .filter(move |exchange| resource_path(exchange, &prefix) == path)
        .flat_map(|exchange| {
            common::json_body(exchange)
                .as_array()
                .cloned()
                .unwrap_or_else(|| common::fail("gitlab list response is not an array"))
        })
}

/// gitlab protected-branch names may contain `*` wildcards.
fn branch_matches(pattern: &str, branch: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == branch;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !branch.starts_with(first) || branch.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &branch[first.len()..];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

fn access_levels(entry: &Value, field: &str) -> Vec<Value> {
    let mut levels = entry
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|level| {
            json!({
                "access_level":level.get("access_level"), "user_id":level.get("user_id"),
                "group_id":level.get("group_id"), "deploy_key_id":level.get("deploy_key_id")
            })
        })
        .collect::<Vec<_>>();
    levels.sort_by_key(Value::to_string);
    levels
}

fn normalize_branch_protection(payload: &Value, branch: &str) -> Value {
    let transcript = common::transcript(payload);
    let project = transcript.contents.exchanges.first().map_or_else(
        || common::fail("gitlab transcript has no project response"),
        common::json_body,
    );
    let mut protected = list_items(&transcript, "/protected_branches")
        .filter(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| branch_matches(name, branch))
        })
        .map(|entry| {
            json!({
                "name":entry.get("name"),
                "push_access_levels":access_levels(&entry, "push_access_levels"),
                "merge_access_levels":access_levels(&entry, "merge_access_levels"),
                "allow_force_push":entry.get("allow_force_push").and_then(Value::as_bool).unwrap_or(false),
                "code_owner_approval_required":entry.get("code_owner_approval_required").and_then(Value::as_bool).unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    protected.sort_by_key(|entry| entry["name"].as_str().unwrap_or("").to_owned());
    let is_protected = !protected.is_empty();
    let mut rules = list_items(&transcript, "/approval_rules")
        .filter(|rule| {
            let named = rule
                .get("protected_branches")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if rule.get("applies_to_all_protected_branches").and_then(Value::as_bool) == Some(true)
            {
                is_protected
            } else if named.is_empty() {
                true
            } else {
                named.iter().any(|item| {
                    item.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| branch_matches(name, branch))
                })
            }
        })
        .map(|rule| {
            json!({
                "id":rule.get("id"), "name":rule.get("name"), "rule_type":rule.get("rule_type"),
                "approvals_required":rule.get("approvals_required").and_then(Value::as_u64).unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| rule["id"].as_u64().unwrap_or(0));
    let prefix = project_prefix(&transcript);
    let settings = transcript
        .contents
        .exchanges
        .iter()
        .rev()
        .find(|exchange| resource_path(exchange, &prefix) == "/approvals")
        .map_or(Value::Null, common::json_body);
    common::normalized(
        "gitlab:branch-protection",
        json!({
            "branch":branch,
            "project":{
                "merge_method":project.get("merge_method"),
                "only_allow_merge_if_pipeline_succeeds":project.get("only_allow_merge_if_pipeline_succeeds"),
                "only_allow_merge_if_all_discussions_are_resolved":project.get("only_allow_merge_if_all_discussions_are_resolved")
            },
            "protected_branches":protected,
            "approval_rules":rules,
            "approval_settings":{
                "merge_requests_author_approval":settings.get("merge_requests_author_approval"),
                "merge_requests_disable_committers_approval":settings.get("merge_requests_disable_committers_approval"),
                "reset_approvals_on_push":settings.get("reset_approvals_on_push"),
                "disable_overriding_approvers_per_merge_request":settings.get("disable_overriding_approvers_per_merge_request")
            }
        }),
        "configured_intent",
        "configuration_snapshot",
    )
}

/// the branch revision a merged request produced.
///
/// a merge commit is the branch head when one exists; a squash without a merge
/// commit leaves the squash commit; a fast-forward leaves the request head.
fn integration_revision(request: &Value) -> Option<&str> {
    ["merge_commit_sha", "squash_commit_sha", "sha"]
        .iter()
        .find_map(|field| request.get(*field).and_then(Value::as_str))
}

fn normalize_mutations(payload: &Value, branch: &str) -> Value {
    let transcript = common::transcript(payload);
    let prefix = project_prefix(&transcript);
    let from = parse_time(&transcript.contents.requested_scope.from);
    let until = parse_time(&transcript.contents.requested_scope.until);
    let mut associations: BTreeMap<String, (Vec<Value>, bool)> = BTreeMap::new();
    for exchange in &transcript.contents.exchanges {
        let path = resource_path(exchange, &prefix);
        let Some(commit) = path
            .strip_prefix("/repository/commits/")
            .and_then(|rest| rest.strip_suffix("/merge_requests"))
        else {
            continue;
        };
        let entry = associations.entry(commit.to_owned()).or_default();
        entry.0.extend(
            common::json_body(exchange)
                .as_array()
                .cloned()
                .unwrap_or_else(|| {
                    common::fail("gitlab commit merge-request response is not an array")
                }),
        );
        entry.1 = !exchange
            .response
            .headers
            .get("link")
            .is_some_and(|link| link.contains("rel=\"next\""));
    }
    let mut events = Vec::new();
    for event in list_items(&transcript, "/events") {
        let push = event.get("push_data").unwrap_or(&Value::Null);
        if push.get("ref_type").and_then(Value::as_str) != Some("branch")
            || push.get("ref").and_then(Value::as_str) != Some(branch)
        {
            continue;
        }
        let occurred_at = common::required_str(&event, "created_at");
        let at = parse_time(occurred_at);
        if at < from || at >= until {
            continue;
        }
        let id = event.get("id").unwrap_or(&Value::Null);
        let Some(commit) = push.get("commit_to").and_then(Value::as_str) else {
            let removed = push
                .get("commit_from")
                .and_then(Value::as_str)
                .unwrap_or("");
            events.push(json!({
                "event_id":format!("gitlab-push:{id}:{removed}"), "kind":"branch_removal",
                "occurred_at":occurred_at, "commit":removed, "pull_request":null
            }));
            continue;
        };
        let (requests, complete) = associations
            .get(commit)
            .map_or((&[][..], false), |(requests, complete)| {
                (requests.as_slice(), *complete)
            });
        let candidates = requests
            .iter()
            .filter(|request| {
                request.get("target_branch").and_then(Value::as_str) == Some(branch)
                    && request.get("state").and_then(Value::as_str) == Some("merged")
                    && integration_revision(request) == Some(commit)
            })
            .collect::<Vec<_>>();
        events.push(json!({
            "event_id":format!("gitlab-push:{id}:{commit}"),
            "kind":if candidates.is_empty() && complete { "direct_push" } else { "pull_request_merge" },
            "occurred_at":occurred_at, "commit":commit,
            "pull_request":if candidates.len() == 1 { candidates[0].get("iid") } else { None }
        }));
    }
    events.sort_by_key(|event| {
        (
            event["occurred_at"].as_str().unwrap_or("").to_owned(),
            event["event_id"].as_str().unwrap_or("").to_owned(),
        )
    });
    common::normalized(
        "gitlab:repository-mutations",
        json!({"branch":branch,"events":events}),
        "observed_operation",
        "mutation_history",
    )
}

/// per merge request: current approvers, retained notes, and read completeness.
#[derive(Default)]
struct ReviewHistory {
    approvers: BTreeMap<u64, BTreeSet<String>>,
    approvals_read: BTreeSet<u64>,
    notes: BTreeMap<u64, Vec<Value>>,
    notes_complete: BTreeSet<u64>,
}

fn review_history(transcript: &divinate::acquisition::AcquisitionTranscript) -> ReviewHistory {
    let prefix = project_prefix(transcript);
    let mut history = ReviewHistory::default();
    for exchange in &transcript.contents.exchanges {
        let path = resource_path(exchange, &prefix);
        let Some((iid, resource)) = path
            .strip_prefix("/merge_requests/")
            .and_then(|rest| rest.split_once('/'))
        else {
            continue;
        };
        let iid = iid
            .parse::<u64>()
            .unwrap_or_else(|_| common::fail("gitlab merge-request URL has no iid"));
        let body = common::json_body(exchange);
        match resource {
            "approvals" => {
                history.approvals_read.insert(iid);
                let users = body
                    .get("approved_by")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.pointer("/user/id").and_then(Value::as_u64))
                    .map(|id| id.to_string());
                history.approvers.entry(iid).or_default().extend(users);
            }
            "notes" => {
                history.notes.entry(iid).or_default().extend(
                    body.as_array()
                        .cloned()
                        .unwrap_or_else(|| common::fail("gitlab notes response is not an array")),
                );
                let more = exchange
                    .response
                    .headers
                    .get("link")
                    .is_some_and(|link| link.contains("rel=\"next\""));
                if more {
                    history.notes_complete.remove(&iid);
                } else {
                    history.notes_complete.insert(iid);
                }
            }
            _ => {}
        }
    }
    history
}

/// the approver's last approval system note before the merge.
fn approval_time<'a>(notes: &'a [Value], actor: &str, merged: OffsetDateTime) -> Option<&'a str> {
    notes
        .iter()
        .filter(|note| {
            note.get("system").and_then(Value::as_bool) == Some(true)
                && note.get("body").and_then(Value::as_str).map(str::trim) == Some(APPROVED_NOTE)
                && note
                    .pointer("/author/id")
                    .and_then(Value::as_u64)
                    .is_some_and(|id| id.to_string() == actor)
        })
        .filter_map(|note| note.get("created_at").and_then(Value::as_str))
        .map(|created| (parse_time(created), created))
        .filter(|(created, _)| *created < merged)
        .max_by_key(|(created, _)| *created)
        .map(|(_, created)| created)
}

fn normalize_reviews(payload: &Value, branch: &str) -> Value {
    let transcript = common::transcript(payload);
    let from = parse_time(&transcript.contents.requested_scope.from);
    let until = parse_time(&transcript.contents.requested_scope.until);
    let history = review_history(&transcript);
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    for request in list_items(&transcript, "/merge_requests") {
        if request.get("target_branch").and_then(Value::as_str) != Some(branch) {
            continue;
        }
        let Some(merged_at) = request.get("merged_at").and_then(Value::as_str) else {
            continue;
        };
        let merged = parse_time(merged_at);
        if merged < from || merged >= until {
            continue;
        }
        let iid = request
            .get("iid")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| common::fail("gitlab merge request has no iid"));
        if !seen.insert(iid) {
            continue;
        }
        let author = request
            .pointer("/author/id")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| common::fail("gitlab merge request has no author"))
            .to_string();
        let notes = history
            .notes
            .get(&iid)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let approvals = history
            .approvers
            .get(&iid)
            .into_iter()
            .flatten()
            .map(|actor| {
                json!({"actor":actor,"submitted_at":approval_time(notes, actor, merged),"state":"approved"})
            })
            .collect::<Vec<_>>();
        records.push(json!({
            "number":iid, "author":author,
            "merge_commit_sha":integration_revision(&request).unwrap_or_else(|| common::fail("gitlab merge request has no integration revision")),
            "merged_at":merged_at, "approvals":approvals,
            "enumeration_complete":history.approvals_read.contains(&iid) && history.notes_complete.contains(&iid)
        }));
    }
    records.sort_by_key(|record| record["number"].as_u64().unwrap_or(0));
    common::normalized(
        "gitlab:merge-request-reviews",
        json!({"pull_requests":records}),
        "observed_operation",
        "review_record",
    )
}

fn push_restricted(data: &Value) -> bool {
    let protected = data
        .get("protected_branches")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    !protected.is_empty()
        && protected.iter().all(|entry| {
            entry
                .get("push_access_levels")
                .and_then(Value::as_array)
                .is_some_and(|levels| {
                    levels.iter().all(|level| {
                        level.get("access_level").and_then(Value::as_u64) == Some(0)
                            && ["user_id", "group_id", "deploy_key_id"]
                                .iter()
                                .all(|field| level.get(*field).is_none_or(Value::is_null))
                    })
                })
        })
}

fn evaluate(input: &Value) -> Value {
    let evaluator = common::required_str(input, "evaluator");
    let branch = input
        .pointer("/target/branch")
        .and_then(Value::as_str)
        .unwrap_or("the branch");
    let (assertion_type, claim, predicate): (&str, String, fn(&Value) -> bool) = match evaluator {
        "protected-branch" => (
            "gitlab_branch_protected",
            format!("{branch} matches a GitLab protected-branch rule"),
            |data| {
                data.get("protected_branches")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())
            },
        ),
        "no-direct-push" => (
            "gitlab_direct_push_restricted",
            format!("no role, user, group, or deploy key may push directly to {branch}"),
            push_restricted,
        ),
        "approving-review" => (
            "configured_independent_review",
            format!("changes to {branch} are configured to require approval by someone other than the author before merge"),
            |data| {
                push_restricted(data)
                    && data
                        .pointer("/approval_settings/merge_requests_author_approval")
                        .and_then(Value::as_bool)
                        == Some(false)
                    && data
                        .get("approval_rules")
                        .and_then(Value::as_array)
                        .is_some_and(|rules| {
                            rules.iter().any(|rule| {
                                rule.get("approvals_required")
                                    .and_then(Value::as_u64)
                                    .is_some_and(|count| count > 0)
                            })
                        })
            },
        ),
        "force-push-disabled" => (
            "gitlab_force_push_disabled",
            format!("force pushes to {branch} are disabled"),
            |data| {
                data.get("protected_branches")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        !items.is_empty()
                            && items.iter().all(|entry| {
                                entry.get("allow_force_push").and_then(Value::as_bool)
                                    == Some(false)
                            })
                    })
            },
        ),
        _ => common::fail("unsupported evaluator"),
    };
    let target = input.get("target").unwrap_or(&Value::Null);
    let mut limitations = vec![json!(
        "current configuration does not establish historical enforcement"
    )];
    let observations = latest(input);
    if evaluator == "approving-review"
        && observations.iter().any(|item| {
            item.pointer("/data/approval_settings/disable_overriding_approvers_per_merge_request")
                .and_then(Value::as_bool)
                != Some(true)
        })
    {
        limitations.push(json!(
            "approval rules may be edited per merge request, so the project rules state intent, not a floor"
        ));
    }
    let mut result = json!({
        "assertion_type":assertion_type,"claim":claim,
        "subject":{"repository":target.get("repository"),"branch":target.get("branch"),"release":null,"from":null,"until":null},
        "outcome":"insufficient_evidence","evaluated_at":input.get("evaluated_at"),
        "validity":{"basis":"point_in_time","at":input.get("evaluated_at"),"from":null,"through":null,"fresh_until":null},
        "support":[],"contradictions":[],"considered":[],"missing":[],"identity_joins":[],"reasoning":[],
        "limitations":limitations,"coverage":[]
    });
    let uses = observations.iter().map(|observation| json!({"observation_id":observation.get("id"),"source_id":observation.pointer("/provenance/source_id"),"reason":"GitLab reported the protection and approval configuration for this branch"})).collect::<Vec<_>>();
    if !complete(input, &observations) {
        result["considered"] = json!(uses);
        result["missing"] = json!([{"requirement":"complete current GitLab branch-protection configuration","subject":target.get("repository"),"reason":"no complete authoritative branch-protection read is available"}]);
        return json!([result]);
    }
    let satisfied = observations
        .iter()
        .all(|item| item.get("data").is_some_and(predicate));
    result["reasoning"] = json!([{"code":format!("gitlab_{}",evaluator.replace('-', "_")),"conclusion":format!("GitLab's current configuration for {branch} {} this predicate", if satisfied { "satisfies" } else { "does not satisfy" }),"evidence_ids":observations.iter().filter_map(|item| item.get("id")).collect::<Vec<_>>()}]);
    if satisfied {
        result["outcome"] = json!("supported");
        result["support"] = json!(uses);
    } else {
        result["outcome"] = json!("contradicted");
        result["contradictions"] = json!(uses);
    }
    json!([result])
}

fn latest(evaluation: &Value) -> Vec<&Value> {
    let target = evaluation.get("target").unwrap_or(&Value::Null);
    let mut matching = evaluation
        .pointer("/corpus/observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("claim_key").and_then(Value::as_str) == Some("gitlab:branch-protection")
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

    const PROJECT: &str =
        "https://gitlab.example.org/api/v4/projects/example-group%2Fexample-project";
    const MERGED: &str = "1111111111111111111111111111111111111111";
    const DIRECT: &str = "2222222222222222222222222222222222222222";

    fn url(path: &str) -> String {
        format!("{PROJECT}{path}")
    }

    fn payload(exchanges: &[(String, Value)]) -> Value {
        let exchanges = exchanges
            .iter()
            .map(|(url, body)| (url.as_str(), body.clone()))
            .collect::<Vec<_>>();
        common::historical_payload(
            "gitlab:gitlab.example.org/example-group/example-project",
            "main",
            exchanges,
        )
    }

    fn push(id: u64, commit: &str) -> Value {
        json!({"id":id,"created_at":"2026-09-11T12:00:00Z","push_data":{"ref":"main","ref_type":"branch","commit_from":null,"commit_to":commit}})
    }

    #[test]
    fn push_joins_its_merge_request_and_unmatched_push_is_direct() {
        let payload = payload(&[
            (
                PROJECT.into(),
                json!({"id":7,"path_with_namespace":"example-group/example-project"}),
            ),
            (
                url("/events?action=pushed"),
                json!([push(1, MERGED), push(2, DIRECT),
                {"id":3,"created_at":"2026-09-11T12:00:00Z","push_data":{"ref":"other","ref_type":"branch","commit_to":DIRECT}}]),
            ),
            (
                url(&format!(
                    "/repository/commits/{MERGED}/merge_requests?per_page=100"
                )),
                json!([{"iid":42,"state":"merged","target_branch":"main","merge_commit_sha":MERGED}]),
            ),
            (
                url(&format!(
                    "/repository/commits/{DIRECT}/merge_requests?per_page=100"
                )),
                json!([]),
            ),
        ]);
        let events = normalize_mutations(&payload, "main")["data"]["events"].clone();
        assert_eq!(events.as_array().map(Vec::len), Some(2));
        assert_eq!(events[0]["kind"], "pull_request_merge");
        assert_eq!(events[0]["pull_request"], 42);
        assert_eq!(events[1]["kind"], "direct_push");
    }

    #[test]
    fn unread_association_is_not_called_a_direct_push() {
        let payload = payload(&[
            (
                PROJECT.into(),
                json!({"id":7,"path_with_namespace":"example-group/example-project"}),
            ),
            (url("/events?action=pushed"), json!([push(1, DIRECT)])),
        ]);
        assert_eq!(
            normalize_mutations(&payload, "main")["data"]["events"][0]["kind"],
            "pull_request_merge"
        );
    }

    #[test]
    fn approval_time_comes_from_the_approver_note_before_merge() {
        let payload = payload(&[
            (
                PROJECT.into(),
                json!({"id":7,"path_with_namespace":"example-group/example-project"}),
            ),
            (
                url("/merge_requests?state=merged"),
                json!([{"iid":42,"target_branch":"main","merged_at":"2026-09-11T12:00:00Z","author":{"id":1},"merge_commit_sha":MERGED}]),
            ),
            (
                url("/merge_requests/42/approvals"),
                json!({"approved_by":[{"user":{"id":2}}]}),
            ),
            (
                url("/merge_requests/42/notes?sort=asc"),
                json!([
                    {"system":true,"body":"approved this merge request","author":{"id":2},"created_at":"2026-09-11T11:00:00Z"},
                    {"system":true,"body":"approved this merge request","author":{"id":3},"created_at":"2026-09-11T11:30:00Z"},
                    {"system":false,"body":"approved this merge request","author":{"id":2},"created_at":"2026-09-11T11:45:00Z"}
                ]),
            ),
        ]);
        let record = normalize_reviews(&payload, "main")["data"]["pull_requests"][0].clone();
        assert_eq!(record["author"], "1");
        assert_eq!(record["merge_commit_sha"], MERGED);
        assert_eq!(record["enumeration_complete"], true);
        assert_eq!(record["approvals"].as_array().map(Vec::len), Some(1));
        assert_eq!(record["approvals"][0]["actor"], "2");
        assert_eq!(
            record["approvals"][0]["submitted_at"],
            "2026-09-11T11:00:00Z"
        );
    }

    #[test]
    fn wildcard_protection_and_approval_rule_scope() {
        assert!(branch_matches("main", "main"));
        assert!(branch_matches("release/*", "release/5.2"));
        assert!(branch_matches("*-stable", "5-2-stable"));
        assert!(!branch_matches("release/*", "main"));
        assert!(!branch_matches("main", "main2"));
        let payload = payload(&[
            (
                PROJECT.into(),
                json!({"id":7,"path_with_namespace":"example-group/example-project","merge_method":"merge"}),
            ),
            (
                url("/protected_branches?per_page=100"),
                json!([
                    {"name":"ma*","push_access_levels":[{"access_level":0}],"allow_force_push":false},
                    {"name":"release/*","push_access_levels":[{"access_level":40}],"allow_force_push":true}
                ]),
            ),
            (
                url("/approval_rules?per_page=100"),
                json!([
                    {"id":1,"name":"all","approvals_required":1,"protected_branches":[]},
                    {"id":2,"name":"release","approvals_required":2,"protected_branches":[{"name":"release/*"}]}
                ]),
            ),
            (
                url("/approvals"),
                json!({"merge_requests_author_approval":false,"disable_overriding_approvers_per_merge_request":true}),
            ),
        ]);
        let data = normalize_branch_protection(&payload, "main")["data"].clone();
        assert_eq!(data["protected_branches"].as_array().map(Vec::len), Some(1));
        assert_eq!(data["approval_rules"].as_array().map(Vec::len), Some(1));
        assert!(push_restricted(&data));
        let mut open = data.clone();
        open["protected_branches"][0]["push_access_levels"] = json!([{"access_level":40}]);
        assert!(!push_restricted(&open));
    }
}
