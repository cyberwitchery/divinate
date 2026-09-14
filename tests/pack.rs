use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use divinate::assertions::{AssertionType, DerivedAssertion, Outcome};
use divinate::model::{
    CollectionOutcome, CollectionRun, CollectionScope, Corpus, Enumeration, Producer, Proposition,
    Subject, TimeRange,
};
use divinate::{pack, project, read_json, workflow};

fn example(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn pack_config(executable: PathBuf, configuration: serde_json::Value) -> pack::PackConfig {
    pack::PackConfig {
        executable,
        configuration,
        timeout_seconds: 30,
    }
}

#[test]
fn every_pack_shape_shares_one_protocol() {
    let open = pack::describe(&pack_config(
        example("packs/sbom-collector/divinate-pack-sbom-collector"),
        serde_json::Value::Null,
    ))
    .unwrap()
    .0;
    let collector = pack::describe(&pack_config(
        example("packs/config-collector/divinate-pack-config-collector"),
        serde_json::Value::Null,
    ))
    .unwrap()
    .0;
    let evaluator = pack::describe(&pack_config(
        example("packs/external-evaluator/divinate-pack-external-evaluator"),
        serde_json::Value::Null,
    ))
    .unwrap()
    .0;
    assert_eq!(open.protocol_version, pack::PROTOCOL_VERSION);
    assert_eq!(collector.protocol_version, pack::PROTOCOL_VERSION);
    assert_eq!(evaluator.protocol_version, pack::PROTOCOL_VERSION);
    assert_eq!(open.collectors, ["release-diff"]);
    assert_eq!(collector.collectors, ["backup-encryption"]);
    assert_eq!(evaluator.evaluators, ["backup-encryption"]);
}

#[test]
fn github_pack_plans_remote_reads_without_receiving_credentials() {
    let config = pack_config(
        example("packs/github/divinate-pack-github"),
        serde_json::Value::Null,
    );
    let (metadata, _) = pack::describe(&config).unwrap();
    assert_eq!(metadata.id, "cyberwitchery.github");
    let context = serde_json::json!({
        "repository": "github:cyberwitchery/divinate",
        "branch": "main",
        "revision": "abc123",
        "interval": {
            "from": "2026-09-11T00:00:00Z",
            "until": "2026-09-12T00:00:00Z"
        },
        "observed_at": "2026-09-12T00:00:00Z",
        "configuration": {}
    });
    let (plan, capture) = pack::plan(&config, &metadata, "check-runs", &context).unwrap();
    assert!(matches!(
        plan.action().unwrap(),
        pack::CollectionAction::Remote {
            acquisition: pack::RemoteAcquisitionPlan::Github {
                resource: pack::GithubResource::CheckRuns,
                ..
            }
        }
    ));
    let retained = serde_json::to_string(&capture.invocation).unwrap();
    assert!(!retained.to_ascii_lowercase().contains("authorization"));
    assert!(!retained.to_ascii_lowercase().contains("token"));

    let (plan, capture) = pack::plan(&config, &metadata, "commit-statuses", &context).unwrap();
    assert!(matches!(
        plan.action().unwrap(),
        pack::CollectionAction::Remote {
            acquisition: pack::RemoteAcquisitionPlan::Github {
                resource: pack::GithubResource::CommitStatuses,
                ..
            }
        }
    ));
    let retained = serde_json::to_string(&capture.invocation).unwrap();
    assert!(!retained.to_ascii_lowercase().contains("authorization"));
    assert!(!retained.to_ascii_lowercase().contains("token"));
}

#[test]
fn github_pack_normalizes_branch_and_check_responses() {
    let config = pack_config(
        example("packs/github/divinate-pack-github"),
        serde_json::Value::Null,
    );
    let (metadata, _) = pack::describe(&config).unwrap();
    let subject = Subject {
        kind: "repository".into(),
        id: "github:cyberwitchery/divinate".into(),
        qualifiers: BTreeMap::from([
            ("branch".into(), serde_json::json!("main")),
            ("revision".into(), serde_json::json!("abc123")),
        ]),
    };
    let branch = br#"{"protected":false}"#;
    let (normalized, _) = pack::normalize(
        &config,
        &metadata,
        "github-branch-protection/v1",
        branch,
        &divinate::hex_digest(branch),
        &subject,
    )
    .unwrap();
    assert_eq!(normalized.claim_key, "github:branch-protection");
    assert_eq!(normalized.data["required_approving_review_count"], 0);

    let checks = br#"{"total_count":1,"check_runs":[{"name":"test","status":"completed","conclusion":"success","head_sha":"abc123"}]}"#;
    let (normalized, _) = pack::normalize(
        &config,
        &metadata,
        "github-check-runs/v1",
        checks,
        &divinate::hex_digest(checks),
        &subject,
    )
    .unwrap();
    assert_eq!(normalized.claim_key, "github:check-runs");
    assert_eq!(normalized.data["checks"][0]["conclusion"], "success");

    let statuses = br#"{"state":"success","total_count":1,"statuses":[{"context":"ci/legacy","state":"success","description":"passed","target_url":"https://example.invalid"}]}"#;
    let (normalized, _) = pack::normalize(
        &config,
        &metadata,
        "github-commit-statuses/v1",
        statuses,
        &divinate::hex_digest(statuses),
        &subject,
    )
    .unwrap();
    assert_eq!(normalized.claim_key, "github:commit-statuses");
    assert_eq!(normalized.data["statuses"][0]["context"], "ci/legacy");
    assert!(normalized.data["statuses"][0].get("target_url").is_none());
}

#[test]
fn azure_devops_pack_plans_and_normalizes_branch_policy() {
    let config = pack_config(
        example("packs/azure-devops/divinate-pack-azure-devops"),
        serde_json::Value::Null,
    );
    let (metadata, _) = pack::describe(&config).unwrap();
    assert_eq!(metadata.id, "cyberwitchery.azure-devops");
    let context = serde_json::json!({
        "repository": "azure-devops:example-org/example-project/example-repository",
        "branch": "develop",
        "revision": "abc123",
        "interval": {
            "from": "2026-09-11T00:00:00Z",
            "until": "2026-09-12T00:00:00Z"
        },
        "observed_at": "2026-09-12T00:00:00Z",
        "configuration": {}
    });
    let (plan, capture) = pack::plan(&config, &metadata, "branch-policy", &context).unwrap();
    assert!(matches!(
        plan.action().unwrap(),
        pack::CollectionAction::Remote {
            acquisition: pack::RemoteAcquisitionPlan::AzureDevops {
                resource: pack::AzureDevopsResource::BranchPolicy,
                ..
            }
        }
    ));
    let retained = serde_json::to_string(&capture.invocation).unwrap();
    assert!(!retained.to_ascii_lowercase().contains("authorization"));
    assert!(!retained.to_ascii_lowercase().contains("token"));

    let subject = Subject {
        kind: "repository".into(),
        id: "azure-devops:example-org/example-project/example-repository".into(),
        qualifiers: BTreeMap::from([
            ("branch".into(), serde_json::json!("develop")),
            ("revision".into(), serde_json::json!("abc123")),
        ]),
    };
    let response = br#"{"count":1,"value":[{"id":7,"isEnabled":true,"isBlocking":true,"type":{"id":"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd","displayName":"Minimum number of reviewers"},"settings":{"minimumApproverCount":2,"creatorVoteCounts":false,"resetOnSourcePush":true,"scope":[{"repositoryId":"repo-guid","refName":"refs/heads/develop","matchKind":"exact"}]}}]}"#;
    let (normalized, _) = pack::normalize(
        &config,
        &metadata,
        "azure-devops-branch-policy/v1",
        response,
        &divinate::hex_digest(response),
        &subject,
    )
    .unwrap();
    assert_eq!(normalized.claim_key, "azure-devops:branch-policy");
    assert_eq!(normalized.data["policies"][0]["minimum_approver_count"], 2);
    assert_eq!(
        normalized.data["policies"][0]["scopes"][0]["ref_name"],
        "refs/heads/develop"
    );
}

#[test]
fn azure_devops_policy_assertions_require_complete_current_configuration() {
    let policies = serde_json::json!([
        {
            "id": 1,
            "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
            "type_name": "Minimum number of reviewers",
            "enabled": true,
            "blocking": true,
            "minimum_approver_count": 2,
            "creator_vote_counts": false,
            "reset_on_source_push": true,
            "reset_rejections_on_source_push": null,
            "block_last_pusher_vote": null,
            "build_definition_id": null,
            "status_name": null,
            "scopes": []
        },
        {
            "id": 2,
            "type_id": "0609b952-1397-4640-95ec-e00a01b2c241",
            "type_name": "Build",
            "enabled": true,
            "blocking": true,
            "minimum_approver_count": null,
            "creator_vote_counts": null,
            "reset_on_source_push": null,
            "reset_rejections_on_source_push": null,
            "block_last_pusher_vote": null,
            "build_definition_id": 5,
            "status_name": null,
            "scopes": []
        }
    ]);
    for evaluator in ["blocking-policy", "approving-review", "build-validation"] {
        let response = azure_pack_result(&azure_policy_evaluation(evaluator, &policies, true));
        assert_eq!(response["result"][0]["outcome"], "supported");
        if evaluator == "approving-review" {
            assert_eq!(
                response["result"][0]["assertion_type"],
                "configured_independent_review"
            );
            assert_eq!(
                response["result"][0]["claim"],
                "changes to develop are configured to require approval before merge"
            );
            assert_eq!(
                response["result"][0]["subject"]["from"],
                serde_json::Value::Null
            );
            assert_eq!(
                response["result"][0]["subject"]["until"],
                serde_json::Value::Null
            );
        }
    }
}

#[test]
fn azure_devops_review_assertion_rejects_incomplete_or_nonqualifying_policy() {
    let qualifying = serde_json::json!([{
        "id": 1,
        "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
        "enabled": true,
        "blocking": true,
        "minimum_approver_count": 2
    }]);
    let response = azure_pack_result(&azure_policy_evaluation(
        "approving-review",
        &qualifying,
        false,
    ));
    assert_eq!(response["result"][0]["outcome"], "insufficient_evidence");
    let response = azure_pack_result(&azure_policy_evaluation(
        "build-validation",
        &serde_json::json!([]),
        true,
    ));
    assert_eq!(response["result"][0]["outcome"], "contradicted");
    let response = azure_pack_result(&azure_policy_evaluation(
        "approving-review",
        &serde_json::json!([]),
        true,
    ));
    assert_eq!(response["result"][0]["outcome"], "contradicted");

    for policy in [
        serde_json::json!({
            "id": 3,
            "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
            "enabled": false,
            "blocking": true,
            "minimum_approver_count": 2
        }),
        serde_json::json!({
            "id": 4,
            "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
            "enabled": true,
            "blocking": false,
            "minimum_approver_count": 2
        }),
        serde_json::json!({
            "id": 5,
            "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd",
            "enabled": true,
            "blocking": true,
            "minimum_approver_count": 0
        }),
    ] {
        let response = azure_pack_result(&azure_policy_evaluation(
            "approving-review",
            &serde_json::json!([policy]),
            true,
        ));
        assert_eq!(response["result"][0]["outcome"], "contradicted");
    }

    let mut mismatched = azure_policy_evaluation("approving-review", &qualifying, true);
    mismatched["input"]["corpus"]["observations"][0]["subject"]["branch"] =
        serde_json::json!("main");
    let response = azure_pack_result(&mismatched);
    assert_eq!(response["result"][0]["outcome"], "insufficient_evidence");
}

#[test]
fn github_ci_assertion_requires_both_status_mechanisms() {
    let success_check = serde_json::json!({
        "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
    });
    let success_status = serde_json::json!({"context": "legacy", "state": "success"});
    assert_eq!(
        github_ci_outcome(
            &[
                success_check.clone(),
                serde_json::json!({
                    "name": "advisory", "status": "completed", "conclusion": "neutral", "head_sha": "abc123"
                }),
                serde_json::json!({
                    "name": "optional", "status": "completed", "conclusion": "skipped", "head_sha": "abc123"
                }),
            ],
            std::slice::from_ref(&success_status),
            true,
            true
        ),
        "supported"
    );
    assert_eq!(
        github_ci_outcome(
            &[serde_json::json!({
                "name": "test", "status": "completed", "conclusion": "failure", "head_sha": "abc123"
            })],
            std::slice::from_ref(&success_status),
            true,
            true,
        ),
        "contradicted"
    );
    assert_eq!(
        github_ci_outcome(
            std::slice::from_ref(&success_check),
            &[serde_json::json!({"context": "legacy", "state": "error"})],
            true,
            true,
        ),
        "contradicted"
    );
    assert_eq!(
        github_ci_outcome(
            std::slice::from_ref(&success_check),
            &[serde_json::json!({"context": "legacy", "state": "pending"})],
            true,
            true,
        ),
        "insufficient_evidence"
    );
    assert_eq!(
        github_ci_outcome(
            &[serde_json::json!({
                "name": "test", "status": "queued", "conclusion": null, "head_sha": "abc123"
            })],
            std::slice::from_ref(&success_status),
            true,
            true,
        ),
        "insufficient_evidence"
    );
    assert_eq!(
        github_ci_outcome(&[], &[], true, true),
        "insufficient_evidence"
    );
    assert_eq!(
        github_ci_outcome(
            std::slice::from_ref(&success_check),
            std::slice::from_ref(&success_status),
            false,
            true
        ),
        "insufficient_evidence"
    );
    assert_eq!(
        github_ci_outcome(
            std::slice::from_ref(&success_check),
            std::slice::from_ref(&success_status),
            true,
            false,
        ),
        "insufficient_evidence"
    );
}

#[test]
fn github_ci_unknown_results_are_insufficient() {
    let success_check = serde_json::json!({
        "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
    });
    let success_status = serde_json::json!({"context": "legacy", "state": "success"});
    assert_eq!(
        github_ci_outcome(
            &[serde_json::json!({
                "name": "future", "status": "completed", "conclusion": "new_conclusion", "head_sha": "abc123"
            })],
            std::slice::from_ref(&success_status),
            true,
            true,
        ),
        "insufficient_evidence"
    );
    assert_eq!(
        github_ci_outcome(
            std::slice::from_ref(&success_check),
            &[serde_json::json!({"context": "future", "state": "new_state"})],
            true,
            true,
        ),
        "insufficient_evidence"
    );
}

#[test]
fn github_ci_assertion_wording_matches_the_observed_result_predicate() {
    let assertion = github_ci_assertion(
        &[
            serde_json::json!({
                "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
            }),
            serde_json::json!({
                "name": "advisory", "status": "completed", "conclusion": "neutral", "head_sha": "abc123"
            }),
            serde_json::json!({
                "name": "optional", "status": "completed", "conclusion": "skipped", "head_sha": "abc123"
            }),
        ],
        &[serde_json::json!({"context": "legacy", "state": "success"})],
        true,
        true,
    );
    assert_eq!(
        assertion["assertion_type"],
        "github_current_revision_checks_passed"
    );
    assert_eq!(
        assertion["claim"],
        "GitHub check runs and commit statuses for the current revision were completely enumerated and had acceptable terminal outcomes"
    );
    assert_eq!(assertion["outcome"], "supported");
    assert!(assertion["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("3 check runs and 1 classic commit status"));
    assert!(assertion["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("not satisfaction of configured")));
}

#[test]
fn github_ci_insufficient_reasoning_names_the_gap() {
    let empty = github_ci_assertion(&[], &[], true, true);
    assert!(empty["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("reported no CI results"));

    let incomplete = github_ci_assertion(
        &[serde_json::json!({
            "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "legacy", "state": "success"})],
        false,
        true,
    );
    assert_eq!(incomplete["outcome"], "insufficient_evidence");
    assert!(incomplete["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("check-run enumeration was incomplete"));

    let pending = github_ci_assertion(
        &[serde_json::json!({
            "name": "test", "status": "in_progress", "conclusion": null, "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "legacy", "state": "success"})],
        true,
        true,
    );
    assert_eq!(pending["outcome"], "insufficient_evidence");
    assert!(pending["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("pending, transitional, or unrecognized"));
}

#[test]
fn github_ci_assertion_requires_a_same_revision_join() {
    let mut request = github_ci_request(
        &[serde_json::json!({
            "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "legacy", "state": "success"})],
        true,
        true,
    );
    request["input"]["corpus"]["observations"][1]["subject"]["revision"] =
        serde_json::json!("different");
    let response = github_pack_result(&request);
    assert_eq!(response["result"][0]["outcome"], "insufficient_evidence");
    assert!(response["result"][0]["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("did not resolve to the same revision"));
}

#[test]
fn github_required_context_configuration_remains_a_separate_claim() {
    let response = github_pack_result(&serde_json::json!({
        "protocol_version": 1,
        "operation": "evaluate",
        "configuration": null,
        "input": {
            "evaluator": "required-status-checks",
            "target": {
                "repository": "github:cyberwitchery/divinate",
                "branch": "main",
                "release": null,
                "from": "2026-09-11T00:00:00Z",
                "until": "2026-09-12T00:00:00Z"
            },
            "evaluated_at": "2026-09-12T00:00:00Z",
            "coverage": [{"outcome": "incomplete"}],
            "corpus": {"collections": [], "observations": []}
        }
    }));
    assert_eq!(response["result"][0]["outcome"], "insufficient_evidence");
    assert_eq!(
        response["result"][0]["missing"][0]["requirement"],
        "current github branch protection configuration"
    );

    let mut request = github_ci_request(
        &[serde_json::json!({
            "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "test", "state": "success"})],
        true,
        true,
    );
    request["input"]["corpus"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "protection",
            "claim_key": "github:branch-protection",
            "observed_at": "2026-09-12T00:00:00Z",
            "subject": {"id": "github:cyberwitchery/divinate", "branch": "main"},
            "data": {"required_status_checks": ["test", "missing"]},
            "provenance": {"source_id": "src_protection"}
        }));
    let response = github_pack_result(&request);
    assert_eq!(response["result"][0]["outcome"], "supported");
    assert!(response["result"][0]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("not satisfaction of configured")));
}

#[test]
fn github_ci_failure_contradicts_despite_incomplete_enumeration() {
    let assertion = github_ci_assertion(
        &[serde_json::json!({
            "name": "test", "status": "completed", "conclusion": "failure", "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "legacy", "state": "success"})],
        false,
        true,
    );
    assert_eq!(assertion["outcome"], "contradicted");
    assert!(assertion["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("1 check run and no commit statuses had failing"));

    let assertion = github_ci_assertion(
        &[serde_json::json!({
            "name": "test", "status": "completed", "conclusion": "success", "head_sha": "abc123"
        })],
        &[serde_json::json!({"context": "legacy", "state": "failure"})],
        true,
        false,
    );
    assert_eq!(assertion["outcome"], "contradicted");
    assert!(assertion["reasoning"][0]["conclusion"]
        .as_str()
        .unwrap()
        .contains("no check runs and 1 commit status had failing"));
}

#[test]
fn open_sbom_integration_collects_through_the_pack_boundary() {
    let state = tempfile::tempdir().unwrap();
    let tool = state.path().join("sbom-diff");
    executable(
        &tool,
        b"#!/bin/sh\nprintf '%s\\n' '{\"added\":[],\"removed\":[],\"changed\":[],\"edge_diffs\":[],\"metadata_changed\":null,\"old_total\":1,\"new_total\":1,\"unchanged\":1}'\n",
    );
    let base = state.path().join("base.json");
    let target = state.path().join("target.json");
    fs::write(&base, b"base").unwrap();
    fs::write(&target, b"target").unwrap();
    configure_project(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            sources: BTreeMap::default(),
            packs: BTreeMap::from([(
                "example.sbom-release-diff".into(),
                pack_config(
                    example("packs/sbom-collector/divinate-pack-sbom-collector"),
                    serde_json::json!({
                        "repository": "github:cyberwitchery/example",
                        "release": "v1.1", "base_release": "v1.0",
                        "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "base_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "executable": tool, "base_sbom": base, "target_sbom": target,
                        "tool_version": "test", "observed_at": "2026-09-08T12:00:00Z"
                    }),
                ),
            )]),
        },
    )
    .unwrap();
    cli(&[
        "collect",
        "pack",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        state.path().to_str().unwrap(),
        "example.sbom-release-diff",
        "release-diff",
    ]);
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(
        corpus.observations[0].claim_key,
        "sbom-diff:dependency-change"
    );
    assert_eq!(corpus.observations[0].pack_invocation_ids.len(), 3);
    let mut mismatched = corpus.clone();
    mismatched.observations[0]
        .subject
        .qualifiers
        .insert("release".into(), serde_json::json!("v2.0"));
    let invocations = workflow::load_pack_invocations(state.path()).unwrap();
    let executions = workflow::load_executions(state.path()).unwrap();
    let blobs = workflow::load_blobs(state.path()).unwrap();
    assert!(
        pack::verify_observation_links(&mismatched, &invocations, &executions, &blobs)
            .unwrap_err()
            .to_string()
            .contains("subject, time, or adapter")
    );
}

#[test]
fn configured_pack_collector_runs_and_evaluates_in_normal_collect() {
    let state = tempfile::tempdir().unwrap();
    let tool = state.path().join("sbom-diff");
    executable(
        &tool,
        b"#!/bin/sh\nprintf '%s\\n' '{\"added\":[],\"removed\":[],\"changed\":[],\"edge_diffs\":[],\"metadata_changed\":null,\"old_total\":1,\"new_total\":1,\"unchanged\":1}'\n",
    );
    let base = state.path().join("base.json");
    let target = state.path().join("target.json");
    let optional = state.path().join("optional-pack");
    executable(&optional, b"#!/bin/sh\nexit 9\n");
    fs::write(&base, b"base").unwrap();
    fs::write(&target, b"target").unwrap();
    configure_project(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            sources: BTreeMap::from([
                (
                    "release-diff".into(),
                    workflow::SourceConfig {
                        provider: workflow::SourceProvider::Pack {
                            pack: "example.sbom-release-diff".into(),
                            collector: "release-diff".into(),
                        },
                        configuration: serde_json::Value::Null,
                        context: workflow::SourceContext::Repository,
                        enabled: true,
                        required: true,
                    },
                ),
                (
                    "optional".into(),
                    workflow::SourceConfig {
                        provider: workflow::SourceProvider::Pack {
                            pack: "example.optional".into(),
                            collector: "extra".into(),
                        },
                        configuration: serde_json::Value::Null,
                        context: workflow::SourceContext::Repository,
                        enabled: true,
                        required: false,
                    },
                ),
            ]),
            packs: BTreeMap::from([
                (
                    "example.sbom-release-diff".into(),
                    pack_config(
                        example("packs/sbom-collector/divinate-pack-sbom-collector"),
                        serde_json::json!({
                            "repository": "github:cyberwitchery/example",
                            "release": "v1.1", "base_release": "v1.0",
                            "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "base_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "executable": tool, "base_sbom": base, "target_sbom": target,
                            "observed_at": "2026-09-08T12:00:00Z"
                        }),
                    ),
                ),
                (
                    "example.optional".into(),
                    pack_config(optional, serde_json::Value::Null),
                ),
            ]),
        },
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["collect", "--state"])
        .arg(state.path())
        .arg("--repository-path")
        .arg(state.path())
        .args([
            "--from",
            "2026-09-01T00:00:00Z",
            "--until",
            "2026-09-09T00:00:00Z",
            "--at",
            "2026-09-09T00:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("release-diff"));
    assert!(stdout.contains("optional"));
    assert!(stdout.contains("failed (optional)"));
    assert!(state.path().join("assertions/current.json").is_file());
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 1);
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 1);
}

#[test]
fn required_pack_failure_is_named_and_writes_no_canonical_evidence() {
    let state = tempfile::tempdir().unwrap();
    let crashing = state.path().join("crashing-pack");
    executable(&crashing, b"#!/bin/sh\nexit 7\n");
    configure_project(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            sources: BTreeMap::from([(
                "crash".into(),
                workflow::SourceConfig {
                    provider: workflow::SourceProvider::Pack {
                        pack: "example.crash".into(),
                        collector: "anything".into(),
                    },
                    configuration: serde_json::Value::Null,
                    context: workflow::SourceContext::Repository,
                    enabled: true,
                    required: true,
                },
            )]),
            packs: BTreeMap::from([(
                "example.crash".into(),
                pack_config(crashing, serde_json::Value::Null),
            )]),
        },
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["collect", "--state"])
        .arg(state.path())
        .arg("--repository-path")
        .arg(state.path())
        .args(["--from", "2026-09-01T00:00:00Z"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("required source crash failed"));
    assert!(!workflow::corpus_path(state.path()).exists());
    assert!(!state.path().join("assertions/current.json").exists());
}

#[test]
fn status_reports_saved_incomplete_collection_without_reinterpreting_it() {
    let state = tempfile::tempdir().unwrap();
    configure_project(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            sources: BTreeMap::default(),
            packs: BTreeMap::default(),
        },
    )
    .unwrap();
    let mut run = collection_run("partial", Proposition::RepositoryMutations);
    run.outcome = CollectionOutcome::Partial;
    run.observed_scope = None;
    run.authority.clear();
    let corpus = Corpus {
        schema_version: divinate::SCHEMA_VERSION.into(),
        collections: vec![run],
        observations: vec![],
        sources: vec![],
    };
    divinate::write_json(&corpus, &workflow::corpus_path(state.path())).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["status", "--state"])
        .arg(state.path())
        .arg("--repository-path")
        .arg(state.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let status = String::from_utf8(output.stdout).unwrap();
    assert!(status.contains("degraded collections"));
    assert!(status.contains("fixture / fixture  partial"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn release_context_is_supplied_consistently_to_multiple_configured_sources() {
    let directory = tempfile::tempdir().unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-q"]);
    git(&repository, &["config", "user.name", "Divinate Test"]);
    git(
        &repository,
        &["config", "user.email", "divinate@example.invalid"],
    );
    git(
        &repository,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:cyberwitchery/example.git",
        ],
    );
    fs::write(repository.join("tracked"), "one\n").unwrap();
    git(&repository, &["add", "tracked"]);
    git(&repository, &["commit", "-qm", "one"]);
    git(&repository, &["tag", "v1.0"]);
    fs::write(repository.join("tracked"), "two\n").unwrap();
    git(&repository, &["commit", "-qam", "two"]);
    git(&repository, &["tag", "v1.1"]);

    let state = directory.path().join("state");
    let context_pack = directory.path().join("context-pack");
    executable(
        &context_pack,
        br#"#!/usr/bin/env python3
import json,sys
r=json.load(sys.stdin)
op=r["operation"]
if op=="describe":
 x={"id":"example.context","version":"1","protocol_version":1,"collectors":["release"],"evaluators":[],"evaluator_inputs":{},"evaluator_propositions":{},"source_contracts":[],"configuration_schema":{}}
elif op=="collect":
 c=r["input"]["context"]; rel=c["release"]; label=c["configuration"]["label"]
 payload=json.dumps({"label":label,"release":rel["release"],"revision":rel["revision"],"previous_release":rel["previous_release"],"previous_revision":rel["previous_revision"]},separators=(",",":"))
 x={"adapter":"context","subject":{"kind":"release","id":c["repository"]+":"+rel["release"],"repository":c["repository"],"release":rel["release"],"revision":rel["revision"],"base_release":rel["previous_release"],"base_revision":rel["previous_revision"]},"observed_at":c["observed_at"],"command":{"tool_name":"printf","executable":"/usr/bin/printf","argv":["%s",payload],"inputs":{}}}
elif op=="normalize":
 p=json.loads(r["input"]["source"]["content"]); x={"claim_key":"context:"+p["label"],"data":p,"evidence_class":"observed_state","kind":"configuration_snapshot","severity":None,"status":None}
else:
 print(json.dumps({"ok":False,"error":"unsupported"})); raise SystemExit
print(json.dumps({"ok":True,"result":x},separators=(",",":")))
"#,
    );
    configure_project(
        &repository,
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            packs: BTreeMap::from([(
                "example.context".into(),
                pack_config(context_pack, serde_json::json!({})),
            )]),
            sources: [("first", "one"), ("second", "two")]
                .into_iter()
                .map(|(id, label)| {
                    (
                        id.into(),
                        workflow::SourceConfig {
                            provider: workflow::SourceProvider::Pack {
                                pack: "example.context".into(),
                                collector: "release".into(),
                            },
                            configuration: serde_json::json!({"label": label}),
                            context: workflow::SourceContext::Release,
                            enabled: true,
                            required: true,
                        },
                    )
                })
                .collect(),
        },
    )
    .unwrap();
    cli(&[
        "collect",
        "--state",
        state.to_str().unwrap(),
        "--repository-path",
        repository.to_str().unwrap(),
        "--release",
        "v1.1",
        "--base-release",
        "v1.0",
        "--from",
        "2026-01-01T00:00:00Z",
        "--until",
        "2030-01-01T00:00:00Z",
        "--at",
        "2030-01-01T00:00:00Z",
    ]);
    let corpus = divinate::load_corpus(&workflow::corpus_path(&state)).unwrap();
    assert_eq!(corpus.observations.len(), 2);
    let revisions = corpus
        .observations
        .iter()
        .map(|observation| observation.subject.qualifier("revision").unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(revisions.len(), 1);
    assert_eq!(
        corpus
            .observations
            .iter()
            .map(|observation| observation.data["label"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["one", "two"])
    );
    cli(&["verify", "--state", state.to_str().unwrap()]);
}

#[test]
fn pack_collection_and_external_assertion_keep_core_provenance() {
    let state = tempfile::tempdir().unwrap();
    let evaluator_path = state.path().join("evaluator-pack");
    let evaluator_bytes = fs::read(example(
        "packs/external-evaluator/divinate-pack-external-evaluator",
    ))
    .unwrap();
    executable(&evaluator_path, &evaluator_bytes);
    let collector = pack_config(
        example("packs/config-collector/divinate-pack-config-collector"),
        serde_json::json!({
            "repository": "github:cyberwitchery/example",
            "source_command": "/usr/bin/printf",
            "source_argv": ["%s", "{\"encrypted\":true}"],
            "observed_at": "2026-09-08T12:00:00Z"
        }),
    );
    let evaluator = pack_config(evaluator_path.clone(), serde_json::Value::Null);
    configure_project(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            sources: BTreeMap::default(),
            packs: BTreeMap::from([
                ("example.backup-control".into(), collector),
                ("example.backup-evaluator".into(), evaluator),
            ]),
        },
    )
    .unwrap();
    cli(&[
        "collect",
        "pack",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        state.path().to_str().unwrap(),
        "example.backup-control",
        "backup-encryption",
    ]);
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 1);
    assert_eq!(corpus.observations[0].pack_invocation_ids.len(), 3);
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 1);

    assert_before_execution_is_insufficient(state.path());

    evaluate(state.path(), "current");
    let assertions: Vec<DerivedAssertion> =
        read_json(&state.path().join("assertions/current.json")).unwrap();
    let assertion = assertions
        .iter()
        .find(|item| {
            item.assertion_type == AssertionType::External("internal_backup_encryption".into())
        })
        .unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);
    assert!(assertion.derivation.pack_invocation_id.is_some());
    let invocations = workflow::load_pack_invocations(state.path()).unwrap();
    let blobs = workflow::load_blobs(state.path()).unwrap();
    let executions = workflow::load_executions(state.path()).unwrap();
    pack::verify_observation_links(&corpus, &invocations, &executions, &blobs).unwrap();
    pack::verify_assertion_links(&assertions, &invocations, &blobs).unwrap();
    let mut tampered_assertions = assertions.clone();
    tampered_assertions
        .iter_mut()
        .find(|item| item.id == assertion.id)
        .unwrap()
        .outcome = Outcome::Contradicted;
    assert!(
        pack::verify_assertion_links(&tampered_assertions, &invocations, &blobs)
            .unwrap_err()
            .to_string()
            .contains("does not match its retained pack response")
    );

    let historical_bytes = fs::read(state.path().join("assertions/current.json")).unwrap();
    let historical_pack_invocation = assertion.derivation.pack_invocation_id.clone().unwrap();
    let mut updated_pack = evaluator_bytes;
    updated_pack.extend_from_slice(b"\n# independently updated\n");
    executable(&evaluator_path, &updated_pack);
    evaluate(state.path(), "updated");
    assert_eq!(
        fs::read(state.path().join("assertions/current.json")).unwrap(),
        historical_bytes
    );
    let updated: Vec<DerivedAssertion> =
        read_json(&state.path().join("assertions/updated.json")).unwrap();
    let updated_assertion = updated
        .iter()
        .find(|item| {
            item.assertion_type == AssertionType::External("internal_backup_encryption".into())
        })
        .unwrap();
    assert_ne!(
        updated_assertion.derivation.pack_invocation_id.as_ref(),
        Some(&historical_pack_invocation)
    );
    let updated_invocations = workflow::load_pack_invocations(state.path()).unwrap();
    let updated_blobs = workflow::load_blobs(state.path()).unwrap();
    pack::verify_assertion_links(&assertions, &updated_invocations, &updated_blobs).unwrap();
    pack::verify_assertion_links(&updated, &updated_invocations, &updated_blobs).unwrap();
    cli(&["verify", "--state", state.path().to_str().unwrap()]);
}

#[test]
fn executable_changes_change_identity_without_rewriting_history() {
    let state = tempfile::tempdir().unwrap();
    let original = fs::read(example(
        "packs/config-collector/divinate-pack-config-collector",
    ))
    .unwrap();
    let first_path = state.path().join("pack-one");
    let second_path = state.path().join("pack-two");
    executable(&first_path, &original);
    let mut changed = original;
    changed.extend_from_slice(b"\n# independently updated\n");
    executable(&second_path, &changed);
    let first = pack::describe(&pack_config(first_path, serde_json::Value::Null))
        .unwrap()
        .1;
    let identical = pack::describe(&pack_config(
        state.path().join("pack-one"),
        serde_json::Value::Null,
    ))
    .unwrap()
    .1;
    let second = pack::describe(&pack_config(second_path, serde_json::Value::Null))
        .unwrap()
        .1;
    assert_ne!(first.invocation.id, second.invocation.id);
    assert_eq!(first.invocation.id, identical.invocation.id);
    assert_ne!(
        first.invocation.contents.executable,
        second.invocation.contents.executable
    );
    workflow::store_pack_invocations(state.path(), &[first.clone(), second]).unwrap();
    let stored = workflow::load_pack_invocations(state.path()).unwrap();
    assert!(stored.iter().any(|item| item == &first.invocation));
}

#[test]
fn evaluator_receives_declared_zero_result_coverage_but_not_unrelated_runs() {
    let state = tempfile::tempdir().unwrap();
    let path = state.path().join("coverage-pack");
    executable(
        &path,
        b"#!/usr/bin/env python3\nimport json,sys\nr=json.load(sys.stdin)\nif r['operation']=='describe': x={'id':'example.coverage','version':'1','protocol_version':1,'collectors':[],'evaluators':['check'],'evaluator_inputs':{'check':[]},'evaluator_propositions':{'check':['repository_mutations']},'source_contracts':[],'configuration_schema':{}}\nelif r['operation']=='evaluate': x=[]\nelse: print(json.dumps({'ok':False,'error':'unsupported'})); raise SystemExit\nprint(json.dumps({'ok':True,'result':x},separators=(',',':')))\n",
    );
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let corpus = Corpus {
        schema_version: divinate::SCHEMA_VERSION.into(),
        collections: vec![
            collection_run("relevant-zero", Proposition::RepositoryMutations),
            collection_run("unrelated-zero", Proposition::PullRequestReviews),
        ],
        observations: vec![],
        sources: vec![],
    };
    let target = divinate::assertions::EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: Some("v1".into()),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-09T00:00:00Z".into(),
    };
    let (_, capture) = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:00:00Z",
    )
    .unwrap();
    let request: serde_json::Value =
        serde_json::from_str(&capture.invocation.contents.request).unwrap();
    let runs = request["input"]["corpus"]["collections"]
        .as_array()
        .unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["id"], "relevant-zero");
}

#[test]
fn assertion_wording_does_not_change_core_identity() {
    let state = tempfile::tempdir().unwrap();
    let corpus = Corpus {
        schema_version: divinate::SCHEMA_VERSION.into(),
        collections: vec![collection_run(
            "relevant-zero",
            Proposition::RepositoryMutations,
        )],
        observations: vec![],
        sources: vec![],
    };
    let target = pack_target();
    let requirement = divinate::coverage::CoverageRequirement {
        proposition: Proposition::RepositoryMutations,
        repository: target.repository.clone(),
        branch: Some(target.branch.clone()),
        interval: TimeRange {
            from: target.from.clone(),
            until: target.until.clone(),
        },
    };
    let complete = divinate::coverage::assess(
        &corpus,
        requirement,
        divinate::parse_timestamp("2026-09-09T00:01:00Z").unwrap(),
    )
    .unwrap();
    let original = pack_assertion(&target, &serde_json::json!([complete.clone()]));
    let path = state.path().join("original-wording-pack");
    assertion_pack(&path, &original);
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let first = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:01:00Z",
    )
    .unwrap()
    .0
    .remove(0);
    let mut reworded = original;
    reworded["claim"] = serde_json::json!("the same semantic claim with revised wording");
    let path = state.path().join("reworded-pack");
    assertion_pack(&path, &reworded);
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let second = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:01:00Z",
    )
    .unwrap()
    .0
    .remove(0);
    assert_eq!(first.id, second.id);
    assert_ne!(first.claim, second.claim);
}

#[test]
fn core_assigns_assertion_identity_and_rejects_false_or_missing_coverage() {
    let state = tempfile::tempdir().unwrap();
    let corpus = Corpus {
        schema_version: divinate::SCHEMA_VERSION.into(),
        collections: vec![collection_run(
            "relevant-zero",
            Proposition::RepositoryMutations,
        )],
        observations: vec![],
        sources: vec![],
    };
    let target = pack_target();
    let requirement = divinate::coverage::CoverageRequirement {
        proposition: Proposition::RepositoryMutations,
        repository: target.repository.clone(),
        branch: Some(target.branch.clone()),
        interval: TimeRange {
            from: target.from.clone(),
            until: target.until.clone(),
        },
    };
    let complete = divinate::coverage::assess(
        &corpus,
        requirement,
        divinate::parse_timestamp("2026-09-09T00:01:00Z").unwrap(),
    )
    .unwrap();

    let mut decision = complete.clone();
    decision.outcome = divinate::coverage::CoverageOutcome::Incomplete;
    let assertion = pack_assertion(&target, &serde_json::json!([decision]));
    let path = state.path().join("false-coverage-pack");
    assertion_pack(&path, &assertion);
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let error = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:01:00Z",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("does not match core assessment"),
        "{error}"
    );

    let path = state.path().join("missing-coverage-pack");
    assertion_pack(&path, &pack_assertion(&target, &serde_json::json!([])));
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let error = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:01:00Z",
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("supported without complete RepositoryMutations coverage"));

    let mut point_in_time = pack_assertion(&target, &serde_json::json!([complete]));
    point_in_time["subject"]
        .as_object_mut()
        .unwrap()
        .remove("from");
    point_in_time["subject"]
        .as_object_mut()
        .unwrap()
        .remove("until");
    let path = state.path().join("point-in-time-coverage-pack");
    assertion_pack(&path, &point_in_time);
    let config = pack_config(path, serde_json::Value::Null);
    let (metadata, _) = pack::describe(&config).unwrap();
    let error = pack::evaluate(
        &config,
        &metadata,
        "check",
        &corpus,
        &target,
        "2026-09-09T00:01:00Z",
    )
    .unwrap_err();
    assert!(error.to_string().contains("subject lacks from or until"));
}

#[test]
fn pack_timeout_is_bounded() {
    let state = tempfile::tempdir().unwrap();
    let path = state.path().join("hung-pack");
    executable(
        &path,
        b"#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n",
    );
    let started = std::time::Instant::now();
    let error = pack::describe(&pack::PackConfig {
        executable: path,
        configuration: serde_json::Value::Null,
        timeout_seconds: 1,
    })
    .unwrap_err();
    assert!(error.to_string().contains("timed out after 1 second"));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}

#[test]
fn credential_like_configuration_is_not_sent_or_retained() {
    let error = pack::describe(&pack_config(
        example("packs/config-collector/divinate-pack-config-collector"),
        serde_json::json!({"api_token": "not-retained"}),
    ))
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("credential-like pack configuration"));
}

#[test]
fn protocol_crash_and_malformed_response_do_not_create_canonical_evidence() {
    for (name, body, expected) in [
        (
            "crash",
            b"#!/bin/sh\ncat >/dev/null\nexit 7\n".as_slice(),
            "exited with",
        ),
        (
            "malformed",
            b"#!/bin/sh\ncat >/dev/null\nprintf noise\n".as_slice(),
            "invalid pack",
        ),
        (
            "incompatible",
            b"#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"ok\":true,\"result\":{\"id\":\"bad\",\"version\":\"1\",\"protocol_version\":2,\"collectors\":[],\"evaluators\":[],\"evaluator_inputs\":{},\"evaluator_propositions\":{},\"source_contracts\":[],\"configuration_schema\":{}}}'\n".as_slice(),
            "uses protocol 2",
        ),
    ] {
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join(name);
        executable(&path, body);
        let error = pack::describe(&pack_config(path, serde_json::Value::Null)).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert!(!workflow::corpus_path(state.path()).exists());
        assert!(workflow::load_pack_invocations(state.path()).unwrap().is_empty());
    }
}

fn cli(args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "divinate {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn evaluate(state: &Path, label: &str) {
    let at = (time::OffsetDateTime::now_utc() + time::Duration::minutes(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    evaluate_at(state, label, &at);
}

fn evaluate_at(state: &Path, label: &str, at: &str) {
    cli(&[
        "evaluate",
        "--state",
        state.to_str().unwrap(),
        "--repository-path",
        state.to_str().unwrap(),
        "--label",
        label,
        "--release",
        "v1",
        "--from",
        "2026-09-01T00:00:00Z",
        "--until",
        at,
        "--at",
        at,
    ]);
}

fn assert_before_execution_is_insufficient(state: &Path) {
    let completed_at = divinate::parse_timestamp(
        &workflow::load_executions(state).unwrap()[0]
            .contents
            .completed_at,
    )
    .unwrap();
    let before_execution = (completed_at - time::Duration::seconds(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    evaluate_at(state, "before-execution", &before_execution);
    let historical: Vec<DerivedAssertion> =
        read_json(&state.join("assertions/before-execution.json")).unwrap();
    assert!(historical.iter().any(|item| {
        item.assertion_type == AssertionType::External("internal_backup_encryption".into())
            && item.outcome == Outcome::InsufficientEvidence
    }));
}

fn collection_run(id: &str, proposition: Proposition) -> CollectionRun {
    let interval = TimeRange {
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-09T00:00:00Z".into(),
    };
    CollectionRun {
        id: id.into(),
        acquisition_transcript_ids: vec![],
        collector: Producer {
            name: "fixture".into(),
            version: "1".into(),
            collector: "fixture".into(),
        },
        endpoint: "fixture".into(),
        subject: Subject {
            kind: "repository".into(),
            id: "github:cyberwitchery/example".into(),
            qualifiers: BTreeMap::from([("branch".into(), serde_json::json!("main"))]),
        },
        requested_scope: CollectionScope {
            proposition,
            branch: Some("main".into()),
            interval: interval.clone(),
        },
        observed_scope: Some(CollectionScope {
            proposition,
            branch: Some("main".into()),
            interval,
        }),
        enumeration: Enumeration {
            items_fetched: 0,
            items_reported: Some(0),
            pages_fetched: 1,
            terminal_page_reached: true,
            next_token_present: false,
        },
        outcome: CollectionOutcome::Complete,
        limitations: vec![],
        authority: vec![proposition],
        observation_ids: vec![],
        started_at: "2026-09-09T00:00:00Z".into(),
        completed_at: "2026-09-09T00:00:01Z".into(),
    }
}

fn pack_target() -> divinate::assertions::EvaluationTarget {
    divinate::assertions::EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: Some("v1".into()),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-09T00:00:00Z".into(),
    }
}

fn pack_assertion(
    target: &divinate::assertions::EvaluationTarget,
    coverage: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "assertion_type": "all_mutations_checked",
        "claim": "all repository mutations were checked",
        "subject": {
            "repository": target.repository,
            "branch": target.branch,
            "from": target.from,
            "until": target.until
        },
        "outcome": "supported",
        "evaluated_at": "2026-09-09T00:01:00Z",
        "validity": {"basis": "point_in_time", "at": "2026-09-09T00:01:00Z"},
        "support": [], "contradictions": [], "considered": [], "missing": [],
        "identity_joins": [], "reasoning": [], "limitations": [], "coverage": coverage
    })
}

fn assertion_pack(path: &Path, assertion: &serde_json::Value) {
    let metadata = serde_json::json!({
        "id": "example.coverage", "version": "1", "protocol_version": 1,
        "collectors": [], "evaluators": ["check"], "evaluator_inputs": {"check": []},
        "evaluator_propositions": {"check": ["repository_mutations"]},
        "source_contracts": [], "configuration_schema": {}
    });
    let script = format!(
        "#!/usr/bin/env python3\nimport json,sys\nr=json.load(sys.stdin)\nx={} if r['operation']=='describe' else [{}]\nprint(json.dumps({{'ok':True,'result':x}},separators=(',',':')))\n",
        serde_json::to_string(&metadata).unwrap(),
        serde_json::to_string(assertion).unwrap()
    );
    executable(path, script.as_bytes());
}

fn github_ci_outcome(
    checks: &[serde_json::Value],
    statuses: &[serde_json::Value],
    checks_complete: bool,
    statuses_complete: bool,
) -> String {
    github_ci_assertion(checks, statuses, checks_complete, statuses_complete)["outcome"]
        .as_str()
        .unwrap()
        .into()
}

fn github_ci_assertion(
    checks: &[serde_json::Value],
    statuses: &[serde_json::Value],
    checks_complete: bool,
    statuses_complete: bool,
) -> serde_json::Value {
    let response = github_pack_result(&github_ci_request(
        checks,
        statuses,
        checks_complete,
        statuses_complete,
    ));
    response["result"][0].clone()
}

fn github_ci_request(
    checks: &[serde_json::Value],
    statuses: &[serde_json::Value],
    checks_complete: bool,
    statuses_complete: bool,
) -> serde_json::Value {
    fn run(id: &str, complete: bool) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "outcome": if complete { "complete" } else { "partial" },
            "authority": if complete { serde_json::json!(["revision_checks"]) } else { serde_json::json!([]) },
            "enumeration": {
                "terminal_page_reached": complete,
                "next_token_present": !complete
            }
        })
    }
    fn observation(
        id: &str,
        claim_key: &str,
        run: &str,
        data: &serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "claim_key": claim_key,
            "collection_run_id": run,
            "observed_at": "2026-09-12T00:00:00Z",
            "subject": {
                "id": "github:cyberwitchery/divinate",
                "branch": "main",
                "revision": "abc123"
            },
            "data": data,
            "provenance": {"source_id": format!("src_{id}")}
        })
    }
    serde_json::json!({
        "protocol_version": 1,
        "operation": "evaluate",
        "configuration": null,
        "input": {
            "evaluator": "current-revision-checks",
            "target": {
                "repository": "github:cyberwitchery/divinate",
                "branch": "main",
                "release": null,
                "from": "2026-09-11T00:00:00Z",
                "until": "2026-09-12T00:00:00Z"
            },
            "evaluated_at": "2026-09-12T00:00:00Z",
            "coverage": [{"outcome": "complete"}],
            "corpus": {
                "collections": [
                    run("run_checks", checks_complete),
                    run("run_statuses", statuses_complete)
                ],
                "observations": [
                    observation(
                        "checks",
                        "github:check-runs",
                        "run_checks",
                        &serde_json::json!({"revision": "abc123", "checks": checks})
                    ),
                    observation(
                        "statuses",
                        "github:commit-statuses",
                        "run_statuses",
                        &serde_json::json!({"revision": "abc123", "statuses": statuses})
                    )
                ]
            }
        }
    })
}

fn github_pack_result(request: &serde_json::Value) -> serde_json::Value {
    pack_result("packs/github/divinate-pack-github", request)
}

fn azure_pack_result(request: &serde_json::Value) -> serde_json::Value {
    pack_result("packs/azure-devops/divinate-pack-azure-devops", request)
}

fn pack_result(executable: &str, request: &serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(example(executable))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn azure_policy_evaluation(
    evaluator: &str,
    policies: &serde_json::Value,
    complete: bool,
) -> serde_json::Value {
    serde_json::json!({
        "protocol_version": 1,
        "operation": "evaluate",
        "configuration": null,
        "input": {
            "evaluator": evaluator,
            "target": {
                "repository": "azure-devops:example-org/example-project/example-repository",
                "branch": "develop",
                "release": null,
                "from": "2026-09-11T00:00:00Z",
                "until": "2026-09-12T00:00:00Z"
            },
            "evaluated_at": "2026-09-12T00:00:00Z",
            "coverage": [{"outcome": if complete { "complete" } else { "incomplete" }}],
            "corpus": {
                "collections": [{
                    "id": "run_policy",
                    "outcome": if complete { "complete" } else { "partial" },
                    "authority": if complete { serde_json::json!(["branch_configuration"]) } else { serde_json::json!([]) },
                    "enumeration": {
                        "terminal_page_reached": complete,
                        "next_token_present": !complete
                    }
                }],
                "observations": [{
                    "id": "azure_policy",
                    "claim_key": "azure-devops:branch-policy",
                    "collection_run_id": "run_policy",
                    "observed_at": "2026-09-12T00:00:00Z",
                    "subject": {
                        "id": "azure-devops:example-org/example-project/example-repository",
                        "branch": "develop",
                        "revision": "abc123"
                    },
                    "data": {"branch": "develop", "policies": policies},
                    "provenance": {"source_id": "src_policy"}
                }]
            }
        }
    })
}

fn executable(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension("new");
    fs::write(&temporary, bytes).unwrap();
    let mut permissions = fs::metadata(&temporary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&temporary, permissions).unwrap();
    fs::rename(temporary, path).unwrap();
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn configure_project(root: &Path, config: &workflow::ProjectConfig) -> divinate::error::Result<()> {
    if !root.join(".git").exists() {
        git(root, &["init", "-q"]);
        let repository = config
            .repository
            .strip_prefix("github:")
            .unwrap_or(&config.repository);
        git(
            root,
            &[
                "remote",
                "add",
                "origin",
                &format!("git@github.com:{repository}.git"),
            ],
        );
        git(root, &["config", "user.name", "Divinate Test"]);
        git(root, &["config", "user.email", "divinate@example.invalid"]);
        git(root, &["add", "-A"]);
        git(root, &["commit", "--allow-empty", "-qm", "fixture"]);
    }
    project::store(root, &project::from_legacy(config))
}
