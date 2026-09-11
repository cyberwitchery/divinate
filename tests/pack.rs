use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use divinate::assertions::{AssertionType, DerivedAssertion, Outcome};
use divinate::model::{
    CollectionOutcome, CollectionRun, CollectionScope, Corpus, Enumeration, Producer, Proposition,
    Subject, TimeRange,
};
use divinate::{pack, read_json, workflow};

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
    workflow::configure(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
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
    workflow::configure(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
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
        release: "v1".into(),
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
        ("crash", b"#!/bin/sh\nexit 7\n".as_slice(), "exited with"),
        ("malformed", b"#!/bin/sh\nprintf noise\n".as_slice(), "invalid pack"),
        ("incompatible", b"#!/bin/sh\nprintf '%s' '{\"ok\":true,\"result\":{\"id\":\"bad\",\"version\":\"1\",\"protocol_version\":2,\"collectors\":[],\"evaluators\":[],\"evaluator_inputs\":{},\"evaluator_propositions\":{},\"source_contracts\":[],\"configuration_schema\":{}}}'\n".as_slice(), "uses protocol 2"),
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
        release: "v1".into(),
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

fn executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}
