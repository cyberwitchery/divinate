use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use divinate::assertions::{self, AssertionType, EvaluationTarget, Outcome};
use divinate::release::{self, ReleaseRequest};
use divinate::{parse_timestamp, project, provenance, workflow};

struct Fixture {
    directory: tempfile::TempDir,
    repository: PathBuf,
    base_sbom: PathBuf,
    target_sbom: PathBuf,
    executable: PathBuf,
    base_revision: String,
}

impl Fixture {
    fn new(gate_output_mismatch: bool) -> Self {
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
        let tracked = repository.join("tracked");
        fs::write(&tracked, "one\n").unwrap();
        git(&repository, &["add", "tracked"]);
        git(&repository, &["commit", "-qm", "one"]);
        git(&repository, &["tag", "v1.0.0"]);
        let base_revision = revision(&repository, "v1.0.0");
        fs::write(&tracked, "two\n").unwrap();
        git(&repository, &["commit", "-qam", "two"]);
        git(&repository, &["tag", "v1.1.0"]);
        let _revision = revision(&repository, "v1.1.0");

        let base_sbom = directory.path().join("base.cdx.json");
        let target_sbom = directory.path().join("target.cdx.json");
        sbom(&base_sbom, "1.0.0");
        sbom(&target_sbom, "1.1.0");
        let executable = directory.path().join("sbom-diff");
        let script = if gate_output_mismatch {
            "#!/bin/sh\ncase \" $* \" in *\" --fail-on \"*) printf '%s\\n' '{\"added\":[{\"name\":\"different\"}],\"removed\":[],\"changed\":[],\"edge_diffs\":[],\"metadata_changed\":null,\"old_total\":1,\"new_total\":2,\"unchanged\":1}' ;; *) printf '%s\\n' '{\"added\":[],\"removed\":[],\"changed\":[],\"edge_diffs\":[],\"metadata_changed\":null,\"old_total\":1,\"new_total\":1,\"unchanged\":1}' ;; esac\n"
        } else {
            "#!/bin/sh\nprintf '%s\\n' '{\"added\":[],\"removed\":[],\"changed\":[],\"edge_diffs\":[],\"metadata_changed\":null,\"old_total\":1,\"new_total\":1,\"unchanged\":1}'\n"
        };
        fs::write(&executable, script).unwrap();
        let mut permissions = fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).unwrap();
        Self {
            directory,
            repository,
            base_sbom,
            target_sbom,
            executable,
            base_revision,
        }
    }

    fn request(&self) -> ReleaseRequest {
        ReleaseRequest {
            repository: "github:cyberwitchery/example".into(),
            repository_path: self.repository.clone(),
            base_release: "v1.0.0".into(),
            release: "v1.1.0".into(),
            expected_base_revision: None,
            expected_revision: None,
            base_sbom: self.base_sbom.clone(),
            target_sbom: self.target_sbom.clone(),
            executable: self.executable.clone(),
            reported_version: Some("test".into()),
            policy_id: "supply-chain/default".into(),
            fail_on: "added-components".into(),
            force: false,
        }
    }
}

#[test]
fn baseline_release_generates_observations_and_complete_local_provenance() {
    let fixture = Fixture::new(false);
    let capture = release::collect(&fixture.request(), &[], &BTreeMap::default()).unwrap();
    assert_eq!(capture.executions.len(), 2);
    assert_eq!(capture.corpus.observations.len(), 2);
    assert!(capture
        .corpus
        .observations
        .iter()
        .all(|item| item.execution_transcript_ids.len() == 1));

    let manifest_directory = tempfile::tempdir().unwrap();
    let entries = capture
        .corpus
        .observations
        .iter()
        .zip(&capture.corpus.sources)
        .enumerate()
        .map(|(index, (observation, source))| {
            let path = format!("source-{index}.json");
            fs::write(
                manifest_directory.path().join(&path),
                source.content.as_bytes(),
            )
            .unwrap();
            serde_json::json!({
                "adapter": source.format,
                "collection_run": null,
                "execution_transcripts": observation.execution_transcript_ids,
                "path": path,
                "observed_at": observation.observed_at,
                "producer": observation.producer,
                "subject": observation.subject,
            })
        })
        .collect::<Vec<_>>();
    let manifest_path = manifest_directory.path().join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&serde_json::json!({"sources": entries})).unwrap(),
    )
    .unwrap();
    let lower_level = divinate::collect(&manifest_path).unwrap();
    for generated in &capture.corpus.observations {
        let lower = lower_level
            .observations
            .iter()
            .find(|item| item.claim_key == generated.claim_key)
            .unwrap();
        assert_eq!(lower.id, generated.id);
        assert_eq!(lower.claim_key, generated.claim_key);
        assert_eq!(lower.kind, generated.kind);
        assert_eq!(lower.data, generated.data);
        assert_eq!(lower.status, generated.status);
        assert_eq!(lower.subject, generated.subject);
        assert_eq!(
            lower.execution_transcript_ids,
            generated.execution_transcript_ids
        );
        assert_eq!(lower.provenance.source_id, generated.provenance.source_id);
    }

    let state = tempfile::tempdir().unwrap();
    workflow::accumulate_with_executions(state.path(), &capture.corpus, &[], &capture.executions)
        .unwrap();
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    let executions = workflow::load_executions(state.path()).unwrap();
    let blobs = workflow::load_blobs(state.path()).unwrap();
    provenance::verify_execution_links(&corpus, &executions, &blobs).unwrap();

    let assertions = assertions::evaluate_all(
        &corpus,
        &target(),
        parse_timestamp("2030-01-01T00:00:00Z").unwrap(),
    )
    .unwrap();
    let gate = assertions
        .iter()
        .find(|item| item.assertion_type == AssertionType::ReleaseSupplyChainPolicy)
        .unwrap();
    assert_eq!(gate.outcome, Outcome::Supported);
    assert_eq!(gate.support.len(), 2);
    assert!(gate.support.iter().all(|support| {
        corpus
            .observations
            .iter()
            .find(|item| item.id == support.observation_id)
            .is_some_and(|item| item.execution_transcript_ids.len() == 1)
    }));
}

#[test]
fn release_binding_refuses_revision_sbom_policy_and_gate_mismatches() {
    let fixture = Fixture::new(false);
    let mut request = fixture.request();
    request.expected_revision = Some(fixture.base_revision.clone());
    assert_error(&request, "not expected revision");

    request = fixture.request();
    sbom(&fixture.target_sbom, "9.9.9");
    assert_error(&request, "not release");

    sbom(&fixture.target_sbom, "1.1.0");
    request.fail_on = "missing-hashes".into();
    assert_error(&request, "requires --fail-on added-components");

    let mismatched = Fixture::new(true);
    assert_error(&mismatched.request(), "gate output does not match");
}

#[test]
fn repeated_release_reuses_content_and_changed_release_appends() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let first = release::collect(&fixture.request(), &[], &BTreeMap::default()).unwrap();
    let first_ids = first.result.observation_ids.clone();
    workflow::accumulate_with_executions(state.path(), &first.corpus, &[], &first.executions)
        .unwrap();
    let executions = workflow::load_executions(state.path()).unwrap();
    let blobs = workflow::load_blobs(state.path()).unwrap();
    let second = release::collect(&fixture.request(), &executions, &blobs).unwrap();
    assert_eq!(second.result.reused_executions.len(), 2);
    assert_eq!(second.result.observation_ids, first_ids);
    let merged =
        workflow::accumulate_with_executions(state.path(), &second.corpus, &[], &second.executions)
            .unwrap();
    assert_eq!(merged.observations.len(), 2);
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 2);

    let tracked = fixture.repository.join("tracked");
    fs::write(&tracked, "three\n").unwrap();
    git(&fixture.repository, &["commit", "-qam", "three"]);
    git(&fixture.repository, &["tag", "v1.2.0"]);
    let next_sbom = fixture.repository.join("next.cdx.json");
    sbom(&next_sbom, "1.2.0");
    let mut next = fixture.request();
    next.base_release = "v1.1.0".into();
    next.release = "v1.2.0".into();
    next.base_sbom = fixture.target_sbom.clone();
    next.target_sbom = next_sbom;
    let third = release::collect(
        &next,
        &workflow::load_executions(state.path()).unwrap(),
        &workflow::load_blobs(state.path()).unwrap(),
    )
    .unwrap();
    let merged =
        workflow::accumulate_with_executions(state.path(), &third.corpus, &[], &third.executions)
            .unwrap();
    assert_eq!(merged.observations.len(), 4);
    assert!(first_ids
        .iter()
        .all(|id| merged.observations.iter().any(|item| &item.id == id)));
}

#[test]
fn high_level_cli_collects_without_a_manifest() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["collect", "release", "--state"])
        .arg(state.path())
        .arg("--repository-path")
        .arg(&fixture.repository)
        .args(["--base-release", "v1.0.0", "--release", "v1.1.0"])
        .arg("--base-sbom")
        .arg(&fixture.base_sbom)
        .arg("--target-sbom")
        .arg(&fixture.target_sbom)
        .arg("--sbom-diff")
        .arg(&fixture.executable)
        .args(["--tool-version", "test"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.path().join("evidence-manifest.json").exists());
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 2);
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn configured_collect_infers_release_inputs_evaluates_and_deduplicates() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let sbom_template = fixture
        .directory
        .path()
        .join("{release}.cdx.json")
        .to_string_lossy()
        .into_owned();
    fs::copy(
        &fixture.base_sbom,
        fixture.directory.path().join("v1.0.0.cdx.json"),
    )
    .unwrap();
    fs::copy(
        &fixture.target_sbom,
        fixture.directory.path().join("v1.1.0.cdx.json"),
    )
    .unwrap();
    configure_release(&fixture, state.path(), &sbom_template);

    let first = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(first.status.success(), "{}", stderr(&first));
    let stdout = String::from_utf8(first.stdout).unwrap();
    assert!(stdout.contains("Collected"));
    assert!(stdout.contains("Evaluation"));
    assert!(!stdout.contains("exec_"));
    assert!(!stdout.contains("ev_"));
    assert!(state.path().join("assertions/current.json").is_file());
    assert!(state.path().join("dossiers/current.md").is_file());

    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 2);
    assert!(corpus.observations.iter().all(|item| {
        item.subject.qualifier("revision") == Some(revision(&fixture.repository, "v1.1.0").as_str())
            || item.subject.qualifier("revision")
                == Some(revision(&fixture.repository, "v1.0.0").as_str())
    }));

    let second = product_collect(&fixture, state.path(), "2030-01-02T00:00:00Z");
    assert!(second.status.success(), "{}", stderr(&second));
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 2);
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 2);
    assert!(state.path().join("assertions/previous.json").is_file());

    let current: Vec<divinate::assertions::DerivedAssertion> =
        divinate::read_json(&state.path().join("assertions/current.json")).unwrap();
    let configured_branch = project::load(&fixture.repository).unwrap().config.branch;
    assert!(current
        .iter()
        .filter_map(|assertion| assertion.subject.branch.as_deref())
        .all(|branch| branch == configured_branch));

    let mut explicit_request = fixture.request();
    explicit_request.reported_version = None;
    let explicit = release::collect(&explicit_request, &[], &BTreeMap::default()).unwrap();
    let explicit_assertions = assertions::evaluate_all(
        &explicit.corpus,
        &EvaluationTarget {
            repository: "github:cyberwitchery/example".into(),
            branch: configured_branch.clone(),
            release: "v1.1.0".into(),
            from: "2030-01-01T00:00:00Z".into(),
            until: "2030-01-02T00:00:00Z".into(),
        },
        parse_timestamp("2030-01-02T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(
        assertion_semantics(&explicit_assertions),
        assertion_semantics(&current)
    );

    let reproduced = cli_output(&[
        "evaluate",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
        "--label",
        "reproduced",
        "--repository",
        "github:cyberwitchery/example",
        "--branch",
        &configured_branch,
        "--release",
        "v1.1.0",
        "--from",
        "2030-01-01T00:00:00Z",
        "--until",
        "2030-01-02T00:00:00Z",
        "--at",
        &current[0].evaluated_at,
    ]);
    assert!(reproduced.status.success(), "{}", stderr(&reproduced));
    let reproduced: Vec<divinate::assertions::DerivedAssertion> =
        divinate::read_json(&state.path().join("assertions/reproduced.json")).unwrap();
    assert_eq!(reproduced, current);

    let verified = cli_output(&["verify", "--state", state.path().to_str().unwrap()]);
    assert!(verified.status.success(), "{}", stderr(&verified));
    let supported = current
        .iter()
        .find(|assertion| !assertion.support.is_empty())
        .unwrap();
    let provenance = cli_output(&[
        "provenance",
        "--state",
        state.path().to_str().unwrap(),
        &supported.id,
    ]);
    assert!(provenance.status.success(), "{}", stderr(&provenance));
    let provenance = String::from_utf8(provenance.stdout).unwrap();
    assert!(provenance.contains("\"observation\""));
    assert!(provenance.contains("sha256"));

    let status = cli_output(&[
        "status",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
    ]);
    assert!(status.status.success(), "{}", stderr(&status));
    let status_text = String::from_utf8(status.stdout).unwrap();
    assert!(status_text.contains("github:cyberwitchery/example"));
    assert!(status_text.contains("Since previous evaluation"));
    assert!(!status_text.contains("sha256"));

    let review = cli_output(&["review", "--state", state.path().to_str().unwrap()]);
    assert!(review.status.success(), "{}", stderr(&review));
    assert!(String::from_utf8(review.stdout)
        .unwrap()
        .contains("claims changed"));
    assert!(state.path().join("views/review.md").is_file());
}

#[test]
fn configured_collect_refuses_ambiguous_previous_release_before_writing_evidence() {
    let fixture = Fixture::new(false);
    git(&fixture.repository, &["tag", "stable", "v1.0.0"]);
    let state = tempfile::tempdir().unwrap();
    configure_release(
        &fixture,
        &fixture.repository,
        fixture
            .directory
            .path()
            .join("{release}.cdx.json")
            .to_string_lossy()
            .as_ref(),
    );
    let output = cli_output(&[
        "collect",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
        "--at",
        "2030-01-01T00:00:00Z",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("choose one with --base-release"));
    assert!(!workflow::corpus_path(state.path()).exists());
}

#[test]
fn configured_collect_reports_missing_sbom_before_writing_evidence() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    configure_release(
        &fixture,
        &fixture.repository,
        fixture
            .directory
            .path()
            .join("missing-{release}.cdx.json")
            .to_string_lossy()
            .as_ref(),
    );
    let output = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("release-sbom input does not exist"));
    assert!(!workflow::corpus_path(state.path()).exists());
}

#[test]
fn configured_collect_reports_a_missing_executable_before_writing_evidence() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    configure_project(
        &fixture.repository,
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "master".into(),
            packs: BTreeMap::default(),
            sources: BTreeMap::from([(
                "release-sbom".into(),
                workflow::SourceConfig {
                    provider: workflow::SourceProvider::Builtin {
                        source: "release-sbom".into(),
                    },
                    configuration: serde_json::json!({
                        "executable": fixture.repository.join("missing-sbom-diff"),
                        "sbom_path": "dist/{release}.cdx.json"
                    }),
                    context: workflow::SourceContext::Release,
                    enabled: true,
                    required: true,
                },
            )]),
        },
    )
    .unwrap();
    let output = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("sources.release-sbom.config.executable"));
    assert!(!workflow::corpus_path(state.path()).exists());
}

#[test]
fn configured_collect_rejects_a_release_tag_moved_after_collection() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let sbom_template = fixture
        .directory
        .path()
        .join("{release}.cdx.json")
        .to_string_lossy()
        .into_owned();
    fs::copy(
        &fixture.base_sbom,
        fixture.directory.path().join("v1.0.0.cdx.json"),
    )
    .unwrap();
    fs::copy(
        &fixture.target_sbom,
        fixture.directory.path().join("v1.1.0.cdx.json"),
    )
    .unwrap();
    configure_release(&fixture, state.path(), &sbom_template);
    let first = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(first.status.success(), "{}", stderr(&first));

    fs::write(fixture.repository.join("tracked"), "moved\n").unwrap();
    git(&fixture.repository, &["commit", "-qam", "moved"]);
    git(&fixture.repository, &["tag", "-f", "v1.1.0"]);
    let output = product_collect(&fixture, state.path(), "2030-01-02T00:00:00Z");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("not expected revision"));
    let corpus = divinate::load_corpus(&workflow::corpus_path(state.path())).unwrap();
    assert_eq!(corpus.observations.len(), 2);
}

#[test]
fn normal_collect_without_any_configured_source_fails_clearly() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    configure_project(
        &fixture.repository,
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "master".into(),
            packs: BTreeMap::default(),
            sources: BTreeMap::default(),
        },
    )
    .unwrap();
    let output = cli_output(&[
        "collect",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
        "--at",
        "2030-01-01T00:00:00Z",
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("defines no evidence sources"));
    assert!(!workflow::corpus_path(state.path()).exists());
}

#[test]
fn review_without_a_saved_predecessor_requires_since() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let sbom_template = fixture
        .directory
        .path()
        .join("{release}.cdx.json")
        .to_string_lossy()
        .into_owned();
    fs::copy(
        &fixture.base_sbom,
        fixture.directory.path().join("v1.0.0.cdx.json"),
    )
    .unwrap();
    fs::copy(
        &fixture.target_sbom,
        fixture.directory.path().join("v1.1.0.cdx.json"),
    )
    .unwrap();
    configure_release(&fixture, state.path(), &sbom_template);
    let collected = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(collected.status.success(), "{}", stderr(&collected));
    let output = cli_output(&["review", "--state", state.path().to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("choose one with --since"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn declarative_source_configuration_controls_release_collection() {
    let fixture = Fixture::new(false);
    let state = tempfile::tempdir().unwrap();
    let init_help = cli_output(&["init", "--help"]);
    assert!(init_help.status.success());
    let init_help = String::from_utf8(init_help.stdout).unwrap();
    assert!(!init_help.contains("sbom"));
    let collect_help = cli_output(&["collect", "--help"]);
    assert!(collect_help.status.success());
    let collect_help = String::from_utf8(collect_help.stdout).unwrap();
    assert!(!collect_help.contains("--sbom"));
    let top_help = cli_output(&["--help"]);
    assert!(!String::from_utf8(top_help.stdout)
        .unwrap()
        .contains("source add"));

    let template = fixture
        .directory
        .path()
        .join("{release}.cdx.json")
        .to_string_lossy()
        .into_owned();
    fs::copy(
        &fixture.base_sbom,
        fixture.directory.path().join("v1.0.0.cdx.json"),
    )
    .unwrap();
    fs::copy(
        &fixture.target_sbom,
        fixture.directory.path().join("v1.1.0.cdx.json"),
    )
    .unwrap();
    configure_release(&fixture, state.path(), &template);
    let project = project::load(&fixture.repository).unwrap().config;
    let source = project.sources.get("release-sbom").unwrap();
    assert!(source.configuration.get("executable").is_some());
    assert!(source.configuration.get("sbom_path").is_some());

    let yaml = fs::read(fixture.repository.join(project::PROJECT_FILE)).unwrap();
    let mut file: project::ProjectFile = serde_yaml_ng::from_slice(&yaml).unwrap();
    let release_source = file.sources.remove("release-sbom").unwrap();
    project::store(&fixture.repository, &file).unwrap();
    let collect = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(!collect.status.success());
    assert!(stderr(&collect).contains("defines no evidence sources"));
    assert!(!workflow::corpus_path(state.path()).exists());

    file.sources.insert("release-sbom".into(), release_source);
    project::store(&fixture.repository, &file).unwrap();
    let collect = product_collect(&fixture, state.path(), "2030-01-01T00:00:00Z");
    assert!(collect.status.success(), "{}", stderr(&collect));
    assert!(!state.path().join("config.json").exists());
    let first_corpus = fs::read(workflow::corpus_path(state.path())).unwrap();
    let first_cycles = workflow::load_collection_cycles(state.path()).unwrap();
    assert_eq!(first_cycles.len(), 1);
    let first_config = first_cycles[0].contents.project_config_sha256.clone();
    assert!(state
        .path()
        .join("project-configs")
        .join(format!("{first_config}.yaml"))
        .is_file());
    let evaluation: workflow::EvaluationConfiguration =
        divinate::read_json(&state.path().join("assertions/current.configuration.json")).unwrap();
    assert_eq!(evaluation.project_config_sha256, first_config);

    let mut file: project::ProjectFile = serde_yaml_ng::from_slice(
        &fs::read(fixture.repository.join(project::PROJECT_FILE)).unwrap(),
    )
    .unwrap();
    file.sources.get_mut("release-sbom").unwrap().required = false;
    project::store(&fixture.repository, &file).unwrap();
    let status = cli_output(&[
        "status",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
    ]);
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(status.contains("release-sbom"));
    assert!(status.contains("stale"));
    assert!(status.contains("optional"));

    let collect = product_collect(&fixture, state.path(), "2030-01-02T00:00:00Z");
    assert!(collect.status.success(), "{}", stderr(&collect));
    assert_eq!(
        workflow::load_collection_cycles(state.path())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fs::read(workflow::corpus_path(state.path())).unwrap(),
        first_corpus
    );

    file.sources.remove("release-sbom");
    project::store(&fixture.repository, &file).unwrap();
    let status = cli_output(&[
        "status",
        "--state",
        state.path().to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
    ]);
    assert!(String::from_utf8(status.stdout)
        .unwrap()
        .contains("removed"));
    let verified = cli_output(&["verify", "--state", state.path().to_str().unwrap()]);
    assert!(verified.status.success(), "{}", stderr(&verified));
}

fn configure_release(fixture: &Fixture, state: &Path, sbom_path: &str) {
    let initialized = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["init", "--state"])
        .arg(state)
        .arg("--repository-path")
        .arg(&fixture.repository)
        .output()
        .unwrap();
    assert!(initialized.status.success(), "{}", stderr(&initialized));
    configure_project(
        &fixture.repository,
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: release::current_branch(&fixture.repository).unwrap(),
            packs: BTreeMap::new(),
            sources: BTreeMap::from([(
                "release-sbom".into(),
                workflow::SourceConfig {
                    provider: workflow::SourceProvider::Builtin {
                        source: "release-sbom".into(),
                    },
                    configuration: serde_json::json!({
                        "executable": fixture.executable,
                        "sbom_path": sbom_path,
                    }),
                    context: workflow::SourceContext::Release,
                    enabled: true,
                    required: true,
                },
            )]),
        },
    )
    .unwrap();
}

fn product_collect(fixture: &Fixture, state: &Path, at: &str) -> std::process::Output {
    cli_output(&[
        "collect",
        "--state",
        state.to_str().unwrap(),
        "--repository-path",
        fixture.repository.to_str().unwrap(),
        "--release",
        "v1.1.0",
        "--at",
        at,
    ])
}

fn cli_output(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assertion_semantics(assertions: &[divinate::assertions::DerivedAssertion]) -> Vec<String> {
    assertions
        .iter()
        .map(|assertion| {
            serde_json::to_string(&serde_json::json!({
                "type": assertion.assertion_type,
                "claim": assertion.claim,
                "subject": assertion.subject,
                "outcome": assertion.outcome,
                "missing": assertion.missing,
                "limitations": assertion.limitations,
            }))
            .unwrap()
        })
        .collect()
}

fn target() -> EvaluationTarget {
    EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: "v1.1.0".into(),
        from: "2026-01-01T00:00:00Z".into(),
        until: "2026-12-31T00:00:00Z".into(),
    }
}

fn assert_error(request: &ReleaseRequest, expected: &str) {
    let error = release::collect(request, &[], &BTreeMap::default()).unwrap_err();
    assert!(error.to_string().contains(expected), "{error}");
}

fn sbom(path: &Path, version: &str) {
    fs::write(
        path,
        format!(
            "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{{\"component\":{{\"name\":\"example\",\"version\":\"{version}\"}}}},\"components\":[]}}\n"
        ),
    )
    .unwrap();
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

fn revision(repository: &Path, tag: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", &format!("{tag}^{{commit}}")])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn configure_project(root: &Path, config: &workflow::ProjectConfig) -> divinate::error::Result<()> {
    project::store(root, &project::from_legacy(config))
}
