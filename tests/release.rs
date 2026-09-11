use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use divinate::assertions::{self, AssertionType, EvaluationTarget, Outcome};
use divinate::release::{self, ReleaseRequest};
use divinate::{parse_timestamp, provenance, workflow};

struct Fixture {
    _directory: tempfile::TempDir,
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
            _directory: directory,
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
    workflow::configure(
        state.path(),
        &workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            packs: BTreeMap::default(),
        },
    )
    .unwrap();
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
