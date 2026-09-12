use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use divinate::project::{
    self, BuiltinProvider, PackFileConfig, PackProvider, ProjectFile, RepositoryConfig,
    SourceFileConfig, SourceFileProvider,
};
use divinate::workflow::SourceContext;

struct Repository {
    directory: tempfile::TempDir,
    path: PathBuf,
}

impl Repository {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("repository");
        fs::create_dir(&path).unwrap();
        git(&path, &["init", "-q"]);
        git(&path, &["config", "user.name", "Divinate Test"]);
        git(&path, &["config", "user.email", "divinate@example.invalid"]);
        git(
            &path,
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:cyberwitchery/example.git",
            ],
        );
        fs::write(path.join("tracked"), "one\n").unwrap();
        git(&path, &["add", "tracked"]);
        git(&path, &["commit", "-qm", "one"]);
        git(&path, &["tag", "v1"]);
        fs::write(path.join("tracked"), "two\n").unwrap();
        git(&path, &["commit", "-qam", "two"]);
        git(&path, &["tag", "v2"]);
        Self { directory, path }
    }
}

#[test]
fn init_creates_strict_minimal_yaml() {
    let repository = Repository::new();
    let state = repository.directory.path().join("state");
    let output = cli(&repository.path, &state, &["init"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let path = repository.path.join(project::PROJECT_FILE);
    let bytes = fs::read(&path).unwrap();
    let file: ProjectFile = serde_yaml_ng::from_slice(&bytes).unwrap();
    assert_eq!(file.repository.identity, "github:cyberwitchery/example");
    assert!(file.sources.is_empty());
    assert!(state.join("repository.json").is_file());
    assert!(!state.join("config.json").exists());

    let mut malformed = String::from_utf8(bytes).unwrap();
    malformed.push_str("unknown: true\n");
    fs::write(&path, malformed).unwrap();
    let error = project::load(&repository.path).unwrap_err();
    assert!(
        error.to_string().contains("unknown field `unknown`"),
        "{error}"
    );
}

#[test]
fn duplicate_source_ids_are_rejected() {
    let repository = Repository::new();
    fs::write(
        repository.path.join(project::PROJECT_FILE),
        r"repository:
  identity: github:cyberwitchery/example
  branch: main
sources:
  duplicate:
    provider:
      builtin: release-sbom
    config: {}
  duplicate:
    provider:
      builtin: release-sbom
    config: {}
",
    )
    .unwrap();
    let error = project::load(&repository.path).unwrap_err();
    assert!(error.to_string().contains("duplicate"), "{error}");
}

#[test]
fn init_migrates_legacy_live_configuration_to_yaml() {
    let repository = Repository::new();
    let state = repository.directory.path().join("state");
    divinate::workflow::init(&state).unwrap();
    divinate::write_json(
        &divinate::workflow::ProjectConfig {
            repository: "github:cyberwitchery/example".into(),
            branch: "main".into(),
            packs: BTreeMap::new(),
            sources: BTreeMap::new(),
        },
        &state.join(divinate::workflow::CONFIG_FILE),
    )
    .unwrap();
    let output = cli(&repository.path, &state, &["init"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let loaded = project::load(&repository.path).unwrap();
    assert_eq!(loaded.config.repository, "github:cyberwitchery/example");
    assert!(state.join("config.json").is_file());
    assert!(repository.path.join(project::PROJECT_FILE).is_file());
}

#[test]
#[allow(clippy::too_many_lines)]
fn committed_yaml_collects_external_pack_from_path_without_init() {
    let repository = Repository::new();
    let bin = repository.directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let executable = bin.join("divinate-pack-fixture");
    executable_file(
        &executable,
        br#"#!/usr/bin/env python3
import json,sys
r=json.load(sys.stdin); op=r["operation"]
if op=="describe":
 x={"id":"example.fixture","version":"1","protocol_version":1,"collectors":["release"],"evaluators":[],"evaluator_inputs":{},"evaluator_propositions":{},"source_contracts":[],"configuration_schema":{}}
elif op=="collect":
 c=r["input"]["context"]; rel=c["release"]
 payload=json.dumps({"release":rel["release"],"revision":rel["revision"]},separators=(",",":"))
 x={"adapter":"fixture","subject":{"kind":"release","id":c["repository"]+":"+rel["release"],"repository":c["repository"],"release":rel["release"],"revision":rel["revision"]},"observed_at":c["observed_at"],"command":{"tool_name":"printf","executable":"/usr/bin/printf","argv":["%s",payload],"inputs":{}}}
elif op=="normalize":
 p=json.loads(r["input"]["source"]["content"]); x={"claim_key":"fixture:release","data":p,"evidence_class":"observed_state","kind":"configuration_snapshot","severity":None,"status":None}
else:
 print(json.dumps({"ok":False,"error":"unsupported"})); raise SystemExit
print(json.dumps({"ok":True,"result":x},separators=(",",":")))
"#,
    );
    project::store(
        &repository.path,
        &ProjectFile {
            repository: RepositoryConfig {
                identity: "github:cyberwitchery/example".into(),
                branch: "main".into(),
            },
            packs: BTreeMap::from([(
                "example.fixture".into(),
                PackFileConfig {
                    executable: "divinate-pack-fixture".into(),
                    configuration: serde_json::json!({}),
                    timeout_seconds: 30,
                },
            )]),
            sources: BTreeMap::from([(
                "repository-release".into(),
                SourceFileConfig {
                    provider: SourceFileProvider::Pack(PackProvider {
                        pack: "example.fixture".into(),
                        collector: "release".into(),
                    }),
                    required: true,
                    context: SourceContext::Release,
                    configuration: serde_json::json!({}),
                },
            )]),
        },
    )
    .unwrap();
    let state = repository.path.join(".evidence");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let before = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .current_dir(&repository.path)
        .env("PATH", &path)
        .args(["status", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(before.status.success(), "{}", stderr(&before));
    assert!(String::from_utf8(before.stdout)
        .unwrap()
        .contains("never collected"));
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .current_dir(&repository.path)
        .env("PATH", &path)
        .args([
            "collect",
            "--release",
            "v2",
            "--base-release",
            "v1",
            "--from",
            "2026-01-01T00:00:00Z",
            "--until",
            "2030-01-01T00:00:00Z",
            "--at",
            "2030-01-01T00:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(state.join("repository.json").is_file());
    assert!(state.join("assertions/current.json").is_file());
    assert_eq!(
        divinate::workflow::load_collection_cycles(&state)
            .unwrap()
            .len(),
        1
    );
    let after = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .current_dir(&repository.path)
        .env("PATH", &path)
        .args(["status", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(after.status.success(), "{}", stderr(&after));
    assert!(String::from_utf8(after.stdout).unwrap().contains("current"));
    assert!(cli(&repository.path, &state, &["verify"]).status.success());

    let cycle = divinate::workflow::load_collection_cycles(&state)
        .unwrap()
        .pop()
        .unwrap();
    let snapshot = state
        .join("project-configs")
        .join(format!("{}.yaml", cycle.contents.project_config_sha256));
    fs::write(snapshot, "altered: true\n").unwrap();
    let verified = cli(&repository.path, &state, &["verify"]);
    assert!(!verified.status.success());
    assert!(stderr(&verified).contains("configuration digest mismatch"));
}

#[test]
fn pack_identity_mismatch_is_rejected_from_yaml() {
    let repository = Repository::new();
    let executable = repository.path.join("pack");
    executable_file(
        &executable,
        b"#!/bin/sh\nprintf '%s' '{\"ok\":true,\"result\":{\"id\":\"actual\",\"version\":\"1\",\"protocol_version\":1,\"collectors\":[\"one\"],\"evaluators\":[],\"evaluator_inputs\":{},\"evaluator_propositions\":{},\"source_contracts\":[],\"configuration_schema\":{}}}'\n",
    );
    project::store(
        &repository.path,
        &ProjectFile {
            repository: RepositoryConfig {
                identity: "github:cyberwitchery/example".into(),
                branch: "main".into(),
            },
            packs: BTreeMap::from([(
                "expected".into(),
                PackFileConfig {
                    executable,
                    configuration: serde_json::json!({}),
                    timeout_seconds: 30,
                },
            )]),
            sources: BTreeMap::from([(
                "one".into(),
                SourceFileConfig {
                    provider: SourceFileProvider::Pack(PackProvider {
                        pack: "expected".into(),
                        collector: "one".into(),
                    }),
                    required: true,
                    context: SourceContext::Repository,
                    configuration: serde_json::json!({}),
                },
            )]),
        },
    )
    .unwrap();
    let state = repository.directory.path().join("state");
    let output = cli(
        &repository.path,
        &state,
        &["collect", "--from", "2026-01-01T00:00:00Z"],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("identifies itself as \"actual\""));
}

#[test]
fn invalid_builtin_configuration_names_its_yaml_path() {
    let repository = Repository::new();
    project::store(
        &repository.path,
        &ProjectFile {
            repository: RepositoryConfig {
                identity: "github:cyberwitchery/example".into(),
                branch: "main".into(),
            },
            packs: BTreeMap::new(),
            sources: BTreeMap::from([(
                "release-sbom".into(),
                SourceFileConfig {
                    provider: SourceFileProvider::Builtin(BuiltinProvider {
                        builtin: "release-sbom".into(),
                    }),
                    required: true,
                    context: SourceContext::Release,
                    configuration: serde_json::json!({"executable": "/usr/bin/true"}),
                },
            )]),
        },
    )
    .unwrap();
    let error = project::load(&repository.path).unwrap_err();
    assert!(error.to_string().contains("sources.release-sbom.config"));
    assert!(error.to_string().contains("sbom_path"));
}

fn cli(repository: &Path, state: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_divinate"))
        .current_dir(repository)
        .args(args)
        .args(["--state", state.to_str().unwrap()])
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn executable_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
}
