use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use divinate::assertions::{AssertionType, DerivedAssertion, Outcome};
use divinate::read_json;

fn repository() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("divinate");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.name", "Divinate Test"]);
    git(&root, &["config", "user.email", "divinate@example.invalid"]);
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:cyberwitchery/divinate.git",
        ],
    );
    let pack_directory = root.join("packs/cargo-lock");
    fs::create_dir_all(&pack_directory).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("packs/cargo-lock/divinate-pack-cargo-lock"),
        pack_directory.join("divinate-pack-cargo-lock"),
    )
    .unwrap();
    let pack = pack_directory.join("divinate-pack-cargo-lock");
    let mut permissions = fs::metadata(&pack).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&pack, permissions).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"),
        root.join("Cargo.lock"),
    )
    .unwrap();
    let configuration =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("divinate.yaml")).unwrap();
    let configuration = configuration
        .split_once("  github-branch-protection:\n")
        .map_or(configuration.as_str(), |(local, _)| local)
        .replace(
            "executable: divinate-pack-github",
            &format!("executable: {}", env!("CARGO_BIN_EXE_divinate-pack-github")),
        );
    fs::write(root.join("divinate.yaml"), configuration).unwrap();
    git(&root, &["add", "."]);
    git(&root, &["commit", "-qm", "configured clone"]);
    (directory, root)
}

#[test]
fn repository_configuration_is_a_real_collectable_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read(root.join("divinate.yaml")).unwrap();
    let configured: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&source).unwrap();
    assert_eq!(
        configured["repository"]["identity"],
        "github:cyberwitchery/divinate"
    );
    for source in [
        "cargo-lock",
        "github-branch-protection",
        "github-check-runs",
        "github-commit-statuses",
        "github-repository-mutations",
        "github-pull-request-reviews",
    ] {
        assert!(configured["sources"].get(source).is_some(), "{source}");
    }
}

#[test]
fn configured_clone_collects_statuses_and_reviews_without_init() {
    let (_directory, root) = repository();

    let first = cli(&root, &["collect"]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(String::from_utf8_lossy(&first.stdout).contains("cargo-lock"));
    let assertions: Vec<DerivedAssertion> =
        read_json(&root.join(".evidence/assertions/current.json")).unwrap();
    assert!(assertions.iter().any(|assertion| {
        assertion.assertion_type == AssertionType::External("cargo_dependency_lock_captured".into())
            && assertion.outcome == Outcome::Supported
    }));

    let status = cli(&root, &["status"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(status.contains("cargo-lock"));
    assert!(status.contains("current"));

    let second = cli(&root, &["collect"]);
    assert!(second.status.success(), "{}", stderr(&second));
    let review = cli(&root, &["review"]);
    assert!(review.status.success(), "{}", stderr(&review));
    let verify = cli(&root, &["verify"]);
    assert!(verify.status.success(), "{}", stderr(&verify));
}

fn cli(repository: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_divinate"))
        .current_dir(repository)
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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
