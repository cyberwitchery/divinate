use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

use divinate as evidence_spike;
use evidence_spike::execution::{self, ExecutionRequest, NamedPath, RetainedBytes};
use evidence_spike::{hex_digest, workflow};

fn request(directory: &std::path::Path) -> ExecutionRequest {
    let input = directory.join("input");
    fs::write(&input, b"input bytes\0").unwrap();
    ExecutionRequest {
        tool_name: "test-tool".into(),
        reported_version: Some("1.0.0".into()),
        executable: "/bin/sh".into(),
        argv: vec![
            "-c".into(),
            "printf 'out\\000bytes'; printf 'err\\000bytes' >&2".into(),
        ],
        working_directory: None,
        environment: BTreeMap::new(),
        inputs: vec![NamedPath {
            name: "input".into(),
            path: input,
        }],
        outputs: vec![],
    }
}

#[test]
fn content_changes_change_identity() {
    let directory = tempfile::tempdir().unwrap();
    let capture = execution::capture(&request(directory.path())).unwrap();
    let identical = execution::seal(capture.transcript.contents.clone()).unwrap();
    assert_eq!(capture.transcript.id, identical.id);

    let mut argv = capture.transcript.contents.clone();
    argv.argv.push("changed".into());
    assert_ne!(capture.transcript.id, execution::seal(argv).unwrap().id);

    let mut executable = capture.transcript.contents.clone();
    executable.tool.executable.sha256 = "1".repeat(64);
    assert_ne!(
        capture.transcript.id,
        execution::seal(executable).unwrap().id
    );

    let mut input = capture.transcript.contents.clone();
    input.inputs[0].blob.sha256 = "2".repeat(64);
    assert_ne!(capture.transcript.id, execution::seal(input).unwrap().id);

    let mut output = capture.transcript.contents.clone();
    output.stdout = retained(b"different");
    assert_ne!(capture.transcript.id, execution::seal(output).unwrap().id);
}

#[test]
fn exact_streams_survive_and_environment_is_opt_in() {
    let directory = tempfile::tempdir().unwrap();
    std::env::set_var("EVIDENCE_SPIKE_UNSAFE_SECRET", "must-not-be-captured");
    let capture = execution::capture(&request(directory.path())).unwrap();
    std::env::remove_var("EVIDENCE_SPIKE_UNSAFE_SECRET");
    assert_eq!(
        execution::stdout_bytes(&capture.transcript).unwrap(),
        b"out\0bytes"
    );
    assert_eq!(
        execution::stderr_bytes(&capture.transcript).unwrap(),
        b"err\0bytes"
    );
    assert!(capture.transcript.contents.environment.is_empty());
    assert!(!serde_json::to_string(&capture.transcript)
        .unwrap()
        .contains("must-not-be-captured"));
}

#[test]
fn verification_detects_tampered_or_missing_blobs() {
    let directory = tempfile::tempdir().unwrap();
    let capture = execution::capture(&request(directory.path())).unwrap();
    execution::verify(&capture.transcript, &capture.blobs).unwrap();

    let mut missing = capture.blobs.clone();
    missing.remove(&capture.transcript.contents.inputs[0].blob.sha256);
    assert!(execution::verify(&capture.transcript, &missing)
        .unwrap_err()
        .to_string()
        .contains("missing execution blob"));

    let mut tampered = capture.blobs.clone();
    *tampered
        .get_mut(&capture.transcript.contents.inputs[0].blob.sha256)
        .unwrap() = b"tampered".to_vec();
    assert!(execution::verify(&capture.transcript, &tampered)
        .unwrap_err()
        .to_string()
        .contains("failed integrity"));
}

#[test]
fn immutable_store_reuses_blobs_and_detects_tampering() {
    let directory = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let capture = execution::capture(&request(directory.path())).unwrap();
    workflow::store_execution(state.path(), &capture).unwrap();
    workflow::store_execution(state.path(), &capture).unwrap();
    assert_eq!(workflow::load_executions(state.path()).unwrap().len(), 1);

    let input_digest = &capture.transcript.contents.inputs[0].blob.sha256;
    fs::write(state.path().join("blobs").join(input_digest), b"tampered").unwrap();
    assert!(workflow::load_blobs(state.path())
        .unwrap_err()
        .to_string()
        .contains("filename does not match content"));
}

#[test]
fn credential_like_argv_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = request(directory.path());
    request.argv = vec!["--token=secret".into()];
    assert!(execution::capture(&request)
        .unwrap_err()
        .to_string()
        .contains("credential-like argument"));
}

#[test]
fn declared_output_file_is_preserved_and_verified() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("result.bin");
    let mut request = request(directory.path());
    request.argv = vec![
        "-c".into(),
        "printf 'file\\000bytes' > \"$1\"".into(),
        "test-tool".into(),
        output.to_string_lossy().into_owned(),
    ];
    request.outputs = vec![NamedPath {
        name: "result".into(),
        path: output,
    }];
    let capture = execution::capture(&request).unwrap();
    let digest = &capture.transcript.contents.outputs[0].blob.sha256;
    assert_eq!(capture.blobs[digest], b"file\0bytes");
    execution::verify(&capture.transcript, &capture.blobs).unwrap();

    let mut tampered = capture.blobs.clone();
    *tampered.get_mut(digest).unwrap() = b"different".to_vec();
    assert!(execution::verify(&capture.transcript, &tampered)
        .unwrap_err()
        .to_string()
        .contains("failed integrity"));
}

#[test]
fn projectless_runs_verify_without_a_corpus_or_repository_identity() {
    let state = tempfile::tempdir().unwrap();
    for value in ["one", "two"] {
        let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
            .args(["run", "--state"])
            .arg(state.path())
            .args(["--tool", "printf", "/usr/bin/printf", "--", value])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let verified = verify_cli(state.path());
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["status"], "verified");
    assert_eq!(report["corpus"], "absent");
    assert_eq!(report["execution_transcripts"], 2);
    assert!(!state.path().join("corpus.json").exists());
    assert!(!state.path().join("repository.json").exists());
}

#[test]
fn projectless_verification_rejects_tampered_streams_and_missing_blobs() {
    let state = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["run", "--state"])
        .arg(state.path())
        .args(["--tool", "printf", "/usr/bin/printf", "--", "evidence"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let transcript = workflow::load_executions(state.path())
        .unwrap()
        .pop()
        .unwrap();
    let transcript_path = state
        .path()
        .join("executions")
        .join(format!("{}.json", transcript.id));
    let original = fs::read(&transcript_path).unwrap();
    let mut tampered = transcript.clone();
    tampered.contents.stdout.content.push_str("00");
    divinate::write_json(&tampered, &transcript_path).unwrap();
    assert!(!verify_cli(state.path()).status.success());

    fs::write(&transcript_path, original).unwrap();
    let executable = &transcript.contents.tool.executable.sha256;
    fs::remove_file(state.path().join("blobs").join(executable)).unwrap();
    let verified = verify_cli(state.path());
    assert!(!verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stderr).contains("missing execution blob"));
}

#[test]
fn initialized_empty_state_verifies_and_malformed_execution_does_not() {
    let state = tempfile::tempdir().unwrap();
    workflow::init(state.path()).unwrap();
    let verified = verify_cli(state.path());
    assert!(verified.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap()["corpus"],
        "absent"
    );
    fs::write(state.path().join("executions/bad.json"), b"not json").unwrap();
    assert!(!verify_cli(state.path()).status.success());
}

fn verify_cli(state: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_divinate"))
        .args(["verify", "--state"])
        .arg(state)
        .output()
        .unwrap()
}

fn retained(bytes: &[u8]) -> RetainedBytes {
    use std::fmt::Write as _;
    let content = bytes.iter().fold(String::new(), |mut content, byte| {
        write!(content, "{byte:02x}").unwrap();
        content
    });
    RetainedBytes {
        encoding: execution::ByteEncoding::Hex,
        content,
        sha256: hex_digest(bytes),
        size: u64::try_from(bytes.len()).unwrap(),
        sanitized: false,
    }
}
