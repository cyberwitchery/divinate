use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use divinate as evidence_spike;
use evidence_spike::acquisition::{
    seal_transcript, AcquisitionTermination, HttpExchange, HttpRequest, HttpResponse,
    TranscriptContents, GITHUB_COMMITS_CONTRACT,
};
use evidence_spike::assertions::{self, AssertionType, EvaluationTarget, Outcome};
use evidence_spike::execution::{self, ExecutionRequest};
use evidence_spike::model::{Proposition, Subject, TimeRange};
use evidence_spike::views;
use evidence_spike::{collect, hex_digest, parse_timestamp, workflow};

fn corpus() -> evidence_spike::model::Corpus {
    collect(Path::new("fixtures/collection.json")).unwrap()
}

fn target() -> EvaluationTarget {
    EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: Some("v1.4".into()),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
    }
}

fn transcript() -> evidence_spike::acquisition::AcquisitionTranscript {
    let body = "[]";
    let request = HttpRequest {
        method: "GET".into(),
        url: "page-1".into(),
    };
    seal_transcript(TranscriptContents {
        collector_contract: GITHUB_COMMITS_CONTRACT.into(),
        collector_version: "0.1.0".into(),
        subject: Subject {
            kind: "repository".into(),
            id: "github:cyberwitchery/example".into(),
            qualifiers: BTreeMap::from([("branch".into(), serde_json::json!("main"))]),
        },
        proposition: Proposition::CommitAncestry,
        requested_scope: TimeRange {
            from: "2026-09-01T00:00:00Z".into(),
            until: "2026-09-05T00:00:00Z".into(),
        },
        captured_at: "2026-09-05T01:00:00Z".into(),
        initial_request: request.clone(),
        exchanges: vec![HttpExchange {
            request,
            response: HttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: body.into(),
                body_sha256: hex_digest(body.as_bytes()),
                item_count: 0,
            },
        }],
        termination: AcquisitionTermination::Exhausted,
    })
    .unwrap()
}

fn temp_state(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("evidence-spike-{name}-{}", std::process::id()))
}

#[test]
fn repeated_recording_reuses_content_addressed_objects() {
    let state = temp_state("repeat");
    if state.exists() {
        fs::remove_dir_all(&state).unwrap();
    }
    let corpus = corpus();
    let transcript = transcript();
    let first = workflow::accumulate(&state, &corpus, std::slice::from_ref(&transcript)).unwrap();
    let second = workflow::accumulate(&state, &corpus, &[transcript]).unwrap();
    assert_eq!(first, second);
    assert_eq!(workflow::load_transcripts(&state).unwrap().len(), 1);
    fs::remove_dir_all(state).unwrap();
}

#[test]
fn separate_cycle_increments_accumulate_without_rewriting_earlier_evidence() {
    let complete = corpus();
    let mut early = complete.clone();
    early
        .observations
        .retain(|observation| observation.observed_at.as_str() < "2026-09-03T00:00:00Z");
    let early_ids = early
        .observations
        .iter()
        .map(|observation| observation.id.clone())
        .collect::<Vec<_>>();
    let mut later = complete.clone();
    later
        .observations
        .retain(|observation| observation.observed_at.as_str() >= "2026-09-03T00:00:00Z");
    let merged = workflow::merge(&early, &later).unwrap();
    assert_eq!(merged.observations.len(), complete.observations.len());
    for id in early_ids {
        assert!(merged
            .observations
            .iter()
            .any(|observation| observation.id == id));
    }
}

#[test]
fn historical_view_excludes_later_observations_without_removing_them() {
    let corpus = corpus();
    let historical =
        workflow::as_of(&corpus, parse_timestamp("2026-09-02T00:00:00Z").unwrap()).unwrap();
    assert!(historical
        .observations
        .iter()
        .all(|observation| observation.observed_at.as_str() <= "2026-09-02T00:00:00Z"));
    assert!(historical.observations.len() < corpus.observations.len());
    assert!(corpus
        .observations
        .iter()
        .any(|observation| observation.observed_at.as_str() > "2026-09-02T00:00:00Z"));
}

#[test]
fn historical_graph_excludes_observations_until_their_provenance_exists() {
    let mut local = corpus();
    local.collections.clear();
    local.observations.truncate(1);
    local
        .sources
        .retain(|source| source.id == local.observations[0].provenance.source_id);
    local.observations[0].observed_at = "2026-09-08T00:00:00Z".into();
    let capture = execution::capture(&ExecutionRequest {
        tool_name: "manifest-tool".into(),
        reported_version: Some("1".into()),
        executable: "/usr/bin/printf".into(),
        argv: vec!["output".into()],
        working_directory: None,
        environment: BTreeMap::new(),
        inputs: vec![],
        outputs: vec![],
    })
    .unwrap();
    let mut contents = capture.transcript.contents;
    contents.started_at = "2026-09-10T00:00:00Z".into();
    contents.completed_at = "2026-09-10T00:00:00Z".into();
    let execution = execution::seal(contents).unwrap();
    local.observations[0].execution_transcript_ids = vec![execution.id.clone()];
    let historical = workflow::as_of_with_provenance(
        &local,
        &[],
        std::slice::from_ref(&execution),
        parse_timestamp("2026-09-09T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert!(historical.corpus.observations.is_empty());
    assert!(historical.executions.is_empty());
    let available = workflow::as_of_with_provenance(
        &local,
        &[],
        std::slice::from_ref(&execution),
        parse_timestamp("2026-09-11T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(available.corpus.observations.len(), 1);
    assert_eq!(available.executions, [execution]);

    let mut remote = corpus();
    remote.collections.truncate(1);
    remote.observations.truncate(1);
    remote
        .sources
        .retain(|source| source.id == remote.observations[0].provenance.source_id);
    let mut acquisition_contents = transcript().contents;
    acquisition_contents.captured_at = "2026-09-10T00:00:00Z".into();
    let acquisition = seal_transcript(acquisition_contents).unwrap();
    remote.collections[0].id = "run-late-acquisition".into();
    remote.collections[0].completed_at = "2026-09-08T00:00:00Z".into();
    remote.collections[0].acquisition_transcript_ids = vec![acquisition.id.clone()];
    remote.collections[0].observation_ids = vec![remote.observations[0].id.clone()];
    remote.observations[0].observed_at = "2026-09-08T00:00:00Z".into();
    remote.observations[0].collection_run_id = Some(remote.collections[0].id.clone());
    let historical = workflow::as_of_with_provenance(
        &remote,
        std::slice::from_ref(&acquisition),
        &[],
        parse_timestamp("2026-09-09T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert!(historical.corpus.collections.is_empty());
    assert!(historical.corpus.observations.is_empty());
    assert!(historical.acquisitions.is_empty());
    let available = workflow::as_of_with_provenance(
        &remote,
        std::slice::from_ref(&acquisition),
        &[],
        parse_timestamp("2026-09-11T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(available.corpus.collections.len(), 1);
    assert_eq!(available.corpus.observations.len(), 1);
    assert_eq!(available.acquisitions, [acquisition]);
}

#[test]
fn latest_release_is_inferred_only_when_unambiguous() {
    let corpus = corpus();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    assert_eq!(workflow::latest_release(&corpus, at).unwrap(), "v1.4");

    let mut ambiguous = corpus.clone();
    let mut competing = ambiguous
        .observations
        .iter()
        .filter(|item| item.subject.qualifier("release").is_some())
        .max_by_key(|item| &item.observed_at)
        .unwrap()
        .clone();
    competing.id = "competing-release".into();
    competing.subject.id = "github:cyberwitchery/example:v2.0".into();
    competing
        .subject
        .qualifiers
        .insert("release".into(), serde_json::json!("v2.0"));
    ambiguous.observations.push(competing);
    assert!(workflow::latest_release(&ambiguous, at)
        .unwrap_err()
        .to_string()
        .contains("equally recent evidence"));

    let mut absent = corpus;
    absent
        .observations
        .retain(|item| item.subject.qualifier("release").is_none());
    assert!(workflow::latest_release(&absent, at)
        .unwrap_err()
        .to_string()
        .contains("contains no release evidence"));
}

#[test]
fn structured_isms_change_detection_notices_control_and_coverage_regression() {
    let corpus = corpus();
    let previous = assertions::evaluate_all(
        &corpus,
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let mut degraded = corpus.clone();
    degraded
        .collections
        .retain(|run| run.requested_scope.proposition != Proposition::RepositoryMutations);
    let current = assertions::evaluate_all(
        &degraded,
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let update = views::isms_update(&previous, &current);
    assert!(update
        .coverage_regressions
        .iter()
        .any(|claim| claim.contains("every change")));
    assert!(update
        .new_gaps
        .iter()
        .any(|gap| gap.contains("repository_mutations")));
}

#[test]
fn recurring_gap_is_not_new_only_because_its_interval_advanced() {
    let assertions = assertions::evaluate_all(
        &corpus(),
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let mut current = assertions.clone();
    let gap = current
        .iter_mut()
        .flat_map(|assertion| assertion.missing.iter_mut())
        .next()
        .unwrap();
    gap.subject.push_str(" later interval");
    gap.reason.push_str(" later interval");
    let update = views::isms_update(&assertions, &current);
    assert!(update.new_gaps.is_empty());
}

#[test]
fn dd_view_reuses_existing_assertions_and_sources_without_acquisition() {
    let assertions = assertions::evaluate_all(
        &corpus(),
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let response = views::dd_response(&assertions);
    assert!(response.reuse.evidence_newly_acquired.is_empty());
    assert!(response.reuse.new_derivations.is_empty());
    assert_eq!(response.claims.len(), 4);
    assert!(response
        .claims
        .iter()
        .any(|claim| claim.outcome == Outcome::Supported && !claim.identity_joins.is_empty()));
}

#[test]
fn dd_view_groups_equivalent_coverage_gaps_without_merging_requirements() {
    let mut corpus = corpus();
    corpus.collections.clear();
    let assertions = assertions::evaluate_all(
        &corpus,
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let markdown = views::render_dd(&views::dd_response(&assertions));
    let interval = "uncovered intervals: 2026-09-01T00:00:00Z to 2026-09-05T00:00:00Z";
    assert_eq!(markdown.matches(interval).count(), 1);
    assert!(markdown.contains("missing coverage: pull request reviews, repository mutations"));
}

#[test]
fn pack_assertions_reach_both_views_without_conflating_subjects() {
    let mut previous = assertions::evaluate_all(
        &corpus(),
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let mut first = previous[0].clone();
    first.id = "asrt_pack_first".into();
    first.assertion_type = AssertionType::External("pack_control".into());
    first.claim = "first pack claim".into();
    let mut second = first.clone();
    second.id = "asrt_pack_second".into();
    second.claim = "second pack claim".into();
    previous.extend([first, second]);
    let mut current = previous.clone();
    let changed = current
        .iter_mut()
        .find(|assertion| assertion.id == "asrt_pack_first")
        .unwrap();
    changed.outcome = if changed.outcome == Outcome::Supported {
        Outcome::Contradicted
    } else {
        Outcome::Supported
    };

    let update = views::isms_update(&previous, &current);
    assert_eq!(
        update
            .current
            .iter()
            .filter(|assertion| matches!(assertion.assertion_type, AssertionType::External(_)))
            .count(),
        2
    );
    assert_eq!(
        update
            .changes
            .iter()
            .filter(|change| matches!(change.assertion_type, AssertionType::External(_)))
            .count(),
        1
    );
    let dd = views::dd_response(&current);
    assert_eq!(
        dd.claims
            .iter()
            .filter(|assertion| matches!(assertion.assertion_type, AssertionType::External(_)))
            .count(),
        2
    );
}

#[test]
fn repeated_source_bytes_can_arrive_through_a_different_local_path() {
    let left = corpus();
    let mut right = left.clone();
    right.sources[0].path = "a/recovered/content-addressed/source.json".into();
    let merged = workflow::merge(&left, &right).unwrap();
    assert_eq!(merged.sources.len(), left.sources.len());
    assert_eq!(merged.sources[0].path, left.sources[0].path);
}

#[test]
fn initialization_is_idempotent_but_does_not_retarget_a_repository() {
    let state = tempfile::tempdir().unwrap();
    workflow::ensure_repository_identity(state.path(), "github:cyberwitchery/example").unwrap();
    workflow::ensure_repository_identity(state.path(), "github:cyberwitchery/example").unwrap();
    assert!(
        workflow::ensure_repository_identity(state.path(), "github:cyberwitchery/other")
            .unwrap_err()
            .to_string()
            .contains("evidence state identifies repository")
    );
}
