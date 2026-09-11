use std::collections::BTreeMap;
use std::path::Path;

use divinate as evidence_spike;
use evidence_spike::acquisition::{
    seal_transcript, AcquisitionTermination, ContractInvalidation, ContractRegistry,
    ContractStatus, HttpExchange, HttpRequest, HttpResponse, TranscriptContents,
    GITHUB_BRANCH_PROTECTION_CONTRACT,
};
use evidence_spike::assertions::{self, EvaluationTarget, Outcome};
use evidence_spike::execution::{self, ExecutionCapture, ExecutionRequest, NamedPath};
use evidence_spike::model::{
    CollectionOutcome, CollectionRun, CollectionScope, Enumeration, ObservationKind, Producer,
    Proposition, TimeRange,
};
use evidence_spike::provenance::{
    verify_collection_links, verify_execution_links, with_current_authority,
};
use evidence_spike::{collect, hex_digest, parse_timestamp, source_bytes};

fn linked() -> (
    evidence_spike::model::Corpus,
    evidence_spike::acquisition::AcquisitionTranscript,
) {
    let mut corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    corpus.observations.retain(|observation| {
        observation.kind != ObservationKind::ConfigurationSnapshot
            || observation.observed_at == "2026-09-03T08:00:00Z"
    });
    let observation = corpus
        .observations
        .iter_mut()
        .find(|observation| {
            observation.kind == ObservationKind::ConfigurationSnapshot
                && observation.observed_at == "2026-09-03T08:00:00Z"
        })
        .unwrap();
    observation.collection_run_id = Some("run-linked-branch".into());
    let source = corpus
        .sources
        .iter()
        .find(|source| source.id == observation.provenance.source_id)
        .unwrap();
    let interval = TimeRange {
        from: "2026-09-03T00:00:00Z".into(),
        until: "2026-09-04T00:00:00Z".into(),
    };
    let request = HttpRequest {
        method: "GET".into(),
        url: "repos/cyberwitchery/example/branches/main/protection".into(),
    };
    let transcript = seal_transcript(TranscriptContents {
        collector_contract: GITHUB_BRANCH_PROTECTION_CONTRACT.into(),
        collector_version: "0.1.0".into(),
        subject: observation.subject.clone(),
        proposition: Proposition::BranchConfiguration,
        requested_scope: interval.clone(),
        captured_at: "2026-09-03T08:00:00Z".into(),
        initial_request: request.clone(),
        exchanges: vec![HttpExchange {
            request,
            response: HttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: source.content.clone(),
                body_sha256: source.sha256.clone(),
                item_count: 1,
            },
        }],
        termination: AcquisitionTermination::Exhausted,
    })
    .unwrap();
    corpus.collections.push(CollectionRun {
        id: "run-linked-branch".into(),
        acquisition_transcript_ids: vec![transcript.id.clone()],
        collector: Producer {
            name: "github-rest-api".into(),
            version: "2022-11-28".into(),
            collector: "evidence-spike/github-branch-protection".into(),
        },
        endpoint: "GET /repos/cyberwitchery/example/branches/main/protection".into(),
        subject: observation.subject.clone(),
        requested_scope: CollectionScope {
            proposition: Proposition::BranchConfiguration,
            branch: Some("main".into()),
            interval: interval.clone(),
        },
        observed_scope: Some(CollectionScope {
            proposition: Proposition::BranchConfiguration,
            branch: Some("main".into()),
            interval,
        }),
        enumeration: Enumeration {
            items_fetched: 1,
            items_reported: Some(1),
            pages_fetched: 1,
            terminal_page_reached: true,
            next_token_present: false,
        },
        outcome: CollectionOutcome::Complete,
        limitations: vec![],
        authority: vec![Proposition::BranchConfiguration],
        observation_ids: vec![observation.id.clone()],
        started_at: "2026-09-03T08:00:00Z".into(),
        completed_at: "2026-09-03T08:00:01Z".into(),
    });
    (corpus, transcript)
}

fn target() -> EvaluationTarget {
    EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: "v1.4".into(),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
    }
}

#[test]
fn collection_resolves_verified_transcript_and_exact_source() {
    let (corpus, transcript) = linked();
    let links = verify_collection_links(
        &corpus,
        std::slice::from_ref(&transcript),
        &ContractRegistry::default(),
    )
    .unwrap();
    assert_eq!(links.len(), 1);
    assert!(links[0].currently_authoritative);
    let source = &corpus
        .sources
        .iter()
        .find(|source| links[0].source_ids.contains(&source.id))
        .unwrap();
    assert!(transcript
        .contents
        .exchanges
        .iter()
        .any(|exchange| exchange.response.body_sha256 == source.sha256));
}

#[test]
fn broken_and_tampered_transcript_links_are_detected() {
    let (mut corpus, transcript) = linked();
    corpus
        .collections
        .last_mut()
        .unwrap()
        .acquisition_transcript_ids = vec!["acq_00000000000000000000".into()];
    assert!(
        verify_collection_links(&corpus, &[transcript], &ContractRegistry::default())
            .unwrap_err()
            .to_string()
            .contains("missing acquisition")
    );

    let (corpus, mut transcript) = linked();
    transcript.contents.exchanges[0].response.body.push(' ');
    assert!(
        verify_collection_links(&corpus, &[transcript], &ContractRegistry::default())
            .unwrap_err()
            .to_string()
            .contains("failed integrity")
    );
}

#[test]
fn assertion_traverses_collection_transcript_and_source_bytes() {
    let (corpus, transcript) = linked();
    let target = EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: "v1.4".into(),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
    };
    let assertion = assertions::evaluate_configured_independent_review(
        &corpus,
        &target,
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let observation_id = &assertion.support[0].observation_id;
    let observation = corpus
        .observations
        .iter()
        .find(|item| &item.id == observation_id)
        .unwrap();
    let run = corpus
        .collections
        .iter()
        .find(|run| observation.collection_run_id.as_deref() == Some(&run.id))
        .unwrap();
    assert_eq!(run.acquisition_transcript_ids, vec![transcript.id.clone()]);
    let bytes = source_bytes(&corpus, observation_id).unwrap();
    assert_eq!(
        hex_digest(bytes),
        transcript.contents.exchanges[0].response.body_sha256
    );
}

#[test]
fn contract_invalidation_withdraws_authority_without_rewriting_history() {
    let (corpus, transcript) = linked();
    let original = transcript.clone();
    let registry = ContractRegistry {
        invalidations: vec![ContractInvalidation {
            contract: GITHUB_BRANCH_PROTECTION_CONTRACT.into(),
            discovered_at: "2026-09-06T00:00:00Z".into(),
            reason: "contract narrowed".into(),
        }],
    };
    let links =
        verify_collection_links(&corpus, std::slice::from_ref(&transcript), &registry).unwrap();
    assert!(!links[0].currently_authoritative);
    assert!(matches!(
        links[0].contract,
        ContractStatus::Invalidated { .. }
    ));
    let target = EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: "v1.4".into(),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
    };
    let historical = assertions::evaluate_configured_independent_review(
        &corpus,
        &target,
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    let current_corpus =
        with_current_authority(&corpus, std::slice::from_ref(&transcript), &registry).unwrap();
    let current = assertions::evaluate_configured_independent_review(
        &current_corpus,
        &target,
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(historical.outcome, Outcome::Supported);
    assert_eq!(current.outcome, Outcome::InsufficientEvidence);
    assert_eq!(transcript, original);
}

#[test]
fn observation_resolves_execution_and_exact_source_bytes() {
    let mut corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let observation = corpus
        .observations
        .iter_mut()
        .find(|observation| observation.kind == ObservationKind::ChangeSet)
        .unwrap();
    let source = corpus
        .sources
        .iter()
        .find(|source| source.id == observation.provenance.source_id)
        .unwrap();
    let capture = execution_for_source(&source.content);
    observation.execution_transcript_ids = vec![capture.transcript.id.clone()];
    let observation_id = observation.id.clone();

    let links = verify_execution_links(
        &corpus,
        std::slice::from_ref(&capture.transcript),
        &capture.blobs,
    )
    .unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].output, "stdout");

    let mut broken = corpus.clone();
    broken
        .observations
        .iter_mut()
        .find(|item| item.id == observation_id)
        .unwrap()
        .execution_transcript_ids = vec!["exec_00000000000000000000".into()];
    assert!(
        verify_execution_links(&broken, &[capture.transcript], &capture.blobs)
            .unwrap_err()
            .to_string()
            .contains("missing execution transcript")
    );
}

#[test]
fn release_gate_assertion_traces_to_diff_and_gate_executions() {
    let mut corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let mut captures = Vec::new();
    for observation in corpus.observations.iter_mut().filter(|observation| {
        matches!(
            observation.kind,
            ObservationKind::ChangeSet | ObservationKind::PolicyCheck
        ) && observation.subject.qualifier("release") == Some("v1.4")
    }) {
        let source = corpus
            .sources
            .iter()
            .find(|source| source.id == observation.provenance.source_id)
            .unwrap();
        let capture = execution_for_source(&source.content);
        observation.execution_transcript_ids = vec![capture.transcript.id.clone()];
        captures.push(capture);
    }
    let transcripts = captures
        .iter()
        .map(|capture| capture.transcript.clone())
        .collect::<Vec<_>>();
    let blobs = captures
        .iter()
        .flat_map(|capture| capture.blobs.clone())
        .collect::<BTreeMap<_, _>>();
    let assertion = assertions::evaluate_supply_chain(
        &corpus,
        &target(),
        parse_timestamp("2026-09-05T00:00:00Z").unwrap(),
    )
    .unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);
    assert_eq!(assertion.support.len(), 2);
    let links = verify_execution_links(&corpus, &transcripts, &blobs).unwrap();
    for evidence in &assertion.support {
        assert!(links
            .iter()
            .any(|link| link.observation_id == evidence.observation_id));
    }
}

fn execution_for_source(content: &str) -> ExecutionCapture {
    let directory = tempfile::tempdir().unwrap().keep();
    let input = directory.join("source.json");
    std::fs::write(&input, content.as_bytes()).unwrap();
    execution::capture(&ExecutionRequest {
        tool_name: "fixture-emitter".into(),
        reported_version: Some("1".into()),
        executable: "/bin/sh".into(),
        argv: vec![
            "-c".into(),
            "while IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < \"$1\"".into(),
            "fixture-emitter".into(),
            input.to_string_lossy().into_owned(),
        ],
        working_directory: None,
        environment: BTreeMap::new(),
        inputs: vec![NamedPath {
            name: "source".into(),
            path: input,
        }],
        outputs: vec![],
    })
    .unwrap()
}
