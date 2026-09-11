use std::collections::BTreeMap;

use divinate as evidence_spike;
use evidence_spike::acquisition::{
    assess, compare, seal_transcript, AcquisitionTermination, ContractInvalidation,
    ContractRegistry, ContractStatus, EnumerationStatus, HttpExchange, HttpRequest, HttpResponse,
    IntegrityStatus, RerunOutcome, TranscriptContents, GITHUB_COMMITS_CONTRACT,
};
use evidence_spike::hex_digest;
use evidence_spike::model::{Proposition, Subject, TimeRange};

fn response(url: &str, body: &str, next: Option<&str>) -> HttpExchange {
    let headers = next.map_or_else(BTreeMap::new, |next| {
        BTreeMap::from([(
            "link".into(),
            format!("<{next}>; rel=\"next\", <{next}>; rel=\"last\""),
        )])
    });
    HttpExchange {
        request: HttpRequest {
            method: "GET".into(),
            url: url.into(),
        },
        response: HttpResponse {
            status: 200,
            headers,
            body: body.into(),
            body_sha256: hex_digest(body.as_bytes()),
            item_count: serde_json::from_str::<serde_json::Value>(body)
                .unwrap()
                .as_array()
                .map_or(0, |items| u64::try_from(items.len()).unwrap()),
        },
    }
}

fn contents(
    exchanges: Vec<HttpExchange>,
    termination: AcquisitionTermination,
) -> TranscriptContents {
    TranscriptContents {
        collector_contract: GITHUB_COMMITS_CONTRACT.into(),
        collector_version: "0.1.0".into(),
        subject: Subject {
            kind: "repository".into(),
            id: "github:cyberwitchery/sbom-diff".into(),
            qualifiers: BTreeMap::from([("branch".into(), serde_json::json!("main"))]),
        },
        proposition: Proposition::CommitAncestry,
        requested_scope: TimeRange {
            from: "2026-08-01T00:00:00Z".into(),
            until: "2026-09-01T00:00:00Z".into(),
        },
        captured_at: "2026-09-01T01:00:00Z".into(),
        initial_request: HttpRequest {
            method: "GET".into(),
            url: "page-1".into(),
        },
        exchanges,
        termination,
    }
}

#[test]
fn terminal_link_chain_replays_as_complete_authoritative_coverage() {
    let transcript = seal_transcript(contents(
        vec![
            response("page-1", "[{\"sha\":\"one\"}]", Some("page-2")),
            response("page-2", "[{\"sha\":\"two\"}]", None),
        ],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.integrity, IntegrityStatus::Verified);
    assert_eq!(assessment.contract, ContractStatus::Accepted);
    assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
    assert_eq!(assessment.authority, vec![Proposition::CommitAncestry]);
    assert_eq!(assessment.items, 2);
}

#[test]
fn truncated_transcript_does_not_turn_returned_records_into_complete_coverage() {
    let transcript = seal_transcript(contents(
        vec![response("page-1", "[{\"sha\":\"one\"}]", Some("page-2"))],
        AcquisitionTermination::Truncated {
            next_url: "page-2".into(),
        },
    ))
    .unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.enumeration, EnumerationStatus::Truncated);
    assert!(assessment.authority.is_empty());
    assert!(assessment.reasons[0].contains("next page"));
}

#[test]
fn permission_change_is_preserved_as_a_failed_acquisition_attempt() {
    let transcript = seal_transcript(contents(
        vec![],
        AcquisitionTermination::PermissionDenied {
            diagnostic: "HTTP 403: resource not accessible by integration".into(),
        },
    ))
    .unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.integrity, IntegrityStatus::Verified);
    assert_eq!(assessment.enumeration, EnumerationStatus::PermissionDenied);
    assert!(assessment.authority.is_empty());
}

#[test]
fn response_tampering_is_detected_offline() {
    let mut transcript = seal_transcript(contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    transcript.contents.exchanges[0].response.body = "[{\"sha\":\"injected\"}]".into();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.integrity, IntegrityStatus::Failed);
    assert!(assessment.authority.is_empty());
}

#[test]
fn unsupported_transcript_schema_is_rejected() {
    let mut transcript = seal_transcript(contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    transcript.schema_version = "9.0.0".into();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.integrity, IntegrityStatus::Failed);
    assert!(assessment.authority.is_empty());
}

#[test]
fn declared_item_count_is_checked_against_the_preserved_body() {
    let mut source = contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    );
    source.exchanges[0].response.item_count = 10;
    let transcript = seal_transcript(source).unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.integrity, IntegrityStatus::Failed);
    assert!(assessment
        .reasons
        .iter()
        .any(|reason| reason.contains("count")));
}

#[test]
fn broken_page_chain_is_not_complete() {
    let transcript = seal_transcript(contents(
        vec![
            response("page-1", "[]", Some("page-2")),
            response("page-3", "[]", None),
        ],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.enumeration, EnumerationStatus::Failed);
    assert!(assessment
        .reasons
        .iter()
        .any(|reason| reason.contains("link")));
}

#[test]
fn later_contract_invalidation_changes_the_assessment_without_rewriting_the_transcript() {
    let transcript = seal_transcript(contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let original = transcript.clone();
    let registry = ContractRegistry {
        invalidations: vec![ContractInvalidation {
            contract: GITHUB_COMMITS_CONTRACT.into(),
            discovered_at: "2026-09-03T00:00:00Z".into(),
            reason: "deleted commits can disappear from this enumeration".into(),
        }],
    };
    let assessment = assess(&transcript, &registry);
    assert!(matches!(
        assessment.contract,
        ContractStatus::Invalidated { .. }
    ));
    assert!(assessment.authority.is_empty());
    assert_eq!(transcript, original);
}

#[test]
fn unknown_contract_version_cannot_reuse_an_old_authority_decision() {
    let mut source = contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    );
    source.collector_contract = "github-commits/v2".into();
    let transcript = seal_transcript(source).unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert_eq!(assessment.contract, ContractStatus::Unsupported);
    assert!(assessment.authority.is_empty());
}

#[test]
fn commit_enumeration_is_not_authoritative_for_repository_mutations() {
    let transcript = seal_transcript(contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let assessment = assess(&transcript, &ContractRegistry::default());
    assert!(assessment.authority.contains(&Proposition::CommitAncestry));
    assert!(!assessment
        .authority
        .contains(&Proposition::RepositoryMutations));
}

#[test]
fn fixed_scope_reruns_expose_disappearing_source_records() {
    let left = seal_transcript(contents(
        vec![response(
            "page-1",
            "[{\"sha\":\"one\"},{\"sha\":\"two\"}]",
            None,
        )],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let right = seal_transcript(contents(
        vec![response("page-1", "[{\"sha\":\"two\"}]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let comparison = compare(&left, &right);
    assert_eq!(comparison.outcome, RerunOutcome::ContentChanged);
    assert_eq!(comparison.removed_identities, vec!["one"]);
    assert!(comparison.added_identities.is_empty());
}

#[test]
fn different_scopes_are_not_misclassified_as_inconsistent_reruns() {
    let left = seal_transcript(contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    ))
    .unwrap();
    let mut different = contents(
        vec![response("page-1", "[]", None)],
        AcquisitionTermination::Exhausted,
    );
    different.requested_scope.until = "2026-09-02T00:00:00Z".into();
    let right = seal_transcript(different).unwrap();
    assert_eq!(compare(&left, &right).outcome, RerunOutcome::NotComparable);
}
