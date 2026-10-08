use std::fs;
use std::path::Path;

use divinate as evidence_spike;
use evidence_spike::assertions::{
    evaluate_adequate_security_review, evaluate_all, evaluate_configured_independent_review,
    evaluate_configured_reviews, evaluate_every_main_change_reviewed, evaluate_release_reviews,
    evaluate_supply_chain, EvaluationTarget, Outcome,
};
use evidence_spike::coverage::{assess, CoverageOutcome, CoverageRequirement, RunDisposition};
use evidence_spike::model::{
    CollectionLimitation, CollectionLimitationKind, CollectionOutcome, EvidenceClass,
    ObservationKind, Proposition, TimeRange,
};
use evidence_spike::{collect, hex_digest, parse_timestamp, source_bytes};
use serde_json::json;

const FIXTURES: &str = "fixtures";

fn corpus() -> evidence_spike::model::Corpus {
    collect(Path::new(FIXTURES).join("collection.json").as_path()).unwrap()
}

fn target() -> EvaluationTarget {
    EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: Some("v1.4".into()),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
        mirror_of: None,
    }
}

#[test]
fn repository_evaluation_does_not_invent_release_scope() {
    let mut repository = target();
    repository.release = None;
    let assertions = evaluate_all(&corpus(), &repository, latest_capture()).unwrap();
    assert!(assertions.iter().all(|assertion| {
        !matches!(
            assertion.assertion_type,
            divinate::assertions::AssertionType::ReleaseReviewOperation
                | divinate::assertions::AssertionType::ReleaseSupplyChainPolicy
                | divinate::assertions::AssertionType::AdequateHumanSecurityReview
                | divinate::assertions::AssertionType::DependencyChangeVisibility
        )
    }));
}

#[test]
fn historical_review_limitations_are_provider_neutral() {
    let corpus = corpus();
    let github = evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert!(github
        .limitations
        .iter()
        .all(|item| !item.to_ascii_lowercase().contains("github")));
    assert!(github
        .limitations
        .iter()
        .any(|item| item.contains("stale-review or vote-reset")));

    let mut azure = target();
    azure.repository = "azure-devops:example-org/example-project/example-repository".into();
    azure.branch = "develop".into();
    azure.release = None;
    let assertions = evaluate_all(&corpus, &azure, latest_capture()).unwrap();
    assert_eq!(assertions.len(), 1);
    assert_eq!(
        assertions[0].assertion_type,
        divinate::assertions::AssertionType::EveryMainChangeReviewed
    );
    assert_eq!(assertions[0].outcome, Outcome::InsufficientEvidence);
    assert!(assertions[0]
        .limitations
        .iter()
        .all(|item| !item.to_ascii_lowercase().contains("github")));
}

fn at(value: &str) -> time::OffsetDateTime {
    parse_timestamp(value).unwrap()
}

fn latest_capture() -> time::OffsetDateTime {
    let corpus = corpus();
    corpus
        .collections
        .iter()
        .map(|run| at(&run.completed_at))
        .chain(corpus.observations.iter().map(|item| at(&item.observed_at)))
        .max()
        .unwrap()
}

fn requirement(proposition: Proposition) -> CoverageRequirement {
    CoverageRequirement {
        proposition,
        repository: "github:cyberwitchery/example".into(),
        branch: Some("main".into()),
        interval: TimeRange {
            from: "2026-09-01T00:00:00Z".into(),
            until: "2026-09-05T00:00:00Z".into(),
        },
    }
}

#[test]
fn observation_shapes_and_semantics_remain_distinct() {
    let corpus = corpus();
    let kinds = corpus
        .observations
        .iter()
        .map(|item| item.kind)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        kinds,
        std::collections::BTreeSet::from([
            ObservationKind::ChangeSet,
            ObservationKind::ConfigurationHistory,
            ObservationKind::ConfigurationSnapshot,
            ObservationKind::MutationHistory,
            ObservationKind::PolicyCheck,
            ObservationKind::ReleaseMembership,
            ObservationKind::ReviewRecord,
        ])
    );
    assert!(corpus.observations.iter().any(|item| {
        item.kind == ObservationKind::ConfigurationSnapshot
            && item.evidence_class == EvidenceClass::ConfiguredIntent
    }));
    assert!(corpus.observations.iter().any(|item| {
        item.kind == ObservationKind::ReviewRecord
            && item.evidence_class == EvidenceClass::ObservedOperation
    }));
}

#[test]
fn configured_intent_does_not_substitute_for_observed_operation() {
    let mut corpus = corpus();
    corpus
        .observations
        .retain(|item| item.kind != ObservationKind::ReviewRecord);
    let configured =
        evaluate_configured_reviews(&corpus, &target(), at("2026-09-02T00:00:00Z")).unwrap();
    let operated = evaluate_release_reviews(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(configured.outcome, Outcome::Supported);
    assert_eq!(operated.outcome, Outcome::InsufficientEvidence);
    assert_eq!(
        operated.missing[0].requirement,
        "pull_request_review_records"
    );
}

#[test]
fn historical_configuration_survives_a_later_change() {
    let corpus = corpus();
    let monday =
        evaluate_configured_reviews(&corpus, &target(), at("2026-09-02T00:00:00Z")).unwrap();
    let current = evaluate_configured_reviews(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(monday.outcome, Outcome::Supported);
    assert_eq!(current.outcome, Outcome::Contradicted);
    assert_eq!(current.considered.len(), 1);
    assert_eq!(
        corpus
            .observations
            .iter()
            .filter(|item| item.kind == ObservationKind::ConfigurationSnapshot)
            .count(),
        2
    );
}

#[test]
fn core_github_evaluators_ignore_newer_azure_branch_policy_observations() {
    let mut corpus = corpus();
    let mut azure = corpus
        .observations
        .iter()
        .find(|item| item.claim_key.starts_with("github:branch-protection:"))
        .unwrap()
        .clone();
    azure.id = "ev_azure_branch_policy".into();
    azure.claim_key = "azure-devops:branch-policy".into();
    azure.observed_at = "2026-09-04T12:00:00Z".into();
    azure.data = json!({
        "branch": "main",
        "policies": [{
            "blocking": true,
            "enabled": true,
            "minimum_approver_count": 2,
            "type_id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
        }]
    });
    corpus.observations.push(azure);

    let configured = evaluate_configured_reviews(&corpus, &target(), latest_capture()).unwrap();
    let independent =
        evaluate_configured_independent_review(&corpus, &target(), latest_capture()).unwrap();

    assert_eq!(configured.outcome, Outcome::Contradicted);
    assert_eq!(independent.outcome, Outcome::Supported);
    assert!(configured
        .considered
        .iter()
        .all(|item| item.observation_id != "ev_azure_branch_policy"));

    corpus
        .observations
        .retain(|item| !item.claim_key.starts_with("github:branch-protection"));
    let configured = evaluate_configured_reviews(&corpus, &target(), latest_capture()).unwrap();
    let independent =
        evaluate_configured_independent_review(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(configured.outcome, Outcome::InsufficientEvidence);
    assert_eq!(independent.outcome, Outcome::InsufficientEvidence);
}

#[test]
fn old_support_is_stale_when_no_newer_configuration_exists() {
    let mut corpus = corpus();
    corpus.observations.retain(|item| {
        item.kind != ObservationKind::ConfigurationSnapshot
            || item.observed_at == "2026-09-01T08:00:00Z"
    });
    let assertion =
        evaluate_configured_reviews(&corpus, &target(), at("2026-09-09T12:00:00Z")).unwrap();
    assert_eq!(assertion.outcome, Outcome::Stale);
    assert!(assertion.validity.fresh_until.is_some());
}

#[test]
fn release_reviews_use_policy_observed_for_each_merge() {
    let assertion = evaluate_release_reviews(&corpus(), &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);
    assert!(assertion
        .reasoning
        .iter()
        .any(|step| step.conclusion.contains("required 2")));
    assert!(assertion
        .reasoning
        .iter()
        .any(|step| step.conclusion.contains("required 1")));
    assert_eq!(assertion.identity_joins.len(), 3);
}

#[test]
fn snapshots_do_not_substitute_for_complete_policy_history() {
    let mut corpus = corpus();
    corpus
        .observations
        .retain(|item| item.kind != ObservationKind::ConfigurationHistory);
    let assertion = evaluate_release_reviews(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert!(assertion
        .missing
        .iter()
        .all(|item| item.requirement == "complete_branch_policy_history_at_merge"));
}

#[test]
fn cross_source_claim_joins_exact_release_revision_and_input_digest() {
    let assertion = evaluate_supply_chain(&corpus(), &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);
    assert_eq!(assertion.support.len(), 2);
    let fields = &assertion.identity_joins[0].fields;
    assert_eq!(fields["release"], "v1.4");
    assert_eq!(
        fields["revision"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        fields["sbom_diff_sha256"],
        "3ab027d146bdee7a98361dcf078a0063e6a20e25a742d3e6af8d763c5375245e"
    );
}

#[test]
fn cross_source_claim_refuses_a_mismatched_revision() {
    let mut corpus = corpus();
    let gate = corpus
        .observations
        .iter_mut()
        .find(|item| item.claim_key == "supply-chain-gate:supply-chain/default")
        .unwrap();
    gate.subject.qualifiers.insert(
        "revision".into(),
        json!("cccccccccccccccccccccccccccccccccccccccc"),
    );
    let assertion = evaluate_supply_chain(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert_eq!(assertion.considered.len(), 1);
    assert_eq!(
        assertion.missing[0].requirement,
        "matching_supply_chain_gate"
    );
}

#[test]
fn missing_gate_is_an_explicit_coverage_gap() {
    let mut corpus = corpus();
    corpus
        .observations
        .retain(|item| !item.claim_key.starts_with("supply-chain-gate:"));
    let assertion = evaluate_supply_chain(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert_eq!(
        assertion.missing[0].requirement,
        "matching_supply_chain_gate"
    );
    assert_eq!(assertion.support.len(), 1);
}

#[test]
fn newer_authoritative_gate_failure_explains_a_contradiction() {
    let corpus = collect(
        Path::new(FIXTURES)
            .join("collection-supply-contradicted.json")
            .as_path(),
    )
    .unwrap();
    let assertion = evaluate_supply_chain(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Contradicted);
    assert_eq!(assertion.contradictions.len(), 1);
    assert_eq!(assertion.considered.len(), 1);
    assert_eq!(assertion.reasoning[0].code, "matching_gate_failed");
    assert!(assertion.considered[0]
        .reason
        .contains("conflicting decision"));
}

#[test]
fn incomplete_pagination_prevents_a_universal_claim() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-reviews-complete")
        .unwrap();
    run.outcome = CollectionOutcome::Partial;
    run.enumeration.items_fetched = 100;
    run.enumeration.items_reported = Some(137);
    run.enumeration.terminal_page_reached = false;
    run.enumeration.next_token_present = true;

    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    let reviews = assertion
        .coverage
        .iter()
        .find(|decision| decision.requirement.proposition == Proposition::PullRequestReviews)
        .unwrap();
    assert_eq!(reviews.outcome, CoverageOutcome::Incomplete);
    assert_eq!(
        reviews.collection_runs[0].disposition,
        RunDisposition::PaginationIncomplete
    );
    assert!(assertion
        .reasoning
        .iter()
        .any(|step| { step.conclusion.contains("no counterexample was found") }));
}

#[test]
fn terminal_pagination_and_authoritative_scope_support_the_universal_claim() {
    let assertion =
        evaluate_every_main_change_reviewed(&corpus(), &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);
    assert!(assertion
        .coverage
        .iter()
        .all(|decision| decision.outcome == CoverageOutcome::Complete));
}

#[test]
fn historical_review_requires_explicit_revision_and_branch_joins() {
    for mismatch in ["revision", "branch", "mapping", "mutation_kind"] {
        let mut corpus = corpus();
        if mismatch == "revision" || mismatch == "branch" {
            let review = corpus
                .observations
                .iter_mut()
                .find(|item| item.kind == ObservationKind::ReviewRecord)
                .unwrap();
            if mismatch == "revision" {
                review.data["pull_requests"][0]["merge_commit_sha"] = json!("other-revision");
            } else {
                review
                    .subject
                    .qualifiers
                    .insert("branch".into(), json!("other-branch"));
            }
        } else {
            let mutation = corpus
                .observations
                .iter_mut()
                .find(|item| item.kind == ObservationKind::MutationHistory)
                .unwrap();
            if mismatch == "mapping" {
                mutation.data["events"][0]["pull_request"] = serde_json::Value::Null;
            } else {
                mutation.data["events"][0]["kind"] = json!("future-integration-kind");
            }
        }
        let assertion =
            evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
        assert_eq!(
            assertion.outcome,
            Outcome::InsufficientEvidence,
            "{mismatch}"
        );
    }
}

#[test]
fn historical_review_state_and_chronology_are_conservative() {
    for (state, timestamp, expected) in [
        ("approved", Some("2026-09-02T09:00:00Z"), Outcome::Supported),
        (
            "approved",
            Some("2026-09-02T12:00:00Z"),
            Outcome::InsufficientEvidence,
        ),
        (
            "approved",
            Some("2026-09-02T13:00:00Z"),
            Outcome::Contradicted,
        ),
        (
            "commented",
            Some("2026-09-02T09:00:00Z"),
            Outcome::Contradicted,
        ),
        (
            "changes_requested",
            Some("2026-09-02T09:00:00Z"),
            Outcome::Contradicted,
        ),
        (
            "dismissed",
            Some("2026-09-02T09:00:00Z"),
            Outcome::InsufficientEvidence,
        ),
        ("pending", None, Outcome::InsufficientEvidence),
        (
            "future-state",
            Some("2026-09-02T09:00:00Z"),
            Outcome::InsufficientEvidence,
        ),
        ("approved", None, Outcome::InsufficientEvidence),
    ] {
        let mut corpus = corpus();
        let review = corpus
            .observations
            .iter_mut()
            .find(|item| item.kind == ObservationKind::ReviewRecord)
            .unwrap();
        review.data["pull_requests"][0]["approvals"] =
            json!([{"actor":"bob","state":state,"submitted_at":timestamp}]);
        let assertion =
            evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
        assert_eq!(assertion.outcome, expected, "{state} {timestamp:?}");
    }
}

#[test]
fn complete_empty_reviews_are_a_concrete_counterexample() {
    let mut corpus = corpus();
    let review = corpus
        .observations
        .iter_mut()
        .find(|item| item.kind == ObservationKind::ReviewRecord)
        .unwrap();
    review.data["pull_requests"][0]["approvals"] = json!([]);
    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Contradicted);
}

#[test]
fn permission_denial_is_an_explicit_population_gap() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.outcome = CollectionOutcome::PermissionDenied;
    run.observed_scope = None;
    run.enumeration.terminal_page_reached = false;
    run.limitations = vec![CollectionLimitation {
        kind: CollectionLimitationKind::PermissionDenied,
        detail: "audit-log permission denied; direct pushes cannot be ruled out".into(),
    }];
    corpus
        .observations
        .retain(|item| item.collection_run_id.as_deref() != Some("run-mutations-complete"));

    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert!(assertion.missing.iter().any(|item| {
        item.reason.contains("permission denied") && item.reason.contains("direct pushes")
    }));
    assert_eq!(
        assertion.coverage[0].collection_runs[0].disposition,
        RunDisposition::PermissionDenied
    );
}

#[test]
fn retention_truncation_preserves_success_and_exposes_the_uncovered_window() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.outcome = CollectionOutcome::RetentionLimited;
    run.observed_scope.as_mut().unwrap().interval.from = "2026-09-03T00:00:00Z".into();
    run.limitations = vec![CollectionLimitation {
        kind: CollectionLimitationKind::RetentionBoundary,
        detail: "source retained events only from September 3".into(),
    }];

    let decision = assess(
        &corpus,
        requirement(Proposition::RepositoryMutations),
        latest_capture(),
    )
    .unwrap();
    assert_eq!(decision.outcome, CoverageOutcome::Incomplete);
    assert_eq!(
        decision.collection_runs[0].disposition,
        RunDisposition::RetentionLimited
    );
    assert_eq!(decision.covered_intervals[0].from, "2026-09-03T00:00:00Z");
    assert_eq!(
        decision.uncovered_intervals[0].until,
        "2026-09-03T00:00:00Z"
    );
}

#[test]
fn a_retention_limited_run_is_cut_at_its_start() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.outcome = CollectionOutcome::RetentionLimited;
    run.observed_scope.as_mut().unwrap().interval.from = "2026-09-03T00:00:00Z".into();
    run.limitations = vec![CollectionLimitation {
        kind: CollectionLimitationKind::RetentionBoundary,
        detail: "source retained events only from September 3".into(),
    }];
    run.started_at = "2026-09-04T10:00:00Z".into();

    let partly = assess(
        &corpus,
        requirement(Proposition::RepositoryMutations),
        latest_capture(),
    )
    .unwrap();
    let retained = TimeRange {
        from: "2026-09-03T00:00:00Z".into(),
        until: "2026-09-04T10:00:00Z".into(),
    };
    let run = &partly.collection_runs[0];
    assert_eq!(run.disposition, RunDisposition::RetentionLimited);
    assert_eq!(run.contributed_interval.as_ref(), Some(&retained));
    assert!(run.reason.contains("2026-09-04T10:00:00Z"));
    assert_eq!(partly.covered_intervals, [retained]);

    corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap()
        .started_at = "2026-09-02T00:00:00Z".into();
    let fully = assess(
        &corpus,
        requirement(Proposition::RepositoryMutations),
        latest_capture(),
    )
    .unwrap();
    assert_eq!(fully.covered_intervals, [] as [TimeRange; 0]);
    let run = &fully.collection_runs[0];
    assert_eq!(run.disposition, RunDisposition::RetentionLimited);
    assert_eq!(run.contributed_interval, None);
    assert!(run.reason.contains("2026-09-02T00:00:00Z"));
}

#[test]
fn a_run_covers_nothing_at_or_after_its_start() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.started_at = "2026-09-04T10:00:00Z".into();

    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    let mutations = assertion
        .coverage
        .iter()
        .find(|decision| decision.requirement.proposition == Proposition::RepositoryMutations)
        .unwrap();
    assert_eq!(mutations.outcome, CoverageOutcome::Incomplete);
    assert_eq!(
        mutations.uncovered_intervals,
        [TimeRange {
            from: "2026-09-04T10:00:00Z".into(),
            until: "2026-09-05T00:00:00Z".into(),
        }]
    );
    let used = &mutations.collection_runs[0];
    assert_eq!(used.disposition, RunDisposition::Used);
    assert_eq!(
        used.contributed_interval,
        Some(TimeRange {
            from: "2026-09-01T00:00:00Z".into(),
            until: "2026-09-04T10:00:00Z".into(),
        })
    );
    assert!(used.reason.contains("2026-09-04T10:00:00Z"));
}

#[test]
fn a_run_that_started_before_the_required_interval_contributes_nothing() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.requested_scope.interval.until = "2026-09-06T00:00:00Z".into();
    run.observed_scope.as_mut().unwrap().interval.until = "2026-09-06T00:00:00Z".into();
    let mut later = requirement(Proposition::RepositoryMutations);
    later.interval = TimeRange {
        from: "2026-09-05T12:00:00Z".into(),
        until: "2026-09-06T00:00:00Z".into(),
    };

    let decision = assess(&corpus, later.clone(), latest_capture()).unwrap();
    assert_eq!(decision.outcome, CoverageOutcome::Incomplete);
    assert_eq!(decision.covered_intervals, [] as [TimeRange; 0]);
    assert_eq!(decision.uncovered_intervals, [later.interval]);
    let cut = &decision.collection_runs[0];
    assert_eq!(cut.disposition, RunDisposition::Used);
    assert_eq!(cut.contributed_interval, None);
    assert!(cut.reason.contains("2026-09-05T00:00:00Z"));
}

#[test]
fn a_run_cut_to_nothing_is_named_in_the_coverage_gap() {
    let mut corpus = corpus();
    corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap()
        .started_at = "2026-09-01T00:00:00Z".into();

    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert!(assertion.missing.iter().any(|item| {
        item.requirement.contains("repository_mutations")
            && item
                .reason
                .contains("run-mutations-complete: complete authoritative enumeration contributes no coverage")
    }));
}

#[test]
fn adjacent_complete_windows_compose_but_a_gap_remains_visible() {
    let mut corpus = corpus();
    let template = corpus
        .collections
        .iter()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap()
        .clone();
    corpus.collections.retain(|run| run.id != template.id);
    let mut first = template.clone();
    first.id = "run-mutations-first".into();
    first.requested_scope.interval.until = "2026-09-03T00:00:00Z".into();
    first.observed_scope.as_mut().unwrap().interval.until = "2026-09-03T00:00:00Z".into();
    let mut second = template;
    second.id = "run-mutations-second".into();
    second.requested_scope.interval.from = "2026-09-03T00:00:00Z".into();
    second.observed_scope.as_mut().unwrap().interval.from = "2026-09-03T00:00:00Z".into();
    corpus.collections.extend([first, second]);

    let complete = assess(
        &corpus,
        requirement(Proposition::RepositoryMutations),
        latest_capture(),
    )
    .unwrap();
    assert_eq!(complete.outcome, CoverageOutcome::Complete);
    assert_eq!(complete.covered_intervals.len(), 1);

    corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-second")
        .unwrap()
        .observed_scope
        .as_mut()
        .unwrap()
        .interval
        .from = "2026-09-04T00:00:00Z".into();
    let gap = assess(
        &corpus,
        requirement(Proposition::RepositoryMutations),
        latest_capture(),
    )
    .unwrap();
    assert_eq!(gap.outcome, CoverageOutcome::Incomplete);
    assert_eq!(gap.uncovered_intervals[0].from, "2026-09-03T00:00:00Z");
    assert_eq!(gap.uncovered_intervals[0].until, "2026-09-04T00:00:00Z");
}

#[test]
fn reviewed_pull_requests_without_mutation_visibility_are_insufficient() {
    let mut corpus = corpus();
    corpus
        .collections
        .retain(|run| run.id != "run-mutations-complete");
    corpus
        .observations
        .retain(|item| item.kind != ObservationKind::MutationHistory);
    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert!(assertion.missing.iter().any(|item| {
        item.requirement.contains("repository_mutations")
            && item.reason.contains("no collection attempt")
    }));
}

#[test]
fn an_observed_direct_push_contradicts_even_before_absence_is_proven() {
    let corpus = collect(
        Path::new(FIXTURES)
            .join("collection-direct-push.json")
            .as_path(),
    )
    .unwrap();
    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Contradicted);
    assert!(assertion
        .reasoning
        .iter()
        .any(|step| step.code == "direct_push_observed"));
}

#[test]
fn a_run_cut_to_nothing_still_supplies_its_counterexamples() {
    let mut corpus = collect(
        Path::new(FIXTURES)
            .join("collection-direct-push.json")
            .as_path(),
    )
    .unwrap();
    corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap()
        .started_at = "2026-09-03T12:00:00Z".into();
    let mut target = target();
    target.from = "2026-09-03T13:00:00Z".into();

    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target, latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Contradicted);
    assert_eq!(assertion.contradictions.len(), 1);
    assert!(assertion
        .reasoning
        .iter()
        .any(|step| step.code == "direct_push_observed"));
    let mutations = assertion
        .coverage
        .iter()
        .find(|decision| decision.requirement.proposition == Proposition::RepositoryMutations)
        .unwrap();
    assert_eq!(mutations.outcome, CoverageOutcome::Incomplete);
    assert_eq!(
        mutations.uncovered_intervals,
        [TimeRange {
            from: "2026-09-03T13:00:00Z".into(),
            until: "2026-09-05T00:00:00Z".into(),
        }]
    );
    let cut = &mutations.collection_runs[0];
    assert_eq!(cut.disposition, RunDisposition::Used);
    assert_eq!(cut.contributed_interval, None);
    assert!(cut.reason.contains("2026-09-03T12:00:00Z"));
}

#[test]
fn a_declared_mirror_cannot_contradict_review_with_its_own_pushes() {
    let corpus = collect(
        Path::new(FIXTURES)
            .join("collection-direct-push.json")
            .as_path(),
    )
    .unwrap();
    let mirrored = divinate::provenance::with_declared_mirror(
        &corpus,
        "github:cyberwitchery/example",
        "an internal forge",
    );
    let assertion =
        evaluate_every_main_change_reviewed(&mirrored, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert_eq!(assertion.contradictions, []);
    assert!(assertion.missing.iter().any(|item| {
        item.requirement.contains("repository_mutations")
            && item
                .reason
                .contains("declared a mirror of an internal forge")
    }));
    assert!(assertion.coverage.iter().all(|decision| decision
        .collection_runs
        .iter()
        .all(|run| run.disposition == RunDisposition::NotAuthoritative)));
}

#[test]
fn a_declared_mirror_names_itself_as_the_branch_configuration_gap() {
    let mut corpus = corpus();
    let mut run = corpus.collections[0].clone();
    run.id = "run-branch-configuration".into();
    run.requested_scope.proposition = Proposition::BranchConfiguration;
    run.observed_scope = Some(run.requested_scope.clone());
    run.authority = vec![Proposition::BranchConfiguration];
    for observation in corpus.observations.iter_mut().filter(|item| {
        item.kind == ObservationKind::ConfigurationSnapshot
            && item.claim_key.starts_with("github:branch-protection")
    }) {
        observation.collection_run_id = Some(run.id.clone());
        run.observation_ids.push(observation.id.clone());
    }
    corpus.collections.push(run);
    let assertion =
        evaluate_configured_independent_review(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::Supported);

    let mirrored = divinate::provenance::with_declared_mirror(
        &corpus,
        "github:cyberwitchery/example",
        "an internal forge",
    );
    let assertion =
        evaluate_configured_independent_review(&mirrored, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert!(
        assertion.missing.iter().any(|item| item.reason.contains(
            "is declared a mirror of an internal forge; it is not the system of record for branch configuration"
        )),
        "{:?}",
        assertion.missing
    );
}

#[test]
fn a_declared_mirror_withholds_imported_process_evidence() {
    let corpus = corpus();
    let mut mirrored = target();
    mirrored.mirror_of = Some("an internal forge".into());
    let at = latest_capture();

    let branch = evaluate_configured_independent_review(&corpus, &mirrored, at).unwrap();
    assert_eq!(branch.outcome, Outcome::InsufficientEvidence);
    assert!(branch.missing.iter().any(|item| item
        .reason
        .contains("declared a mirror of an internal forge; it is not the system of record for branch configuration")));

    let release = evaluate_release_reviews(&corpus, &mirrored, at).unwrap();
    assert_eq!(release.outcome, Outcome::InsufficientEvidence);
    assert_eq!(release.support, []);
    assert!(release.missing.iter().any(|item| item
        .reason
        .contains("declared a mirror of an internal forge")));

    let supply = evaluate_supply_chain(&corpus, &mirrored, at).unwrap();
    assert_eq!(
        supply.outcome,
        evaluate_supply_chain(&corpus, &target(), at)
            .unwrap()
            .outcome
    );
}

#[test]
fn a_declared_mirror_keeps_authority_only_for_its_own_repository_and_content() {
    let corpus = corpus();
    let mirrored = divinate::provenance::with_declared_mirror(
        &corpus,
        "github:cyberwitchery/other",
        "an internal forge",
    );
    assert_eq!(mirrored, corpus);
    let mirrored = divinate::provenance::with_declared_mirror(
        &corpus,
        "github:cyberwitchery/example",
        "an internal forge",
    );
    for run in mirrored
        .collections
        .iter()
        .filter(|run| run.subject.id == "github:cyberwitchery/example")
    {
        let content = matches!(
            run.requested_scope.proposition,
            Proposition::CommitAncestry
                | Proposition::DeclaredDependencies
                | Proposition::SupplyChainPolicyDecision
        );
        assert_eq!(
            run.authority.contains(&run.requested_scope.proposition),
            content
                && corpus
                    .collections
                    .iter()
                    .any(|original| original.id == run.id
                        && original
                            .authority
                            .contains(&run.requested_scope.proposition)),
            "{}",
            run.id
        );
    }
}

#[test]
fn authority_is_assessed_per_proposition() {
    let mut corpus = corpus();
    let run = corpus
        .collections
        .iter_mut()
        .find(|run| run.id == "run-mutations-complete")
        .unwrap();
    run.authority = vec![Proposition::CommitAncestry];
    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::InsufficientEvidence);
    assert_eq!(
        assertion.coverage[0].collection_runs[0].disposition,
        RunDisposition::NotAuthoritative
    );
}

#[test]
fn assertion_coverage_traces_through_runs_to_original_sources() {
    let corpus = corpus();
    let assertion =
        evaluate_every_main_change_reviewed(&corpus, &target(), latest_capture()).unwrap();
    for decision in &assertion.coverage {
        for assessment in decision
            .collection_runs
            .iter()
            .filter(|run| run.disposition == RunDisposition::Used)
        {
            let run = corpus
                .collections
                .iter()
                .find(|run| run.id == assessment.collection_run_id)
                .unwrap();
            assert_ne!(run.observation_ids, [] as [String; 0]);
            for observation_id in &run.observation_ids {
                assert_ne!(
                    source_bytes(&corpus, observation_id).unwrap(),
                    [] as [u8; 0]
                );
            }
        }
    }
}

#[test]
fn adequate_security_review_is_not_inferred_from_counts_and_gates() {
    let assertion =
        evaluate_adequate_security_review(&corpus(), &target(), latest_capture()).unwrap();
    assert_eq!(assertion.outcome, Outcome::NotAutomatable);
    assert_ne!(assertion.considered, []);
    assert_eq!(
        assertion.missing[0].requirement,
        "security_review_scope_and_content"
    );
    assert!(assertion.reasoning[0]
        .conclusion
        .contains("cannot establish"));
}

#[test]
fn every_assertion_evidence_reference_reaches_original_source_bytes() {
    let corpus = corpus();
    let assertions = evaluate_all(&corpus, &target(), latest_capture()).unwrap();
    for assertion in assertions {
        for evidence in assertion
            .support
            .iter()
            .chain(&assertion.contradictions)
            .chain(&assertion.considered)
        {
            let observation = corpus
                .observations
                .iter()
                .find(|item| item.id == evidence.observation_id)
                .unwrap();
            assert_eq!(observation.provenance.source_id, evidence.source_id);
            assert_ne!(
                source_bytes(&corpus, &observation.id).unwrap(),
                [] as [u8; 0]
            );
        }
    }
}

#[test]
fn collection_is_deterministic() {
    assert_eq!(corpus(), corpus());
}

#[test]
fn assertion_derivation_is_deterministic() {
    let corpus = corpus();
    let evaluated_at = latest_capture();
    assert_eq!(
        evaluate_all(&corpus, &target(), evaluated_at).unwrap(),
        evaluate_all(&corpus, &target(), evaluated_at).unwrap()
    );
}

#[test]
fn embedded_source_is_byte_exact_and_hash_verified() {
    let corpus = corpus();
    let observation = corpus
        .observations
        .iter()
        .find(|item| item.producer.name == "sbom-diff")
        .unwrap();
    let raw = fs::read(Path::new(FIXTURES).join("sbom-diff.json")).unwrap();
    assert_eq!(source_bytes(&corpus, &observation.id).unwrap(), raw);
    let source = corpus
        .sources
        .iter()
        .find(|source| source.id == observation.provenance.source_id)
        .unwrap();
    assert_eq!(source.sha256, hex_digest(&raw));
}
