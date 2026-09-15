use std::path::Path;

use divinate as evidence_spike;
use evidence_spike::assertions::{self, AssertionType, EvaluationTarget, Outcome};
use evidence_spike::dossier::{self, Dossier};
use evidence_spike::{collect, parse_timestamp, source_bytes};

fn target() -> EvaluationTarget {
    EvaluationTarget {
        repository: "github:cyberwitchery/example".into(),
        branch: "main".into(),
        release: Some("v1.4".into()),
        from: "2026-09-01T00:00:00Z".into(),
        until: "2026-09-05T00:00:00Z".into(),
    }
}

fn dossier() -> (evidence_spike::model::Corpus, Dossier) {
    let corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    (corpus, dossier)
}

#[test]
fn dossier_states_are_the_derived_assertion_states() {
    let corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    for control in &dossier.contents.controls {
        let assertion = assertions
            .iter()
            .find(|assertion| assertion.id == control.assertion_id)
            .unwrap();
        let expected = match assertion.outcome {
            Outcome::Supported => "supported",
            Outcome::Contradicted => "contradicted",
            Outcome::InsufficientEvidence => "insufficient evidence",
            Outcome::Stale => "stale",
            Outcome::NotAutomatable => "not automatable",
        };
        assert_eq!(control.state, expected);
    }
}

#[test]
fn repository_dossier_omits_release_context() {
    let corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let mut repository = target();
    repository.release = None;
    let assertions = assertions::evaluate_all(&corpus, &repository, at).unwrap();
    let dossier = dossier::build(&corpus, &assertions, &[], &repository, at).unwrap();
    assert_eq!(dossier.contents.release, None);
    assert!(!dossier::render_markdown(&dossier).contains("release: `"));
}

#[test]
fn universal_gap_and_human_boundary_remain_specific() {
    let mut corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    corpus.collections.clear();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    let universal = dossier
        .contents
        .controls
        .iter()
        .find(|control| control.title == "changes received approving review before integration")
        .unwrap();
    assert_eq!(universal.state, "insufficient evidence");
    assert!(universal
        .missing
        .iter()
        .any(|gap| gap.requirement.contains("repository_mutations")));

    let human = dossier
        .contents
        .controls
        .iter()
        .find(|control| control.title == "adequate human security review")
        .unwrap();
    assert_eq!(human.state, "not automatable");
    assert_eq!(
        human.missing[0].requirement,
        "security_review_scope_and_content"
    );

    let markdown = dossier::render_markdown(&dossier);
    let interval = "2026-09-01T00:00:00Z to 2026-09-05T00:00:00Z";
    assert_eq!(
        markdown.matches(&format!("uncovered: {interval}")).count(),
        1
    );
    assert!(markdown.contains("missing coverage: pull request reviews, repository mutations"));
}

#[test]
fn distinct_uncovered_intervals_remain_distinct_in_markdown() {
    let mut corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    corpus.collections.clear();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let mut assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    let historical = assertions
        .iter_mut()
        .find(|item| item.assertion_type == AssertionType::EveryMainChangeReviewed)
        .unwrap();
    historical.coverage[1].uncovered_intervals[0].from = "2026-09-02T00:00:00Z".into();
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    let markdown = dossier::render_markdown(&dossier);
    assert!(markdown.contains("uncovered: 2026-09-01T00:00:00Z to 2026-09-05T00:00:00Z"));
    assert!(markdown.contains("uncovered: 2026-09-02T00:00:00Z to 2026-09-05T00:00:00Z"));
}

#[test]
fn current_and_historical_configuration_are_both_rendered() {
    let (_, dossier) = dossier();
    let markdown = dossier::render_markdown(&dossier);
    assert!(markdown.contains("branch protection required 2 approving review(s)"));
    assert!(markdown.contains("branch protection required 1 approving review(s)"));
}

#[test]
fn configured_review_title_uses_the_assertion_branch() {
    let corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let mut assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    assertions
        .iter_mut()
        .find(|item| item.assertion_type == AssertionType::ConfiguredIndependentReview)
        .unwrap()
        .subject
        .branch = Some("develop".into());
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    assert!(dossier
        .contents
        .controls
        .iter()
        .any(|control| control.title == "approval required on develop"));
}

#[test]
fn every_dossier_evidence_reference_resolves_to_verified_source_bytes() {
    let (corpus, dossier) = dossier();
    for control in &dossier.contents.controls {
        for evidence in control.evidence.iter().chain(&control.contradictions) {
            let bytes = source_bytes(&corpus, &evidence.observation_id).unwrap();
            assert!(!bytes.is_empty());
            assert!(corpus.sources.iter().any(|source| {
                source.id == evidence.source_id && source.sha256 == evidence.source_sha256
            }));
        }
    }
}

#[test]
fn regeneration_is_deterministic_and_markdown_uses_machine_states() {
    let (_, first) = dossier();
    let (_, second) = dossier();
    assert_eq!(first, second);
    let markdown = dossier::render_markdown(&first);
    for control in &first.contents.controls {
        assert!(markdown.contains(&format!("state: **{}**", control.state)));
    }
    assert!(first
        .contents
        .controls
        .iter()
        .any(|control| control.assertion_id.starts_with("asrt_")
            && control.evaluator.contains("/v1")));
    assert!(first.contents.controls.iter().any(|control| {
        control.title == "release dependency gate"
            && control.state == "supported"
            && !control.identity_joins.is_empty()
    }));
    assert!(first.contents.controls.iter().any(|control| {
        control.title == "release dependency changes preserved" && control.state == "supported"
    }));
    assert!(first.contents.controls.iter().any(|control| {
        control.title == "approval required on main" && control.state == "supported"
    }));
    assert!(first.contents.controls.iter().all(|control| {
        matches!(
            control.title.as_str(),
            "approval required on main"
                | "changes received approving review before integration"
                | "release dependency changes preserved"
                | "release dependency gate"
                | "adequate human security review"
        )
    }));
    let assertion_types = [
        AssertionType::ConfiguredIndependentReview,
        AssertionType::EveryMainChangeReviewed,
        AssertionType::DependencyChangeVisibility,
        AssertionType::ReleaseSupplyChainPolicy,
        AssertionType::AdequateHumanSecurityReview,
    ];
    assert_eq!(first.contents.controls.len(), assertion_types.len());
}

#[test]
fn pack_assertions_reach_the_dossier() {
    let corpus = collect(Path::new("fixtures/collection.json")).unwrap();
    let at = parse_timestamp("2026-09-05T00:00:00Z").unwrap();
    let mut assertions = assertions::evaluate_all(&corpus, &target(), at).unwrap();
    let mut external = assertions[0].clone();
    external.id = "asrt_external".into();
    external.assertion_type = AssertionType::External("backup_encryption".into());
    external.claim = "repository backups are configured to use encryption".into();
    assertions.push(external);
    let mut github = assertions[0].clone();
    github.id = "asrt_github".into();
    github.assertion_type = AssertionType::External("github_current_revision_checks_passed".into());
    assertions.push(github);
    let dossier = dossier::build(&corpus, &assertions, &[], &target(), at).unwrap();
    assert!(dossier
        .contents
        .controls
        .iter()
        .any(|control| control.assertion_id == "asrt_external"
            && control.title == "backup encryption"));
    assert!(dossier
        .contents
        .controls
        .iter()
        .any(|control| control.assertion_id == "asrt_github"
            && control.title == "observed GitHub revision results acceptable"));
}
