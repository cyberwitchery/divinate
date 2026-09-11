use std::path::Path;

use divinate as evidence_spike;
use evidence_spike::assertions::{AssertionType, DerivedAssertion, Outcome};
use evidence_spike::{load_corpus, provenance, read_json, workflow};

const STATE: &str = "dossiers/sbom-diff/repeated/.evidence";

#[test]
fn checked_in_release_gate_has_complete_local_execution_provenance() {
    let state = Path::new(STATE);
    let corpus = load_corpus(&workflow::corpus_path(state)).unwrap();
    let assertions: Vec<DerivedAssertion> =
        read_json(&state.join("assertions/product-current.json")).unwrap();
    let executions = workflow::load_executions(state).unwrap();
    let blobs = workflow::load_blobs(state).unwrap();
    let links = provenance::verify_execution_links(&corpus, &executions, &blobs).unwrap();
    let assertion = assertions
        .iter()
        .find(|assertion| assertion.assertion_type == AssertionType::ReleaseSupplyChainPolicy)
        .unwrap();

    assert_eq!(assertion.outcome, Outcome::Supported);
    assert_eq!(assertion.support.len(), 2);
    for evidence in &assertion.support {
        assert!(links
            .iter()
            .any(|link| link.observation_id == evidence.observation_id));
    }
    let tools = assertion
        .support
        .iter()
        .flat_map(|evidence| {
            links
                .iter()
                .filter(move |link| link.observation_id == evidence.observation_id)
        })
        .filter_map(|link| {
            executions
                .iter()
                .find(|execution| execution.id == link.execution_transcript_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(tools.len(), 2);
    assert!(tools
        .iter()
        .all(|item| item.contents.tool.name == "sbom-diff"));
    assert!(tools
        .iter()
        .any(|item| item.contents.argv.iter().any(|arg| arg == "--fail-on")));
    assert!(tools.iter().all(|item| item.contents.inputs.len() == 2));
}

#[test]
fn contract_changes_do_not_rewrite_local_executions() {
    let state = Path::new(STATE);
    let before = workflow::load_executions(state).unwrap();
    let mut registry = workflow::load_registry(state).unwrap();
    assert!(!registry.invalidations.is_empty());
    registry.invalidations[0].reason = "a different current interpretation".into();
    let after = workflow::load_executions(state).unwrap();
    assert_eq!(before, after);
}
