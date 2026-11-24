//! one organisation reading, from requests to a verified record.

use std::collections::BTreeMap;
use std::fs;

use divinate::facts::summary;
use divinate::model::aspect::{BRANCH_PROTECTION, REPOSITORIES, REPOSITORY, REQUIRED_CHECKS};
use divinate::{ledger, record, verify};

mod common;

const API: &str = "https://api.github.com";

type Responses = BTreeMap<String, (u16, BTreeMap<String, String>, String)>;

fn respond(responses: &mut Responses, path: &str, status: u16, body: &str) {
    responses.insert(
        format!("{API}{path}"),
        (status, BTreeMap::new(), body.into()),
    );
}

fn repository(id: u64, name: &str) -> String {
    format!(
        r#"{{"id":{id},"name":"{name}","owner":{{"id":1}},"visibility":"public","archived":false,"fork":false,"default_branch":"main"}}"#
    )
}

/// an organisation with two repositories, listed over two pages.
fn organisation() -> Responses {
    let mut responses = Responses::new();
    respond(
        &mut responses,
        "/orgs/example",
        200,
        r#"{"id":1,"login":"example","public_repos":2,"total_private_repos":0}"#,
    );
    responses.insert(
        format!("{API}/orgs/example/repos?per_page=100&type=all"),
        (
            200,
            BTreeMap::from([(
                "link".into(),
                format!("<{API}/organizations/1/repos?per_page=100&type=all&page=2>; rel=\"next\""),
            )]),
            format!("[{}]", repository(10, "service")),
        ),
    );
    respond(
        &mut responses,
        "/organizations/1/repos?per_page=100&type=all&page=2",
        200,
        &format!("[{}]", repository(11, "tools")),
    );
    respond(
        &mut responses,
        "/repos/example/service/branches/main/protection",
        200,
        r#"{"url":"https://api.github.com/x","required_status_checks":{"contexts":["ci"],"checks":[{"context":"ci","app_id":1}]}}"#,
    );
    respond(
        &mut responses,
        "/repos/example/service/rules/branches/main?per_page=100",
        200,
        "[]",
    );
    respond(
        &mut responses,
        "/repos/example/tools/branches/main/protection",
        404,
        r#"{"message":"Branch not protected"}"#,
    );
    respond(
        &mut responses,
        "/repos/example/tools/rules/branches/main?per_page=100",
        200,
        "[]",
    );
    responses
}

fn collect(
    responses: &Responses,
    at: &str,
) -> (record::Collection, Vec<divinate::transcript::Transcript>) {
    common::collect("github:example", at, at, |url| {
        responses
            .get(url)
            .unwrap_or_else(|| panic!("unexpected request: {url}"))
            .clone()
    })
}

#[test]
fn a_reading_is_stored_shown_and_verified() {
    let state = tempfile::tempdir().unwrap();
    let (collection, transcripts) = collect(&organisation(), "2026-03-02T09:00:00Z");
    record::store(state.path(), &collection, &transcripts).unwrap();

    let inventory = collection
        .statement_about("github:example", REPOSITORIES)
        .unwrap();
    assert_eq!(summary(inventory), "2 repositories");
    assert_eq!(inventory.note, None);
    assert_eq!(collection.gaps(), 0);
    let tools = collection
        .statement_about("github:example/tools", REPOSITORY)
        .unwrap();
    assert_eq!(summary(tools), "public, default branch main");
    let unprotected = collection
        .statement_about("github:example/tools@main", BRANCH_PROTECTION)
        .unwrap();
    assert_eq!(summary(unprotected), "not protected");

    let report = verify::verify(state.path()).unwrap();
    assert_eq!((report.collections, report.transcripts), (1, 6));
    assert_eq!(record::load(state.path()).unwrap(), [collection]);
}

#[test]
fn a_changed_setting_shows_in_the_next_collection() {
    let state = tempfile::tempdir().unwrap();
    let mut responses = organisation();
    let (first, transcripts) = collect(&responses, "2026-03-02T09:00:00Z");
    record::store(state.path(), &first, &transcripts).unwrap();
    respond(
        &mut responses,
        "/repos/example/service/branches/main/protection",
        200,
        r#"{"required_status_checks":{"contexts":[],"checks":[]}}"#,
    );
    let (second, transcripts) = collect(&responses, "2026-04-06T09:00:00Z");
    record::store(state.path(), &second, &transcripts).unwrap();

    let collections = record::load(state.path()).unwrap();
    let rendered = ledger::ledger(&collections, 8);
    let row = |subject: &str, kind: &str| {
        rendered
            .lines()
            .skip_while(|line| *line != subject)
            .find(|line| line.trim_start().starts_with(kind))
            .unwrap()
            .to_owned()
    };
    assert!(row("github:example/service@main", REQUIRED_CHECKS).ends_with("■      ▣"));
    assert!(row("github:example/tools@main", REQUIRED_CHECKS).ends_with("■      ■"));
    verify::verify(state.path()).unwrap();
}

#[test]
fn a_denied_reading_is_a_gap_and_a_rate_limit_stops_the_rest() {
    let mut responses = organisation();
    respond(
        &mut responses,
        "/repos/example/service/branches/main/protection",
        403,
        r#"{"message":"Resource not accessible by personal access token"}"#,
    );
    respond(
        &mut responses,
        "/repos/example/service/rules/branches/main?per_page=100",
        429,
        r#"{"message":"API rate limit exceeded"}"#,
    );
    responses.remove(&format!(
        "{API}/repos/example/tools/branches/main/protection"
    ));
    responses.remove(&format!(
        "{API}/repos/example/tools/rules/branches/main?per_page=100"
    ));
    let (collection, _) = collect(&responses, "2026-03-02T09:00:00Z");

    let reason = |name: &str, aspect: &str| {
        let statement = collection.statement_about(name, aspect).unwrap();
        statement.reading.gap_reason().map(str::to_owned)
    };
    let denied = reason("github:example/service@main", BRANCH_PROTECTION).unwrap();
    assert!(denied.starts_with("permission denied"));
    let skipped = reason("github:example/tools@main", BRANCH_PROTECTION).unwrap();
    assert!(skipped.starts_with("not attempted"));
    // nothing about either branch could be read; the listing still was.
    assert_eq!(collection.gaps(), 8);
    assert_eq!(reason("github:example/tools", REPOSITORY), None);
}

#[test]
fn an_unreadable_organisation_is_one_recorded_gap() {
    let mut responses = Responses::new();
    respond(
        &mut responses,
        "/orgs/example",
        404,
        r#"{"message":"Not Found"}"#,
    );
    respond(
        &mut responses,
        "/orgs/example/repos?per_page=100&type=all",
        404,
        r#"{"message":"Not Found"}"#,
    );
    let (collection, _) = collect(&responses, "2026-03-02T09:00:00Z");
    let derived = &collection.contents.derived;
    assert_eq!(derived.statements.len(), 1);
    assert!(summary(&derived.statements[0]).starts_with("gap: not found"));
    // nothing said who the organisation is, so it has a name and no stable id.
    assert_eq!(derived.entities.len(), 1);
    assert_eq!(
        derived.entities[0].uid,
        "github.com/organisation/unresolved:example"
    );
}

#[test]
fn an_edited_record_does_not_verify() {
    let edit = |directory: &str, from: &str, to: &str| {
        let state = tempfile::tempdir().unwrap();
        let (collection, transcripts) = collect(&organisation(), "2026-03-02T09:00:00Z");
        record::store(state.path(), &collection, &transcripts).unwrap();
        let mut edited = 0;
        for file in fs::read_dir(state.path().join(directory)).unwrap() {
            let path = file.unwrap().path();
            let text = fs::read_to_string(&path).unwrap();
            if text.contains(from) {
                fs::write(&path, text.replace(from, to)).unwrap();
                edited += 1;
            }
        }
        assert!(edited > 0, "nothing to edit in {directory}");
        verify::verify(state.path()).unwrap_err().to_string()
    };
    // a response body, an entry, and a transcript swapped for another.
    assert!(edit("transcripts", "Branch not protected", "Branch protected").contains("transcript"));
    assert!(
        edit("collections", "\"protected\": false", "\"protected\": true").contains("collection")
    );
}
