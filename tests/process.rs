//! a repository read with its tickets and changes, and a process checked against it.

use std::collections::BTreeMap;
use std::fs;

use divinate::error::Result;
use divinate::process::{self, Outcome};
use divinate::record::{self, Collection};
use divinate::verify;

mod common;

const API: &str = "https://api.github.com/repos/example/service";
const NOW: &str = "2026-03-27T00:00:00Z";
const FROM: &str = "2026-01-01T00:00:00Z";

const DEFINITION: &str = r"
process: security tickets
items:
  kind: ticket
  label: security
steps:
  - name: answered
    event: comment
    by: someone else
    within: 7d
  - name: resolved
    event: closed
    within: 30d
  - name: fix reviewed
    linked: change
    event: approval
    by: someone else
    before: merge
";

fn user(id: u64) -> String {
    format!(r#"{{"id":{id},"login":"user{id}","type":"User"}}"#)
}

fn ticket(number: u64, opened: &str, label: &str) -> String {
    format!(
        r#"{{"id":{},"number":{number},"title":"t","state":"open","user":{},"created_at":"{opened}","closed_at":null,"labels":[{{"name":"{label}"}}]}}"#,
        100 + number,
        user(1)
    )
}

fn change(number: u64, opened: &str, merged: &str, body: &str) -> String {
    format!(
        r#"{{"id":{},"number":{number},"title":"c","state":"closed","user":{},"created_at":"{opened}","closed_at":"{merged}","labels":[],"body":"{body}","pull_request":{{"merged_at":"{merged}"}},"repository":{{"full_name":"example/service"}}}}"#,
        100 + number,
        user(2)
    )
}

const HEAD: &str = "3f467b9e7ed6241bf3052cdccd47f4c2aec6c924";

/// what github says of the commit a change proposes: one check run with a
/// conclusion that finished at a time, and no commit statuses.
fn checked(
    responses: &mut BTreeMap<String, (u16, String)>,
    number: u64,
    base: &str,
    run: (&str, &str),
) {
    let (conclusion, at) = run;
    let sha = format!("{}{number}", &HEAD[..39]);
    responses.insert(
        format!("{API}/pulls/{number}"),
        (
            200,
            format!(r#"{{"number":{number},"head":{{"sha":"{sha}"}},"base":{{"ref":"{base}"}}}}"#),
        ),
    );
    // change 2 touches the sign-in code, every other change the readme alone.
    let files = if number == 2 {
        r#"[{"filename":"src/auth/login.rs"},{"filename":"README.md","previous_filename":"readme.txt"}]"#
    } else {
        r#"[{"filename":"README.md"}]"#
    };
    responses.insert(
        format!("{API}/pulls/{number}/files?per_page=100"),
        (200, files.to_owned()),
    );
    responses.insert(
        format!("{API}/commits/{sha}/check-runs?filter=all&per_page=100"),
        (200, format!(
            r#"{{"total_count":2,"check_runs":[{{"id":{number}1,"name":"build","status":"completed","conclusion":"{conclusion}","completed_at":"{at}"}},{{"id":{number}2,"name":"docs","status":"completed","conclusion":"skipped","completed_at":"{at}"}}]}}"#
        )),
    );
    responses.insert(
        format!("{API}/commits/{sha}/status?per_page=100"),
        (
            200,
            r#"{"state":"pending","statuses":[],"total_count":0}"#.to_owned(),
        ),
    );
}

fn happened(id: u64, event: &str, by: u64, at: &str) -> String {
    let (who, when, state) = match event {
        "approved" => (
            "user",
            "submitted_at",
            r#""event":"reviewed","state":"approved""#.to_owned(),
        ),
        other => ("actor", "created_at", format!(r#""event":"{other}""#)),
    };
    let who = if event == "commented" { "user" } else { who };
    format!(
        r#"{{"id":{id},{state},"{who}":{},"{when}":"{at}"}}"#,
        user(by)
    )
}

/// a repository with security tickets in every state a step can find them in.
/// `approver` is who approved the change that closes ticket 1.
fn repository(approver: u64) -> BTreeMap<String, (u16, String)> {
    let fix = change(
        2,
        "2026-03-02T09:00:00Z",
        "2026-03-19T12:00:00Z",
        "Fixes #1",
    );
    let items = [
        ticket(1, "2026-03-01T09:00:00Z", "security"),
        fix.clone(),
        ticket(3, "2026-03-25T09:00:00Z", "security"),
        ticket(4, "2026-03-01T09:00:00Z", "security"),
        ticket(5, "2026-03-01T09:00:00Z", "security"),
        ticket(6, "2026-03-01T09:00:00Z", "question"),
        ticket(7, "2025-12-01T09:00:00Z", "security"),
        // opened before the period and merged in it, with no approval.
        change(8, "2025-12-20T09:00:00Z", "2026-02-01T12:00:00Z", ""),
    ];
    let timelines = [
        (
            1,
            200,
            vec![
                happened(11, "commented", 3, "2026-03-03T10:00:00Z"),
                format!(
                    r#"{{"event":"cross-referenced","actor":{},"created_at":"2026-03-02T09:00:00Z","source":{{"issue":{fix}}}}}"#,
                    user(2)
                ),
                happened(12, "closed", 2, "2026-03-20T16:00:00Z"),
            ],
        ),
        (
            2,
            200,
            vec![
                happened(21, "approved", approver, "2026-03-19T11:00:00Z"),
                happened(22, "merged", 2, "2026-03-19T12:00:00Z"),
            ],
        ),
        (3, 200, vec![]),
        (4, 404, vec![]),
        (
            5,
            200,
            vec![happened(51, "commented", 1, "2026-03-02T10:00:00Z")],
        ),
        (6, 200, vec![]),
        (
            8,
            200,
            vec![happened(81, "merged", 2, "2026-02-01T12:00:00Z")],
        ),
    ];
    let mut responses = BTreeMap::from([
        (API.to_owned(), (200, r#"{"id":7,"name":"service","owner":{"id":1,"login":"example","type":"Organization"},"visibility":"private","archived":false,"fork":false,"default_branch":"main"}"#.to_owned())),
        (format!("{API}/branches/main/protection"), (404, r#"{"message":"Branch not protected"}"#.to_owned())),
        (format!("{API}/rules/branches/main?per_page=100"), (200, "[]".to_owned())),
        // change 8 goes into another branch, whose settings are read as well.
        (format!("{API}/branches/release/protection"), (404, r#"{"message":"Branch not protected"}"#.to_owned())),
        (format!("{API}/rules/branches/release?per_page=100"), (200, "[]".to_owned())),
        (format!("{API}/activity?ref=refs%2Fheads%2Frelease&time_period=quarter&per_page=100"), (200, "[]".to_owned())),
        (
            format!("{API}/issues?state=all&sort=created&direction=asc&per_page=100&since=2026-01-01T00%3A00%3A00Z"),
            (200, format!("[{}]", items.join(","))),
        ),
    ]);
    for (number, status, events) in timelines {
        let body = if status == 200 {
            format!("[{}]", events.join(","))
        } else {
            r#"{"message":"Not Found"}"#.to_owned()
        };
        responses.insert(
            format!("{API}/issues/{number}/timeline?per_page=100"),
            (status, body),
        );
    }
    checked(
        &mut responses,
        2,
        "main",
        ("success", "2026-03-19T10:00:00Z"),
    );
    // the check on change 8 passed only after it was merged.
    checked(
        &mut responses,
        8,
        "release",
        ("success", "2026-02-01T12:05:00Z"),
    );
    updated_and_scanned(&mut responses);
    responses
}

/// what github says happened to the default branch, and what its scanners found.
fn updated_and_scanned(responses: &mut BTreeMap<String, (u16, String)>) {
    // one release in the period with a bill of materials, one draft, and one
    // published before the period.
    let release = |id: u64, tag: &str, draft: bool, at: &str, assets: &str| {
        format!(
            r#"{{"id":{id},"tag_name":"{tag}","name":"{tag}","draft":{draft},"prerelease":false,"published_at":"{at}","author":{},"assets":[{assets}]}}"#,
            user(2)
        )
    };
    responses.insert(
        format!("{API}/releases?per_page=100"),
        (
            200,
            format!(
                "[{},{},{}]",
                release(
                    93,
                    "v1.3.0",
                    true,
                    "2026-03-21T10:00:00Z",
                    ""
                ),
                release(
                    92,
                    "v1.2.0",
                    false,
                    "2026-03-20T10:00:00Z",
                    r#"{"name":"service.cdx.json","size":2048,"digest":"sha256:aa"},{"name":"service.tar.gz","size":4096,"digest":null}"#
                ),
                release(91, "v1.1.0", false, "2025-11-01T10:00:00Z", ""),
            ),
        ),
    );
    let update = |id: u64, kind: &str, at: &str| {
        format!(
            r#"{{"id":{id},"ref":"refs/heads/main","timestamp":"{at}","activity_type":"{kind}","actor":{}}}"#,
            user(2)
        )
    };
    responses.insert(
        format!("{API}/activity?ref=refs%2Fheads%2Fmain&time_period=quarter&per_page=100"),
        (
            200,
            format!(
                "[{}]",
                [
                    update(1, "pr_merge", "2026-03-19T12:00:00Z"),
                    update(2, "push", "2026-03-10T08:00:00Z"),
                    update(3, "pr_merge", "2026-02-01T12:00:00Z"),
                    update(4, "push", "2025-12-24T08:00:00Z"),
                    update(5, "branch_creation", "2025-11-01T08:00:00Z"),
                ]
                .join(",")
            ),
        ),
    );
    let alert = |number: u64, opened: &str, rest: &str| {
        format!(
            r#"{{"number":{number},"created_at":"{opened}","rule":{{"severity":"warning","security_severity_level":"high","description":"d"}},{rest}}}"#
        )
    };
    responses.insert(
        format!("{API}/code-scanning/alerts?state=all&per_page=100"),
        (200, format!(
            "[{}]",
            [
                alert(1, "2026-02-01T09:00:00Z", r#""state":"fixed","fixed_at":"2026-02-10T09:00:00Z","dismissed_at":null"#),
                alert(2, "2026-02-01T09:00:00Z", &format!(r#""state":"dismissed","fixed_at":null,"dismissed_at":"2026-03-20T09:00:00Z","dismissed_by":{}"#, user(3))),
                alert(3, "2026-02-01T09:00:00Z", r#""state":"open","fixed_at":null,"dismissed_at":null"#),
                alert(4, "2025-06-01T09:00:00Z", r#""state":"open","fixed_at":null,"dismissed_at":null"#),
            ]
            .join(",")
        )),
    );
    responses.insert(
        format!("{API}/dependabot/alerts?per_page=100"),
        (
            403,
            r#"{"message":"Dependabot alerts are disabled for this repository."}"#.to_owned(),
        ),
    );
    responses.insert(
        format!("{API}/secret-scanning/alerts?per_page=100"),
        (
            403,
            r#"{"message":"Resource not accessible by integration"}"#.to_owned(),
        ),
    );
}

fn collect(
    responses: &BTreeMap<String, (u16, String)>,
) -> (Collection, Vec<divinate::transcript::Transcript>) {
    common::collect("github:example/service", FROM, NOW, |url| {
        common::answer(responses.get(url), url)
    })
}

fn definition(text: &str) -> Result<process::Process> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("process.yaml");
    fs::write(&path, text).unwrap();
    process::load(&path)
}

/// the outcome labels of each selected ticket, by ticket number.
fn outcomes(collection: &Collection) -> BTreeMap<String, Vec<&'static str>> {
    let report = process::check(&definition(DEFINITION).unwrap(), collection, &[]).unwrap();
    report
        .rows
        .iter()
        .map(|row| {
            let number = row.item.rsplit('#').next().unwrap().to_owned();
            (number, row.outcomes.iter().map(Outcome::label).collect())
        })
        .collect()
}

#[test]
fn each_step_is_kept_broken_pending_unknown_or_not_applicable() {
    let (collection, transcripts) = collect(&repository(3));
    let found = outcomes(&collection);
    // ticket 6 has another label, and ticket 7 was opened before the period.
    assert_eq!(found.keys().collect::<Vec<_>>(), ["1", "3", "4", "5"]);
    // answered in two days, closed in nineteen, fixed by a reviewed change.
    assert_eq!(found["1"], ["kept", "kept", "kept"]);
    // opened two days before the reading: nothing is due yet.
    assert_eq!(found["3"], ["pending", "pending", "n/a"]);
    // its events could not be read, so nothing can be said about them.
    assert_eq!(found["4"], ["cannot tell", "cannot tell", "n/a"]);
    // only its own author commented, and a week has passed. thirty days have not.
    assert_eq!(found["5"], ["broken", "pending", "n/a"]);

    let state = tempfile::tempdir().unwrap();
    record::store(state.path(), &collection, &transcripts).unwrap();
    verify::verify(state.path()).unwrap();
}

#[test]
fn an_approval_by_the_author_of_the_change_does_not_count() {
    let (collection, _) = collect(&repository(2));
    assert_eq!(outcomes(&collection)["1"], ["kept", "kept", "broken"]);
    let report = process::check(&definition(DEFINITION).unwrap(), &collection, &[]).unwrap();
    let rendered = process::render(&report);
    assert!(rendered.contains("tickets opened 2026-01-01T00:00:00Z to 2026-03-27T00:00:00Z: 5 read, 4 labelled \"security\""));
    assert!(rendered.contains("fix reviewed  1 broken, 3 n/a"));
    assert!(rendered.contains(
        "github:example/service#1 · fix reviewed: broken, github:example/service#2: merge without approval by someone else before it"
    ));
}

#[test]
fn an_unreadable_listing_leaves_the_whole_process_unknown() {
    let mut responses = repository(3);
    let listing = responses
        .keys()
        .find(|url| url.contains("/issues?"))
        .unwrap()
        .clone();
    responses.insert(
        listing,
        (403, r#"{"message":"Resource not accessible"}"#.to_owned()),
    );
    let (collection, _) = collect(&responses);
    let report = process::check(&definition(DEFINITION).unwrap(), &collection, &[]).unwrap();
    assert!(report.rows.is_empty());
    assert!(report
        .selected
        .as_ref()
        .unwrap_err()
        .contains("permission denied"));
    assert!(process::render(&report).contains("cannot tell: the tickets could not be read"));
}

#[test]
fn a_definition_that_cannot_be_checked_is_refused() {
    assert!(definition(DEFINITION).is_ok());
    let both = DEFINITION.replace("    within: 30d", "    within: 30d\n    before: merge");
    assert!(definition(&both)
        .unwrap_err()
        .to_string()
        .contains("not both"));
    assert!(definition(&DEFINITION.replace("7d", "a week")).is_err());
    assert!(definition(&DEFINITION.replace("label:", "labels:")).is_err());
    assert!(definition(&DEFINITION.replace("someone else", "anyone")).is_err());
}

fn checked_with(text: &str, collection: &Collection) -> process::Report {
    process::check(&definition(text).unwrap(), collection, &[]).unwrap()
}

fn labels(row: &process::Row) -> Vec<&'static str> {
    row.outcomes.iter().map(Outcome::label).collect()
}

#[test]
fn merged_changes_are_checked_whenever_they_were_opened() {
    let (collection, _) = collect(&repository(3));
    let report = checked_with(
        r"
process: change governance
items:
  kind: change
  when: merged
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
  - name: validated
    event: check passed
    before: merge
",
        &collection,
    );
    let found = report
        .rows
        .iter()
        .map(|row| (row.item.as_str(), labels(row)))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            // opened before the period: it is among the merged changes only.
            ("github:example/service#8", vec!["broken", "broken"]),
            ("github:example/service#2", vec!["kept", "kept"]),
        ]
    );
    // a skipped check run neither passed nor failed.
    let checks = collection
        .contents
        .derived
        .entities
        .iter()
        .filter(|entity| entity.kind.starts_with("check"))
        .map(|entity| entity.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(checks, ["build", "build"]);
}

#[test]
fn a_branch_is_checked_for_what_it_requires_and_what_happened_to_it() {
    let rules = r"
process: branch rules
branches:
  - name: review required
    approvals: 1
  - name: checks required
    checks: 1
  - name: no direct updates
    without: [push, force push]
";
    let mut responses = repository(3);
    let report = checked_with(rules, &collect(&responses).0);
    // the default branch, and the branch change 8 went into.
    assert_eq!(report.branches.len(), 2);
    assert_eq!(report.branches[0].item, "github:example/service@main");
    assert_eq!(report.branches[1].item, "github:example/service@release");
    assert_eq!(labels(&report.branches[1]), ["broken", "broken", "kept"]);
    // nothing is required, and one push in the period went around a change.
    // the push before the period and the creation of the branch do not count.
    assert_eq!(labels(&report.branches[0]), ["broken", "broken", "broken"]);
    assert_eq!(
        report.branches[0].outcomes[2],
        Outcome::Broken("1 of them, the first a push at 2026-03-10T08:00:00Z".into())
    );

    responses.insert(
        format!("{API}/branches/main/protection"),
        (200, r#"{"required_pull_request_reviews":{"required_approving_review_count":2},"required_status_checks":{"contexts":["build"]}}"#.to_owned()),
    );
    responses.insert(
        format!("{API}/activity?ref=refs%2Fheads%2Fmain&time_period=quarter&per_page=100"),
        (
            403,
            r#"{"message":"Resource not accessible by integration"}"#.to_owned(),
        ),
    );
    let report = checked_with(rules, &collect(&responses).0);
    assert_eq!(labels(&report.branches[0]), ["kept", "kept", "cannot tell"]);
}

#[test]
fn findings_are_work_items_with_a_population_per_scanner() {
    let (collection, _) = collect(&repository(3));
    let state = |aspect: &str| {
        collection
            .statement_about("github:example/service", aspect)
            .unwrap()
    };
    // three opened in the period; the fourth is older.
    assert_eq!(
        divinate::facts::summary(state("code scanning findings")),
        "3 findings"
    );
    // a scanner that is switched off has no findings, and the record says why.
    let dependencies = state("dependency findings");
    assert_eq!(divinate::facts::summary(dependencies), "no findings");
    assert!(dependencies.note.as_deref().unwrap().contains("not set up"));
    // one that could not be read is a gap, and then nothing can be said of all findings.
    assert!(
        divinate::facts::summary(state("secret findings")).starts_with("gap: permission denied")
    );
    let text = r"
process: scanner findings
items:
  kind: finding
  label: high
steps:
  - name: dealt with
    event: [closed, dismissed]
    within: 30d
";
    assert!(checked_with(text, &collection).selected.is_err());

    let mut responses = repository(3);
    responses.insert(
        format!("{API}/secret-scanning/alerts?per_page=100"),
        (200, "[]".to_owned()),
    );
    let report = checked_with(text, &collect(&responses).0);
    let found = report.rows.iter().map(labels).collect::<Vec<_>>();
    // fixed after 9 days, dismissed after 47, and still open after 54.
    assert_eq!(found, [["kept"], ["broken"], ["broken"]]);
}

const MERGED: &str = r"
process: merged changes
items:
  kind: change
  when: merged
  into: BRANCH
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
";

fn merged_into(branch: &str, collection: &Collection) -> Vec<(String, Outcome)> {
    checked_with(&MERGED.replace("BRANCH", branch), collection)
        .rows
        .into_iter()
        .map(|mut row| (row.item, row.outcomes.remove(0)))
        .collect()
}

#[test]
fn changes_are_selected_by_the_branch_they_go_into() {
    let (collection, _) = collect(&repository(3));
    assert_eq!(
        merged_into("default branch", &collection),
        [("github:example/service#2".to_owned(), Outcome::Kept)]
    );
    let into_release = merged_into("release", &collection);
    assert_eq!(into_release.len(), 1);
    assert_eq!(into_release[0].0, "github:example/service#8");
    assert_eq!(merged_into("develop", &collection).len(), 0);

    // a change whose own reading failed has no known branch. it stays in, and
    // nothing can be said of it.
    let mut responses = repository(3);
    responses.insert(
        format!("{API}/pulls/2"),
        (404, r#"{"message":"Not Found"}"#.to_owned()),
    );
    let unknown = merged_into("default branch", &collect(&responses).0);
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].1.label(), "cannot tell");
}

#[test]
fn a_step_can_ask_for_several_actors() {
    let (collection, _) = collect(&repository(3));
    let two = MERGED
        .replace("BRANCH", "default branch")
        .replace("by: someone else", "by: someone else\n    at least: 2");
    let report = checked_with(&two, &collection);
    assert_eq!(
        report.rows[0].outcomes[0],
        Outcome::Broken("merge with 1 approval by someone else (2 needed) before it".into())
    );
    assert!(definition(&two.replace("at least: 2", "at least: 0")).is_err());
}

#[test]
fn a_report_is_json_with_an_outcome_and_a_reason_per_step() {
    let (collection, _) = collect(&repository(3));
    let report = checked_with(&MERGED.replace("BRANCH", "release"), &collection);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["process"], "merged changes");
    assert_eq!(json["selected"]["into"], "release");
    assert_eq!(json["rows"][0]["item"], "github:example/service#8");
    assert_eq!(json["rows"][0]["outcomes"][0]["outcome"], "broken");
    assert_eq!(
        json["rows"][0]["outcomes"][0]["reason"],
        "merge without approval by someone else before it"
    );
}

/// the outcome of one step on change 2, which user 2 opened, user 3 approved
/// at 11:00 on 2026-03-19, and user 2 merged an hour later. `timeline` adds
/// entries to what happened to it, and `step` adds keys to the step.
fn reviewed(
    responses: &mut BTreeMap<String, (u16, String)>,
    timeline: &[String],
    step: &str,
) -> Outcome {
    let mut entries = vec![
        happened(21, "approved", 3, "2026-03-19T11:00:00Z"),
        happened(22, "merged", 2, "2026-03-19T12:00:00Z"),
    ];
    entries.extend_from_slice(timeline);
    responses.insert(
        format!("{API}/issues/2/timeline?per_page=100"),
        (200, format!("[{}]", entries.join(","))),
    );
    let text = MERGED
        .replace("BRANCH", "default branch")
        .replace("    before: merge", &format!("    before: merge\n{step}"));
    let mut report = checked_with(&text, &collect(responses).0);
    assert_eq!(report.rows[0].item, "github:example/service#2");
    report.rows[0].outcomes.remove(0)
}

#[test]
fn an_approval_that_was_taken_back_does_not_count() {
    let mut responses = repository(3);
    assert_eq!(reviewed(&mut responses, &[], ""), Outcome::Kept);
    // someone dismissed the review before the merge.
    let dismissed = format!(
        r#"{{"id":23,"event":"review_dismissed","actor":{},"created_at":"2026-03-19T11:30:00Z","dismissed_review":{{"review_id":21,"state":"approved"}}}}"#,
        user(2)
    );
    assert_eq!(
        reviewed(&mut responses, std::slice::from_ref(&dismissed), "").label(),
        "broken"
    );
    // a dismissal after the merge changes nothing about the merge.
    let late = dismissed.replace("11:30", "12:30");
    assert_eq!(reviewed(&mut responses, &[late], ""), Outcome::Kept);
    // the reviewer asked for changes after approving.
    let requested = r#"{"id":24,"event":"reviewed","state":"changes_requested","user":{"id":3,"login":"user3","type":"User"},"submitted_at":"2026-03-19T11:45:00Z"}"#;
    assert_eq!(
        reviewed(&mut responses, &[requested.to_owned()], "").label(),
        "broken"
    );
}

#[test]
fn an_approval_can_be_required_after_the_last_commit() {
    let committed = |at: &str| {
        format!(r#"{{"event":"committed","sha":"{HEAD}","committer":{{"date":"{at}"}}}}"#)
    };
    let mut responses = repository(3);
    let fresh = reviewed(
        &mut responses,
        &[committed("2026-03-19T10:00:00Z")],
        "    after: commit",
    );
    assert_eq!(fresh, Outcome::Kept);
    let stale = reviewed(
        &mut responses,
        &[committed("2026-03-19T11:30:00Z")],
        "    after: commit",
    );
    assert_eq!(
        stale,
        Outcome::Broken(
            "merge without approval by someone else after the last commit before it".into()
        )
    );
}

#[test]
fn approvals_are_counted_against_what_the_branch_requires() {
    let protection = |approvals: u64| {
        (
            200,
            format!(
                r#"{{"required_pull_request_reviews":{{"required_approving_review_count":{approvals}}},"required_status_checks":{{"contexts":["build"]}}}}"#
            ),
        )
    };
    let step = "    at least: required";
    let mut responses = repository(3);
    responses.insert(format!("{API}/branches/main/protection"), protection(1));
    assert_eq!(reviewed(&mut responses, &[], step), Outcome::Kept);
    responses.insert(format!("{API}/branches/main/protection"), protection(2));
    assert_eq!(
        reviewed(&mut responses, &[], step),
        Outcome::Broken("merge with 1 approval by someone else (2 needed) before it".into())
    );
    // when the rulesets could not be read, more may be required than was
    // read, so a count that meets what was read is not known to be enough.
    responses.insert(format!("{API}/branches/main/protection"), protection(1));
    responses.insert(
        format!("{API}/rules/branches/main?per_page=100"),
        (
            403,
            r#"{"message":"Resource not accessible by integration"}"#.to_owned(),
        ),
    );
    assert_eq!(reviewed(&mut responses, &[], step).label(), "cannot tell");
}

#[test]
fn each_required_check_must_have_passed() {
    let validated = |responses: &BTreeMap<String, (u16, String)>| {
        let text = r"
process: validated changes
items:
  kind: change
  when: merged
steps:
  - name: validated
    event: check passed
    of: required checks
    before: merge
";
        checked_with(text, &collect(responses).0)
            .rows
            .into_iter()
            .map(|mut row| (row.item, row.outcomes.remove(0)))
            .collect::<BTreeMap<_, _>>()
    };
    let requiring = |contexts: &str| {
        (
            200,
            format!(r#"{{"required_status_checks":{{"contexts":[{contexts}]}}}}"#),
        )
    };
    let mut responses = repository(3);
    // the branch requires nothing, so there is nothing to have passed.
    let found = validated(&responses);
    assert_eq!(found["github:example/service#2"].label(), "n/a");
    assert_eq!(found["github:example/service#8"].label(), "n/a");

    responses.insert(
        format!("{API}/branches/main/protection"),
        requiring(r#""build""#),
    );
    assert_eq!(
        validated(&responses)["github:example/service#2"],
        Outcome::Kept
    );
    // a passing check with another name does not stand in for a required one.
    responses.insert(
        format!("{API}/branches/main/protection"),
        requiring(r#""build","deploy""#),
    );
    assert_eq!(
        validated(&responses)["github:example/service#2"],
        Outcome::Broken("no check passed for deploy before the merge".into())
    );
    // a change into another branch is held to that branch's requirements.
    // change 8's check passed only after it was merged.
    responses.insert(
        format!("{API}/branches/release/protection"),
        requiring(r#""build""#),
    );
    assert_eq!(
        validated(&responses)["github:example/service#8"],
        Outcome::Broken("no check passed for build before the merge".into())
    );
}

#[test]
fn a_step_that_cannot_be_checked_is_refused_when_it_is_read() {
    let step = |extra: &str| {
        definition(&format!(
            "process: p\nitems:\n  kind: change\nsteps:\n  - name: s\n    event: approval\n{extra}"
        ))
    };
    assert!(step("    at least: required\n").is_ok());
    assert!(step("    at least: some\n").is_err());
    assert!(step("    of: required checks\n    before: merge\n").is_ok());
    assert!(step("    of: required checks\n    within: 7d\n").is_err());
    assert!(step("    of: optional checks\n").is_err());
}

#[test]
fn a_change_is_held_to_the_policy_read_closest_after_its_merge() {
    let protection = |approvals: u64| {
        (
            200,
            format!(
                r#"{{"required_pull_request_reviews":{{"required_approving_review_count":{approvals}}}}}"#
            ),
        )
    };
    let text = MERGED.replace("BRANCH", "default branch").replace(
        "    before: merge",
        "    at least: required\n    before: merge",
    );
    let reviewed = |collection: &Collection, earlier: &[Collection]| {
        let report = process::check(&definition(&text).unwrap(), collection, earlier).unwrap();
        report.rows[0].outcomes[0].clone()
    };
    let read_at = |at: &str, approvals: u64| {
        let mut responses = repository(3);
        responses.insert(
            format!("{API}/branches/main/protection"),
            protection(approvals),
        );
        let (mut collection, _) = collect(&responses);
        collection.contents.completed_at = at.into();
        collection
    };
    // change 2 was merged on 19 march with one approval. today the branch
    // requires two.
    let today = read_at(NOW, 2);
    assert_eq!(reviewed(&today, &[]).label(), "broken");
    // a reading on 20 march found that one was required then. it is closer to
    // the merge, and the one before the merge agrees with it.
    let after = read_at("2026-03-20T00:00:00Z", 1);
    let before = read_at("2026-03-18T00:00:00Z", 1);
    assert_eq!(reviewed(&today, &[before, after.clone()]), Outcome::Kept);
    // when the readings on both sides of the merge differ, the policy at the
    // merge is not known.
    let stricter = read_at("2026-03-18T00:00:00Z", 2);
    assert_eq!(reviewed(&today, &[stricter, after]).label(), "cannot tell");
}

#[test]
fn a_commit_listed_after_a_reviewed_one_was_added_after_that_review() {
    // the second commit was made before the approval and pushed after it:
    // the approval names the first commit, and the timeline lists the second
    // after it.
    let committed = |sha: &str, at: &str| {
        format!(r#"{{"event":"committed","sha":"{sha}","committer":{{"date":"{at}"}}}}"#)
    };
    let approval = r#"{"id":21,"event":"reviewed","state":"approved","commit_id":"aaa","user":{"id":3,"login":"user3","type":"User"},"submitted_at":"2026-03-19T11:00:00Z"}"#;
    let mut responses = repository(3);
    responses.insert(
        format!("{API}/issues/2/timeline?per_page=100"),
        (
            200,
            format!(
                "[{}]",
                [
                    committed("aaa", "2026-03-19T09:00:00Z"),
                    approval.to_owned(),
                    committed("bbb", "2026-03-19T10:00:00Z"),
                    happened(22, "merged", 2, "2026-03-19T12:00:00Z"),
                ]
                .join(",")
            ),
        ),
    );
    let text = MERGED
        .replace("BRANCH", "default branch")
        .replace("    before: merge", "    after: commit\n    before: merge");
    let report = checked_with(&text, &collect(&responses).0);
    assert_eq!(report.rows[0].outcomes[0].label(), "broken");
}

const ALL_MERGED: &str = r"
process: merged changes
items:
  kind: change
  when: merged
";

#[test]
fn changes_are_selected_by_the_files_they_touch() {
    let definition = format!("{ALL_MERGED}  paths: src/auth/**\nsteps:\n  - name: reviewed\n    event: approval\n    by: someone else\n    before: merge\n");
    let mut responses = repository(3);
    let (collection, _) = collect(&responses);
    let report = checked_with(&definition, &collection);
    // change 8 touches the readme alone.
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].item, "github:example/service#2");
    assert_eq!(labels(&report.rows[0]), ["kept"]);
    assert!(process::render(&report).contains("1 touching src/auth/**"));
    // a renamed file counts under the name it had.
    let renamed = definition.replace("src/auth/**", "'*.txt'");
    assert_eq!(checked_with(&renamed, &collection).rows.len(), 1);

    // a change whose files could not be read stays in, and nothing is said of it.
    responses.insert(
        format!("{API}/pulls/2/files?per_page=100"),
        (403, r#"{"message":"Resource not accessible"}"#.to_owned()),
    );
    let (collection, _) = collect(&responses);
    let report = checked_with(&definition, &collection);
    assert_eq!(report.rows.len(), 1);
    assert_eq!(labels(&report.rows[0]), ["cannot tell"]);
}

#[test]
fn a_step_can_ask_for_checks_by_name() {
    let (collection, _) = collect(&repository(3));
    let step = |names: &str| {
        format!("{ALL_MERGED}steps:\n  - name: scanned\n    event: check passed\n    named: {names}\n    before: merge\n")
    };
    let report = checked_with(&step("build"), &collection);
    let found = report
        .rows
        .iter()
        .map(|row| {
            (
                row.item.rsplit('#').next().unwrap(),
                row.outcomes[0].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(found["2"], Outcome::Kept);
    // the check on change 8 passed only after the merge.
    assert_eq!(
        found["8"],
        Outcome::Broken("merge without check passed named build before it".into())
    );
    // every name must have its own check. `docs` was skipped.
    let report = checked_with(&step("[build, docs]"), &collection);
    assert!(report
        .rows
        .iter()
        .all(|row| row.outcomes[0].label() == "broken"));
    assert_eq!(
        labels(&checked_with(&step("'b*'"), &collection).rows[0]),
        ["broken"]
    );
}

#[test]
fn a_step_can_ask_for_named_accounts() {
    let (collection, _) = collect(&repository(3));
    let step = |accounts: &str| {
        format!("{ALL_MERGED}  paths: src/**\nsteps:\n  - name: signed off\n    event: approval\n    by: [{accounts}]\n    before: merge\n")
    };
    assert_eq!(
        labels(&checked_with(&step("user9, User3"), &collection).rows[0]),
        ["kept"]
    );
    let report = checked_with(&step("user9"), &collection);
    assert_eq!(
        report.rows[0].outcomes[0],
        Outcome::Broken("merge without approval by user9 before it".into())
    );
    // the author's own approval does not count, even when the author is named.
    let (collection, _) = collect(&repository(2));
    assert_eq!(
        labels(&checked_with(&step("user2"), &collection).rows[0]),
        ["broken"]
    );
}

#[test]
fn a_step_can_ask_for_a_label() {
    let (collection, _) = collect(&repository(3));
    let definition = "process: classified\nitems:\n  kind: ticket\nsteps:\n  - name: classified\n    label: ['sec*', bug]\n";
    let report = checked_with(definition, &collection);
    let found = report
        .rows
        .iter()
        .map(|row| {
            (
                row.item.rsplit('#').next().unwrap(),
                row.outcomes[0].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(found["1"], Outcome::Kept);
    // the labels that select items are patterns as well.
    let selected = checked_with(
        "process: p\nitems:\n  kind: ticket\n  label: ['sec*', question]\nsteps:\n  - name: closed\n    event: closed\n",
        &collection,
    );
    assert_eq!(selected.rows.len(), 5);
    assert!(process::render(&selected).contains("5 labelled \"sec*\" or \"question\""));
    // ticket 6 is labelled `question` and still open.
    assert_eq!(
        found["6"],
        Outcome::Pending("no label sec* or bug yet".into())
    );
}

#[test]
fn releases_are_read_with_what_is_attached_to_them() {
    let (collection, _) = collect(&repository(3));
    let releases = collection
        .statement_about("github:example/service", "releases")
        .unwrap();
    // the draft and the release published before the period are left out.
    assert_eq!(
        releases.reading.value().unwrap()["members"],
        serde_json::json!(["github.com/release/92"])
    );
    let step = |pattern: &str| {
        format!("process: releases\nitems:\n  kind: release\nsteps:\n  - name: has a bill of materials\n    asset: '{pattern}'\n  - name: published by a maintainer\n    event: published\n    by: [user2]\n")
    };
    let report = checked_with(&step("*.cdx.json"), &collection);
    assert_eq!(report.rows[0].item, "github:example/service release v1.2.0");
    assert_eq!(labels(&report.rows[0]), ["kept", "kept"]);
    assert!(process::render(&report).contains("releases published 2026-01-01T00:00:00Z"));
    let report = checked_with(&step("*.sig"), &collection);
    assert_eq!(
        report.rows[0].outcomes[0],
        Outcome::Broken("no attached file *.sig".into())
    );
}

#[test]
fn a_process_can_ask_for_numbers() {
    let (collection, _) = collect(&repository(3));
    let definition = format!("{DEFINITION}measures:\n  - name: answered in time\n    share: answered\n  - name: time to close\n    from: opened\n    to: closed\n");
    let report = checked_with(&definition, &collection);
    // of the four tickets one was answered in time and one was not. the
    // other two are pending or unknown.
    assert_eq!(report.measures[0].value, Some(50.0));
    assert_eq!(
        report.measures[0].basis,
        "1 of 2 kept; 2 pending, unknown, or not applicable left out"
    );
    // ticket 1 was closed nineteen days and seven hours after it was opened.
    assert_eq!(report.measures[1].value, Some(463.0));
    let rendered = process::render(&report);
    assert!(rendered.contains("answered in time  50% (1 of 2 kept"));
    assert!(rendered
        .contains("time to close     19.3 days (median from opened to closed over 1 of 4 items)"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["measures"][1]["unit"], "hours");
}

#[test]
fn the_new_keys_are_refused_where_they_cannot_be_checked() {
    let refused = |text: &str, why: &str| {
        let error = definition(text).unwrap_err().to_string();
        assert!(error.contains(why), "{error}");
    };
    refused(
        &format!("{ALL_MERGED}steps:\n  - name: s\n    label: a\n    event: approval\n"),
        "exactly one of",
    );
    refused(
        &format!("{ALL_MERGED}steps:\n  - name: s\n    label: a\n    within: 7d\n"),
        "stand alone",
    );
    refused(
        &format!(
            "{ALL_MERGED}steps:\n  - name: s\n    event: check passed\n    named: a\n    at least: 2\n"
        ),
        "`named` cannot be used",
    );
    refused(
        &format!("{ALL_MERGED}measures:\n  - name: m\n    share: nothing\n"),
        "no step named",
    );
    refused(
        &format!("{ALL_MERGED}measures:\n  - name: m\n    from: opened\n"),
        "use `share`",
    );
}

/// a pack that runs in the test: it answers from what it is shown.
struct Sample;

impl divinate::pack::Packs for Sample {
    fn call(&self, pack: &str, request: &serde_json::Value) -> Result<serde_json::Value> {
        use serde_json::json;
        assert_eq!(pack, "sample");
        assert_eq!(request["protocol"], 1);
        if request["request"] == "describe" {
            return Ok(json!({
                "protocol": 1,
                "name": "sample",
                "version": "1.2.3",
                "checks": [
                    {"name": "names a ticket", "answers": "each_item"},
                    {"name": "enough work", "answers": "all_items"},
                    {"name": "comments", "answers": "number"},
                ],
            }));
        }
        let items = request["items"].as_array().unwrap();
        Ok(match request["check"].as_str().unwrap() {
            "names a ticket" => json!({
                "results": items.iter().map(|item| {
                    let description = item["state"]["description"].as_str().unwrap_or_default();
                    if description.contains(request["with"]["word"].as_str().unwrap()) {
                        json!({"item": item["id"], "outcome": "kept"})
                    } else {
                        json!({"item": item["id"], "outcome": "broken", "reason": "its description names no ticket"})
                    }
                }).collect::<Vec<_>>(),
            }),
            "enough work" => json!({
                "outcome": "broken",
                "reason": format!("{} items in {}", items.len(), request["collection"]["scope"].as_str().unwrap()),
            }),
            _ => json!({
                "value": items.iter().map(|item| {
                    // an item whose events could not be read has none to show.
                    item["events"].as_array().into_iter().flatten().filter(|event| event["kind"] == "comment").count()
                }).sum::<usize>(),
                "unit": "comments",
                "basis": "all of them",
            }),
        })
    }
}

fn judged(text: &str, collection: &Collection) -> Result<process::Report> {
    process::check_with(&definition(text)?, collection, &[], &Sample)
}

#[test]
fn a_pack_judges_each_item_all_items_together_and_numbers() {
    let (collection, _) = collect(&repository(3));
    let text = format!("{ALL_MERGED}steps:\n  - name: traced\n    ref: policy 4.2\n    uses: sample/names a ticket\n    with:\n      word: Fixes\noverall:\n  - name: busy enough\n    uses: sample/enough work\n");
    let report = judged(&text, &collection).unwrap();
    let found = report
        .rows
        .iter()
        .map(|row| {
            (
                row.item.rsplit('#').next().unwrap(),
                row.outcomes[0].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(found["2"], Outcome::Kept);
    assert_eq!(
        found["8"],
        Outcome::Broken("its description names no ticket".into())
    );
    assert_eq!(
        report.overall[0].outcome,
        Outcome::Broken("2 items in github:example/service".into())
    );
    assert_eq!(report.packs, ["sample 1.2.3"]);
    let rendered = process::render(&report);
    assert!(rendered.contains("busy enough  broken"));
    assert!(rendered.contains("references\n  traced  policy 4.2"));
    assert!(rendered.contains("packs: sample 1.2.3"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["overall"][0]["outcome"], "broken");

    // a pack is shown the tickets with what happened to them, and with a
    // linked step the changes that close them.
    let tickets = format!("{DEFINITION}  - name: fix traced\n    linked: change\n    uses: sample/names a ticket\n    with:\n      word: Fixes\nmeasures:\n  - name: discussion\n    uses: sample/comments\n");
    let report = judged(&tickets, &collection).unwrap();
    assert_eq!(report.rows[0].outcomes[3], Outcome::Kept);
    assert_eq!(report.rows[1].outcomes[3].label(), "n/a");
    // ticket 4 could not be read, and has no events to count.
    assert_eq!(report.measures[0].value, Some(2.0));
    assert_eq!(report.measures[0].unit, "comments");
}

#[test]
fn a_pack_is_asked_only_for_what_it_offers() {
    let (collection, _) = collect(&repository(3));
    let refused = |text: &str, why: &str| {
        let error = judged(text, &collection).unwrap_err().to_string();
        assert!(error.contains(why), "{error}");
    };
    refused(
        &format!("{ALL_MERGED}steps:\n  - name: s\n    uses: sample/nothing\n"),
        "has no check \"nothing\"",
    );
    refused(
        &format!("{ALL_MERGED}steps:\n  - name: s\n    uses: sample/enough work\n"),
        "belongs in `overall`, not in a step",
    );
    // without packs, a definition that uses one cannot be checked.
    let text = format!("{ALL_MERGED}steps:\n  - name: s\n    uses: sample/names a ticket\n");
    let error = process::check(&definition(&text).unwrap(), &collection, &[]).unwrap_err();
    assert!(error.to_string().contains("no packs are available"));
    assert!(definition(&format!(
        "{ALL_MERGED}steps:\n  - name: s\n    uses: sample/x\n    event: merge\n"
    ))
    .is_err());
}

/// a pack as a shell script. it calls itself what `PACK_NAME` says, judges by
/// whether it can see `DIVINATE_TEST_SECRET`, and as a source reads one thing.
#[cfg(unix)]
const SCRIPT: &str = r#"#!/bin/sh
request=$(cat)
case "$request" in
  *'"request":"describe"'*)
    printf '%s\n' '{"protocol":1,"name":"'"$PACK_NAME"'","version":"0.1.0","collects":{"scopes":"'"$PACK_NAME"':<thing>"},"checks":[{"name":"clean","answers":"all_items"}],"processes":[{"name":"merged","definition":"process: merged\nitems:\n  kind: change\n  when: merged\noverall:\n  - name: clean\n    uses: '"$PACK_NAME"'/clean\n"}]}' ;;
  *'"request":"collect"'*)
    printf '%s\n' '{"readings":[{"resource":"'"$PACK_NAME"'/thing/v1","subject":"'"$PACK_NAME"':thing","captured_at":"2026-03-27T00:00:00Z","exchanges":[{"request":{"method":"POST","url":"https://example.test/query","body":"{}"},"response":{"status":200,"body":"{\"n\":1,\"seen\":\"'"$DIVINATE_TEST_SECRET"'\"}"}}],"termination":{"kind":"exhausted"}}]}' ;;
  *'"request":"derive"'*)
    id=$(printf '%s' "$request" | sed 's/.*"id":"\(acq_[0-9a-f]*\)".*/\1/')
    case "$request" in *'"setup"'*) exit 3 ;; esac
    printf '%s\n' '{"entities":[{"uid":"'"$PACK_NAME"'/thing/1","class":"scope","kind":"repository","native_kind":"thing","name":"'"$PACK_NAME"':thing"}],"statements":[{"about":"'"$PACK_NAME"'/thing/1","aspect":"repository","value":{"visibility":"public","default_branch":"main","archived":false,"fork":false},"transcripts":["'"$id"'"]}]}' ;;
  *)
    if [ -n "$DIVINATE_TEST_SECRET" ]; then
      echo '{"outcome":"broken","reason":"the environment was passed on"}'
    else
      echo '{"outcome":"kept"}'
    fi ;;
esac
"#;

/// a directory with the script and a configuration that declares it twice:
/// once given nothing, and once given the secret.
#[cfg(unix)]
fn configured() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pack.sh");
    fs::write(&path, SCRIPT).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let config = directory.path().join("divinate.yaml");
    fs::write(
        &config,
        "packs:\n  sample:\n    command: ./pack.sh\n    env:\n      PACK_NAME: sample\n    setup:\n      anything: 1\n  trusted:\n    command: ./pack.sh\n    inherit: [DIVINATE_TEST_SECRET]\n    env:\n      PACK_NAME: trusted\n  misnamed:\n    command: ./pack.sh\n    env:\n      PACK_NAME: sample\n  slow:\n    command: sleep\n    args: ['5']\n    timeout_seconds: 1\n",
    )
    .unwrap();
    std::env::set_var("DIVINATE_TEST_SECRET", "a-secret-value");
    (directory, config)
}

#[cfg(unix)]
#[test]
fn a_configured_pack_is_given_only_the_environment_its_entry_names() {
    let (_directory, config) = configured();
    let packs = divinate::pack::Configured::load(Some(&config)).unwrap();
    let (collection, _) = collect(&repository(3));
    let overall = |pack: &str| {
        let found = divinate::pack::describe(&packs, pack).unwrap();
        let shipped = process::parse(&found.processes[0].definition, &config).unwrap();
        let report = process::check_with(&shipped, &collection, &[], &packs).unwrap();
        report.overall[0].outcome.label()
    };
    assert_eq!(overall("sample"), "kept");
    assert_eq!(overall("trusted"), "broken");

    let refused = |pack: &str, why: &str| {
        let error = divinate::pack::describe(&packs, pack)
            .unwrap_err()
            .to_string();
        assert!(error.contains(why), "{error}");
    };
    refused("other", "is not configured");
    refused("misnamed", "calls itself \"sample\"");
    refused("slow", "did not answer within 1 seconds");
    // a configuration with a key it does not know is refused.
    fs::write(&config, "packs:\n  sample:\n    comand: x\n").unwrap();
    assert!(divinate::pack::Configured::load(Some(&config)).is_err());
}

#[cfg(unix)]
#[test]
fn a_pack_can_be_a_source_whose_readings_are_kept_and_verified() {
    let (directory, config) = configured();
    let config = config.to_str().unwrap();
    let state = directory.path().join("evidence");
    let run = |arguments: &[&str]| divinate(&state, arguments);

    let (ok, collected) = run(&["--config", config, "collect", "sample:thing"]);
    assert!(ok, "{collected}");
    assert!(collected.contains("collected sample:thing: 1 records, 0 gaps"));
    let (_, shown) = run(&["--config", config, "show"]);
    assert!(shown.contains("sample:thing\n  ■ repository  public, default branch main"));
    let stored = record::load(&state).unwrap();
    let stamp = stored[0].contents.pack.as_ref().unwrap();
    assert_eq!(
        (stamp.name.as_str(), stamp.version.as_str()),
        ("sample", "0.1.0")
    );
    // what the pack sent is kept with what it got back.
    let transcript = record::load_transcript(&state, &stored[0].contents.transcripts[0]).unwrap();
    assert_eq!(
        transcript.contents.exchanges[0].request.body.as_deref(),
        Some("{}")
    );

    // with the pack at hand the collection is derived again. without it the
    // bytes are checked, and the collection is named.
    let (ok, verified) = run(&["--config", config, "verify"]);
    assert!(
        ok && verified.trim() == "verified 1 collections and 1 transcripts",
        "{verified}"
    );
    let (ok, verified) = run(&["verify"]);
    assert!(ok, "{verified}");
    assert!(verified
        .contains("derived by the pack sample 0.1.0, which is not configured here; bytes checked"));

    // a pack that hands back the credential it was given has nothing kept.
    let (ok, refused) = run(&["--config", config, "collect", "trusted:thing"]);
    assert!(
        !ok && refused.contains("repeats a credential it was given"),
        "{refused}"
    );
    assert_eq!(record::load(&state).unwrap().len(), 1);
    // a scope that names neither a source nor a pack is refused as before.
    let (ok, unknown) = run(&["--config", config, "collect", "nothing:thing"]);
    assert!(!ok && unknown.contains("a scope is one of"), "{unknown}");
}

/// run the divinate binary on a state directory and return what it printed.
fn divinate(state: &std::path::Path, arguments: &[&str]) -> (bool, String) {
    let examples = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/divinate.yaml");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_divinate"));
    // the packs of the examples, unless the arguments name a configuration.
    if arguments[0] != "--config" {
        command.arg("--config").arg(examples);
    }
    command.args(arguments);
    // `pack` reads no record.
    if !arguments.contains(&"pack") {
        command.arg("--state").arg(state);
    }
    let output = command.output().unwrap();
    let mut printed = String::from_utf8(output.stdout).unwrap();
    printed.push_str(&String::from_utf8(output.stderr).unwrap());
    (output.status.success(), printed)
}

#[test]
fn the_commands_read_a_stored_record() {
    let (collection, transcripts) = collect(&repository(3));
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("evidence");
    record::store(&state, &collection, &transcripts).unwrap();
    let file = directory.path().join("security-tickets.yaml");
    fs::write(&file, DEFINITION).unwrap();
    let file = file.to_str().unwrap();

    let (ok, shown) = divinate(&state, &["show"]);
    assert!(ok, "{shown}");
    assert!(shown.contains("■ releases                1 release"));
    assert!(divinate(&state, &["show", &collection.id]).0);
    let (ok, shown) = divinate(&state, &["show", "col_none"]);
    assert!(!ok && shown.contains("error: no collection col_none"));
    let (ok, ledger) = divinate(&state, &["ledger"]);
    assert!(ok && ledger.contains("review policy"), "{ledger}");

    let (ok, checked) = divinate(&state, &["check", file]);
    assert!(ok, "{checked}");
    assert!(checked.contains("answered      1 kept, 1 broken, 1 pending, 1 cannot tell"));
    let (_, summary) = divinate(&state, &["check", file, "--all"]);
    assert!(summary.contains("github:example/service · as of 2026-03-27T00:00:00Z"));
    let (_, summary) = divinate(&state, &["check", file, "--last", "3"]);
    assert!(summary.contains("fix reviewed  1 kept, 3 n/a"));
    let (_, json) = divinate(&state, &["check", file, "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["rows"][0]["outcomes"][0]["outcome"], "kept");
    let (ok, missing) = divinate(&state, &["check", "nothing.yaml"]);
    assert!(!ok && missing.contains("nothing.yaml"));

    let (ok, verified) = divinate(&state, &["verify"]);
    assert!(
        ok && verified.starts_with("verified 1 collections and"),
        "{verified}"
    );
}

/// the example pack is a python script. where there is no python, there is
/// nothing to run.
#[cfg(unix)]
#[test]
fn the_example_pack_checks_the_checklist_in_a_description() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let mut responses = repository(3);
    let listing = responses
        .keys()
        .find(|url| url.contains("/issues?"))
        .unwrap()
        .clone();
    let (status, body) = responses[&listing].clone();
    // change 2 gets a checklist with one box left open.
    let body = body.replace("Fixes #1", r"Fixes #1\n\n- [x] tests\n- [ ] docs");
    responses.insert(listing, (status, body));
    let (collection, transcripts) = collect(&responses);
    let directory = tempfile::tempdir().unwrap();
    record::store(directory.path(), &collection, &transcripts).unwrap();

    let (ok, offered) = divinate(directory.path(), &["pack", "checklist"]);
    assert!(ok, "{offered}");
    assert!(offered.contains("checklist/completed  for a step. every box is checked"));
    assert!(offered.contains("checklist:merged  merged changes have a completed checklist"));
    let (ok, checked) = divinate(directory.path(), &["check", "checklist:merged"]);
    assert!(ok, "{checked}");
    assert!(checked.contains("checklist completed: broken, 1 of 2 boxes are not checked"));
    assert!(checked.contains("checklist completed: broken, the description has no checklist"));
    assert!(checked.contains("completed share  0% (0 of 2 items)"));
    assert!(checked.contains("packs: checklist 0.1.0"));
    let (ok, missing) = divinate(directory.path(), &["check", "checklist:nothing"]);
    assert!(!ok && missing.contains("ships no process definition \"nothing\"; it has: merged"));
}

const MAPPED: &str = r"
process: reviewed changes
frameworks:
  policy:
    title: our change policy
    targets:
      '4.10': emergency changes
      '4.2': review
      '4.3': testing
items:
  kind: change
  when: merged
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
    maps:
      - framework: policy
        target: '4.2'
        strength: partial
        limitation: that the reviewer understood the change
branches:
  - name: review required
    approvals: 1
    maps:
      - framework: policy
        target: '4.2'
        strength: full
";

#[test]
fn rules_map_to_the_requirements_of_a_framework() {
    let (collection, _) = collect(&repository(3));
    let report = checked_with(MAPPED, &collection);
    let policy = &report.frameworks[0];
    assert_eq!(policy.title.as_deref(), Some("our change policy"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["frameworks"][0]["targets"][1]["contributions"][0]["strength"],
        "partial"
    );
    // requirements are listed as people number them, and one that no rule
    // speaks to is listed as such.
    assert_eq!(
        process::coverage(&[report]),
        "\nour change policy\n  4.2 review\n    reviewed (partial): 1 kept, 1 broken\n      does not establish: that the reviewer understood the change\n    review required (full): 2 broken\n  4.3 testing: no rule\n  4.10 emergency changes: no rule\n"
    );

    // a second definition that names the same framework adds to the same list.
    let tested = "process: tested changes\nframeworks:\n  policy:\n    targets:\n      '4.3': testing\nitems:\n  kind: change\n  when: merged\nsteps:\n  - name: tested\n    event: check passed\n    before: merge\n    maps:\n      - framework: policy\n        target: '4.3'\n        strength: full\n";
    let both = [
        checked_with(MAPPED, &collection),
        checked_with(tested, &collection),
    ];
    let coverage = process::coverage(&both);
    assert!(coverage.contains("  4.3 testing\n    tested (full): 1 kept, 1 broken\n"));
    assert!(coverage.contains("  4.10 emergency changes: no rule\n"));

    let unknown = definition(&MAPPED.replace(
        "target: '4.2'\n        strength: full",
        "target: '9.9'\n        strength: full",
    ));
    assert!(unknown
        .unwrap_err()
        .to_string()
        .contains("which `frameworks` does not declare"));
    assert!(definition(&MAPPED.replace("strength: full", "strength: strong")).is_err());
}

#[test]
fn several_definitions_are_checked_in_one_run() {
    let (collection, transcripts) = collect(&repository(3));
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("evidence");
    record::store(&state, &collection, &transcripts).unwrap();
    let write = |name: &str, text: &str| {
        let path = directory.path().join(name);
        fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let (tickets, mapped) = (
        write("tickets.yaml", DEFINITION),
        write("mapped.yaml", MAPPED),
    );
    let (ok, printed) = divinate(&state, &["check", &tickets, &mapped]);
    assert!(ok, "{printed}");
    assert!(printed.contains("security tickets · github:example/service"));
    assert!(printed.contains("reviewed changes · github:example/service"));
    assert!(printed.ends_with("  4.3 testing: no rule\n  4.10 emergency changes: no rule\n"));
    let (_, json) = divinate(&state, &["check", &tickets, &mapped, "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);
    let (_, summary) = divinate(&state, &["check", &tickets, &mapped, "--all"]);
    assert!(summary.contains("security tickets\n") && summary.contains("reviewed changes\n"));
}
