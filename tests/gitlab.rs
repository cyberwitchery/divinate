//! a gitlab project read with its issues and merge requests, checked with the
//! same process definition a github repository is checked with.

use std::collections::BTreeMap;
use std::fs;

use divinate::facts::summary;
use divinate::model::aspect;
use divinate::process::{self, Outcome};
use divinate::record::{self, Collection};
use divinate::source;
use divinate::transcript::Transcript;
use divinate::verify;

mod common;

const API: &str = "https://gitlab.com/api/v4";
const NOW: &str = "2026-03-27T00:00:00Z";
const OPENED: &str = "created_after=2026-01-01T00%3A00%3A00Z&created_before=2026-03-27T00%3A00%3A00Z&order_by=created_at&sort=asc&per_page=100";

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

type Responses = BTreeMap<String, (u16, String)>;

fn user(id: u64) -> String {
    format!(r#"{{"id":{id},"username":"user{id}"}}"#)
}

/// a project with one security issue, answered, closed, and closed by a merge
/// request that `approver` approved.
fn project(approver: u64) -> Responses {
    let base = format!("{API}/projects/7");
    let issue = format!(
        r#"{{"id":101,"iid":1,"title":"t","state":"closed","labels":["security"],"author":{},"created_at":"2026-03-01T09:00:00.000Z","closed_at":"2026-03-20T16:00:00.000Z"}}"#,
        user(1)
    );
    let merge_request = format!(
        r#"{{"id":202,"iid":2,"project_id":7,"title":"c","state":"merged","labels":[],"author":{},"created_at":"2026-03-02T09:00:00.000Z","merged_at":"2026-03-19T12:00:00.000Z","closed_at":null,"target_branch":"main","sha":"3f467b9e7ed6241bf3052cdccd47f4c2aec6c924","merge_commit_sha":"af56d96fdbd7c26e9fc94336b6f50dcc6ceff484","squash_commit_sha":null,"references":{{"full":"example/platform/service!2"}}}}"#,
        user(2)
    );
    let ok = |body: String| (200, body);
    BTreeMap::from([
        (format!("{API}/groups/example%2Fplatform%2Fservice?with_projects=false"), (404, r#"{"message":"404 Group Not Found"}"#.to_owned())),
        (format!("{API}/projects/example%2Fplatform%2Fservice"), ok(r#"{"id":7,"path_with_namespace":"example/platform/service","namespace":{"id":3,"kind":"group","full_path":"example/platform"},"visibility":"private","archived":false,"default_branch":"main","only_allow_merge_if_pipeline_succeeds":true}"#.to_owned())),
        (format!("{base}/protected_branches?per_page=100"), ok("[]".to_owned())),
        (format!("{base}/approvals"), ok(r#"{"approvals_before_merge":0}"#.to_owned())),
        (format!("{base}/approval_rules?per_page=100"), ok("[]".to_owned())),
        (format!("{base}/issues?scope=all&{OPENED}"), ok(format!("[{issue}]"))),
        (format!("{base}/merge_requests?scope=all&state=all&{OPENED}"), ok(format!("[{merge_request}]"))),
        (format!("{base}/issues/1/notes?sort=asc&per_page=100"), ok(format!(
            r#"[{{"id":11,"system":true,"body":"changed the description","author":{},"created_at":"2026-03-01T09:05:00.000Z"}},{{"id":12,"system":false,"body":"on it","author":{},"created_at":"2026-03-03T10:00:00.000Z"}}]"#,
            user(1), user(3)
        ))),
        (format!("{base}/issues/1/resource_state_events?per_page=100"), ok(format!(
            r#"[{{"id":13,"state":"closed","user":{},"created_at":"2026-03-20T16:00:00.000Z"}}]"#, user(2)
        ))),
        (format!("{base}/issues/1/closed_by?per_page=100"), ok(format!("[{merge_request}]"))),
        (format!("{base}/merge_requests/2/notes?sort=asc&per_page=100"), ok("[]".to_owned())),
        (format!("{base}/merge_requests/2/resource_state_events?per_page=100"), ok(format!(
            r#"[{{"id":21,"state":"merged","user":{},"created_at":"2026-03-19T12:00:00.000Z"}}]"#, user(2)
        ))),
        (format!("{base}/merge_requests?scope=all&state=merged&updated_after=2026-01-01T00%3A00%3A00Z&order_by=updated_at&sort=asc&per_page=100"), ok(format!("[{merge_request}]"))),
        (format!("{base}/merge_requests/2/pipelines?per_page=100"), ok(r#"[{"id":32,"sha":"3f467b9e7ed6241bf3052cdccd47f4c2aec6c924","ref":"fix","source":"schedule","status":"failed","created_at":"2026-03-19T09:40:00.000Z","updated_at":"2026-03-19T09:50:00.000Z"},{"id":31,"sha":"3f467b9e7ed6241bf3052cdccd47f4c2aec6c924","ref":"fix","source":"merge_request_event","status":"success","created_at":"2026-03-19T09:00:00.000Z","updated_at":"2026-03-19T09:30:00.000Z"},{"id":30,"sha":"1111111111111111111111111111111111111111","ref":"fix","status":"failed","created_at":"2026-03-18T09:00:00.000Z","updated_at":"2026-03-18T09:30:00.000Z"}]"#.to_owned())),
        // the first push merged the merge request, the second went around one,
        // and the third was to another branch.
        (format!("{base}/events?action=pushed&after=2025-12-31&before=2026-03-28&sort=asc&per_page=100"), ok(format!(
            r#"[{{"id":41,"action_name":"pushed to","author":{by},"created_at":"2026-03-19T12:00:00.000Z","push_data":{{"action":"pushed","ref_type":"branch","ref":"main","commit_to":"af56d96fdbd7c26e9fc94336b6f50dcc6ceff484"}}}},{{"id":42,"action_name":"pushed to","author":{by},"created_at":"2026-02-10T12:00:00.000Z","push_data":{{"action":"pushed","ref_type":"branch","ref":"main","commit_to":"2adc745e20d7a07fb7f177853d3e78a95b007aef"}}}},{{"id":43,"action_name":"pushed to","author":{by},"created_at":"2026-02-11T12:00:00.000Z","push_data":{{"action":"pushed","ref_type":"branch","ref":"fix","commit_to":"3f467b9e7ed6241bf3052cdccd47f4c2aec6c924"}}}}]"#,
            by = user(2)
        ))),
        (format!("{base}/merge_requests/2/diffs?per_page=100"), ok(r#"[{"old_path":"auth/login.rb","new_path":"auth/login.rb","diff":"@@"},{"old_path":"docs/old.md","new_path":"docs/new.md","diff":"@@"}]"#.to_owned())),
        (format!("{base}/releases?per_page=100"), ok(r#"[{"tag_name":"v2.0.0","name":"two","released_at":"2026-03-20T10:00:00.000Z","upcoming_release":false,"author":{"id":2,"username":"user2"},"assets":{"links":[{"id":1,"name":"sbom","url":"https://example.test/sbom.json","link_type":"other"}]}}]"#.to_owned())),
        (format!("{base}/pipelines/31/jobs?per_page=100"), ok(r#"[{"id":313,"name":"deploy","status":"manual","finished_at":null},{"id":312,"name":"secret-scan","status":"failed","finished_at":"2026-03-19T09:20:00.000Z"},{"id":311,"name":"sast","status":"success","finished_at":"2026-03-19T09:25:00.000Z"}]"#.to_owned())),
        (format!("{base}/merge_requests/2/approvals"), ok(format!(
            r#"{{"approved_by":[{{"user":{},"approved_at":"2026-03-19T11:00:00.000Z"}}]}}"#, user(approver)
        ))),
    ])
}

fn collect(responses: &Responses) -> (Collection, Vec<Transcript>) {
    common::collect(
        "gitlab:example/platform/service",
        "2026-01-01T00:00:00Z",
        NOW,
        |url| common::answer(responses.get(url), url),
    )
}

fn outcomes(collection: &Collection) -> Vec<&'static str> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("process.yaml");
    fs::write(&path, DEFINITION).unwrap();
    let report = process::check(&process::load(&path).unwrap(), collection, &[]).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].item, "gitlab:example/platform/service#1");
    report.rows[0].outcomes.iter().map(Outcome::label).collect()
}

#[test]
fn a_project_is_read_when_the_path_names_no_group() {
    let (collection, transcripts) = collect(&project(3));
    let derived = &collection.contents.derived;
    let service = derived.named("gitlab:example/platform/service").unwrap();
    assert_eq!(
        (service.uid.as_str(), service.native_kind.as_str()),
        ("gitlab.com/repository/7", "project")
    );
    assert_eq!(
        derived
            .entity(service.parent.as_deref().unwrap())
            .unwrap()
            .name,
        "gitlab:example/platform"
    );
    let state =
        |name: &str, aspect: &str| summary(collection.statement_about(name, aspect).unwrap());
    assert_eq!(
        state("gitlab:example/platform/service", aspect::TICKETS),
        "1 ticket"
    );
    assert_eq!(
        state("gitlab:example/platform/service", aspect::CHANGES),
        "1 change"
    );
    assert_eq!(
        state(
            "gitlab:example/platform/service@main",
            aspect::REQUIRED_CHECKS
        ),
        "pipeline (project setting)"
    );
    // the merge request is named as gitlab names it, and identified by its global id.
    let change = derived.named("gitlab:example/platform/service!2").unwrap();
    assert_eq!(
        (change.uid.as_str(), change.native_kind.as_str()),
        ("gitlab.com/change/202", "merge request")
    );
    // a system note is not a comment. the one in the fixture says nothing the
    // record keeps.
    let comments = derived
        .entities
        .iter()
        .filter(|entity| entity.kind == "comment")
        .count();
    assert_eq!(comments, 1);
    assert_eq!(
        state("gitlab:example/platform/service", aspect::MERGED_CHANGES),
        "1 change"
    );
    let kinds = |parent: &str, kind: &str| {
        derived
            .entities
            .iter()
            .filter(|entity| entity.parent.as_deref() == Some(parent) && entity.kind == kind)
            .count()
    };
    let about = derived.statement(&change.uid, aspect::CHANGE).unwrap();
    let value = about.reading.value().unwrap();
    assert_eq!(value["target_branch"], "main");
    assert_eq!(value["targets_default_branch"], true);
    // one pipeline passed and one failed. of the three jobs of the newest
    // pipeline, one passed, one failed, and one never ran.
    assert_eq!(kinds(&change.uid, "check passed"), 2);
    assert_eq!(kinds(&change.uid, "check failed"), 2);
    let named = |name: &str| {
        derived
            .entities
            .iter()
            .find(|entity| entity.parent.as_deref() == Some(&change.uid) && entity.name == name)
            .map(|entity| entity.kind.as_str())
    };
    assert_eq!(named("sast"), Some("check passed"));
    assert_eq!(named("secret-scan"), Some("check failed"));
    assert_eq!(named("deploy"), None);
    // of the two pushes to the default branch, one ends on the merge commit.
    let branch = derived
        .named("gitlab:example/platform/service@main")
        .unwrap();
    assert_eq!(kinds(&branch.uid, "merge"), 1);
    assert_eq!(kinds(&branch.uid, "push"), 1);

    let state = tempfile::tempdir().unwrap();
    record::store(state.path(), &collection, &transcripts).unwrap();
    verify::verify(state.path()).unwrap();
}

#[test]
fn the_definition_written_for_github_checks_a_gitlab_project() {
    assert_eq!(outcomes(&collect(&project(3)).0), ["kept", "kept", "kept"]);
    // the merge request's own author approving it does not count.
    assert_eq!(
        outcomes(&collect(&project(2)).0),
        ["kept", "kept", "broken"]
    );
}

#[test]
fn one_unreadable_reading_about_an_item_leaves_its_steps_unknown() {
    let mut responses = project(3);
    let denied = (403, r#"{"message":"403 Forbidden"}"#.to_owned());
    responses.insert(
        format!("{API}/projects/7/merge_requests/2/approvals"),
        denied.clone(),
    );
    assert_eq!(
        outcomes(&collect(&responses).0),
        ["kept", "kept", "cannot tell"]
    );
    responses.insert(
        format!("{API}/projects/7/issues/1/resource_state_events?per_page=100"),
        denied,
    );
    assert_eq!(
        outcomes(&collect(&responses).0),
        ["cannot tell", "cannot tell", "n/a"]
    );
}

#[test]
fn a_scope_names_its_source() {
    assert_eq!(
        source::for_scope("github:example").unwrap().0.name(),
        "github"
    );
    assert_eq!(
        source::for_scope("gitlab:example/platform").unwrap().1,
        "example/platform"
    );
    let unknown = source::for_scope("bitbucket:example")
        .err()
        .unwrap()
        .to_string();
    assert!(unknown.contains("github:<organisation>") && unknown.contains("gitlab:<group>"));
    assert!(unknown.contains("azure:<organisation>/<project>"));
    assert!(source::for_scope("example").is_err());
}

#[test]
fn approvals_over_time_come_from_the_notes_gitlab_keeps() {
    let mut responses = project(3);
    let base = format!("{API}/projects/7");
    let note = |id: u64, body: &str, by: u64, at: &str| {
        format!(
            r#"{{"id":{id},"system":true,"body":"{body}","author":{},"created_at":"{at}"}}"#,
            user(by)
        )
    };
    // user 4 approved and took it back before the merge. the approvals
    // gitlab lists today do not show that it ever happened.
    responses.insert(
        format!("{base}/merge_requests/2/notes?sort=asc&per_page=100"),
        (
            200,
            format!(
                "[{}]",
                [
                    note(
                        51,
                        "approved this merge request",
                        4,
                        "2026-03-18T10:00:00.000Z"
                    ),
                    note(
                        52,
                        "unapproved this merge request",
                        4,
                        "2026-03-18T11:00:00.000Z"
                    ),
                    note(
                        53,
                        "added 1 commit\\n\\n<ul><li>3f467b9e - fix</li></ul>",
                        2,
                        "2026-03-19T11:30:00.000Z"
                    ),
                ]
                .join(",")
            ),
        ),
    );
    let (collection, _) = collect(&responses);
    let derived = &collection.contents.derived;
    let change = derived.named("gitlab:example/platform/service!2").unwrap();
    let kinds = |kind: &str| {
        derived
            .entities
            .iter()
            .filter(|entity| entity.parent.as_deref() == Some(&change.uid) && entity.kind == kind)
            .count()
    };
    assert_eq!(kinds("approval"), 2);
    assert_eq!(kinds("approval withdrawn"), 1);
    assert_eq!(kinds("commit"), 1);
    // user 3's approval at 11:00 on the 19th came before the last commit.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("process.yaml");
    fs::write(
        &path,
        "process: p\nitems:\n  kind: change\n  when: merged\nsteps:\n  - name: fresh\n    event: approval\n    by: someone else\n    after: commit\n    before: merge\n  - name: two\n    event: approval\n    by: someone else\n    at least: 2\n    before: merge\n",
    )
    .unwrap();
    let report = process::check(&process::load(&path).unwrap(), &collection, &[]).unwrap();
    let labels = report.rows[0]
        .outcomes
        .iter()
        .map(Outcome::label)
        .collect::<Vec<_>>();
    // and the approval that was taken back is not a second approval.
    assert_eq!(labels, ["broken", "broken"]);
}

#[test]
fn unreadable_jobs_leave_the_checks_unknown_and_the_reviews_standing() {
    let mut responses = project(3);
    responses.insert(
        format!("{API}/projects/7/pipelines/31/jobs?per_page=100"),
        (403, r#"{"message":"403 Forbidden"}"#.to_owned()),
    );
    let (collection, _) = collect(&responses);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("process.yaml");
    fs::write(
        &path,
        "process: p\nitems:\n  kind: change\n  when: merged\nsteps:\n  - name: reviewed\n    event: approval\n    by: someone else\n    before: merge\n  - name: validated\n    event: check passed\n    before: merge\n",
    )
    .unwrap();
    let report = process::check(&process::load(&path).unwrap(), &collection, &[]).unwrap();
    let labels = report.rows[0]
        .outcomes
        .iter()
        .map(Outcome::label)
        .collect::<Vec<_>>();
    assert_eq!(labels, ["kept", "cannot tell"]);
}

#[test]
fn a_merge_request_is_read_with_its_files_and_a_project_with_its_releases() {
    let (collection, transcripts) = collect(&project(3));
    let change = collection
        .statement_about("gitlab:example/platform/service!2", "change")
        .unwrap();
    // a renamed file counts under both of its names.
    assert_eq!(
        change.reading.value().unwrap()["paths"],
        serde_json::json!(["auth/login.rb", "docs/new.md", "docs/old.md"])
    );
    // the paths are traced to the reading they came from.
    assert_eq!(change.transcripts.len(), 2);
    let release = collection
        .statement_about("gitlab:example/platform/service release v2.0.0", "release")
        .unwrap();
    assert_eq!(
        release.reading.value().unwrap()["assets"],
        serde_json::json!([{"name": "sbom", "kind": "other"}])
    );
    let state = tempfile::tempdir().unwrap();
    record::store(state.path(), &collection, &transcripts).unwrap();
    verify::verify(state.path()).unwrap();
}

#[test]
fn a_collection_can_leave_out_the_files_of_each_merge_request() {
    let mut responses = project(3);
    // nothing asks for the diffs, so nothing has to answer for them.
    responses.remove(&format!(
        "{API}/projects/7/merge_requests/2/diffs?per_page=100"
    ));
    let (collection, transcripts) = common::collect_with(
        "gitlab:example/platform/service",
        "2026-01-01T00:00:00Z",
        NOW,
        false,
        |url| common::answer(responses.get(url), url),
    );
    assert!(transcripts
        .iter()
        .all(|transcript| transcript.contents.resource != source::gitlab::DIFFS));
    let change = collection
        .statement_about("gitlab:example/platform/service!2", "change")
        .unwrap();
    // the paths are unknown, which is not the same as none.
    assert!(change.reading.value().unwrap()["paths"].is_null());
    let definition = "process: p\nitems:\n  kind: change\n  paths: auth/**\nsteps:\n  - name: reviewed\n    event: approval\n";
    let definition = process::parse(definition, std::path::Path::new("inline")).unwrap();
    let report = process::check(&definition, &collection, &[]).unwrap();
    assert_eq!(
        report.rows[0].outcomes[0],
        Outcome::CannotTell(
            "the files gitlab:example/platform/service!2 touches were not read".into()
        )
    );
}
