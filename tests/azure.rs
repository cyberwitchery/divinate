//! an azure devops project read with its work items and pull requests,
//! checked with the same process definition a github repository is checked
//! with.
//!
//! the thread shapes for a status change and a comment are what dev.azure.com
//! returned for a public project on 2026-11-24. the vote thread follows the
//! earlier azure devops collector. the work item bodies are written from the
//! api's description and were not read from a live server.

use std::collections::BTreeMap;
use std::fs;

use divinate::facts::summary;
use divinate::model::{aspect, relation};
use divinate::process::{self, Outcome};
use divinate::record::{self, Collection};
use divinate::transcript::Transcript;
use divinate::verify;

mod common;

const ROOT: &str = "https://dev.azure.com/example";
const BASE: &str = "https://dev.azure.com/example/platform/_apis";
const NOW: &str = "2026-03-27T00:00:00Z";
const PROJECT_ID: &str = "cbb18261-c48f-4abb-8651-8cdcb5474649";
const REPOSITORY_ID: &str = "2459d599-fdb2-4d28-9810-daeec061cf90";
const REVISIONS: &str = "wit/reporting/workitemrevisions?fields=System.Id%2CSystem.Rev%2CSystem.WorkItemType%2CSystem.State%2CSystem.Title%2CSystem.Tags%2CSystem.CreatedDate%2CSystem.CreatedBy%2CSystem.ChangedDate%2CSystem.ChangedBy%2CSystem.CommentCount&startDateTime=2026-01-01T00%3A00%3A00Z&includeIdentityRef=true&%24maxPageSize=200&api-version=7.1";

const EVALUATIONS: &str = "policy/evaluations?artifactId=vstfs%3A%2F%2F%2FCodeReview%2FCodeReviewId%2Fcbb18261-c48f-4abb-8651-8cdcb5474649%2F12&includeNotApplicable=true&%24top=100&%24skip=0&api-version=7.1-preview.1";
const PUSHES: &str = "git/repositories/2459d599-fdb2-4d28-9810-daeec061cf90/pushes?searchCriteria.refName=refs%2Fheads%2Fmain&searchCriteria.fromDate=2026-01-01T00%3A00%3A00Z&searchCriteria.toDate=2026-03-27T00%3A00%3A00Z&searchCriteria.includeRefUpdates=true&%24top=100&%24skip=0&api-version=7.1";

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
    format!(
        r#"{{"id":"00000000-0000-0000-0000-00000000000{id}","displayName":"User {id}","uniqueName":"user{id}@example.org"}}"#
    )
}

fn revision(rev: u64, state: &str, comments: u64, changed: &str, by: u64) -> String {
    format!(
        r#"{{"id":34,"rev":{rev},"fields":{{"System.Id":34,"System.Rev":{rev},"System.WorkItemType":"Bug","System.State":"{state}","System.Title":"t","System.Tags":"security; backend","System.CreatedDate":"2026-03-01T09:00:00.123Z","System.CreatedBy":{},"System.ChangedDate":"{changed}","System.ChangedBy":{},"System.CommentCount":{comments}}}}}"#,
        user(1),
        user(by)
    )
}

/// a project with one security bug, answered, closed, and linked to a pull
/// request that `approver` approved before it was completed.
fn project(approver: u64) -> Responses {
    let ok = |body: String| (200, body);
    let pull = format!(
        r#"{{"repository":{{"id":"{REPOSITORY_ID}","name":"service","project":{{"id":"{PROJECT_ID}","name":"platform"}}}},"pullRequestId":12,"codeReviewId":12,"status":"completed","createdBy":{},"creationDate":"2026-03-02T09:00:00.9643061Z","closedDate":"2026-03-19T12:00:00.1682215Z","title":"c","sourceRefName":"refs/heads/fix","targetRefName":"refs/heads/main","lastMergeCommit":{{"commitId":"af56d96fdbd7c26e9fc94336b6f50dcc6ceff484"}}}}"#,
        user(2)
    );
    let threads = format!(
        r#"{{"value":[
            {{"id":1,"publishedDate":"2026-03-19T11:00:00.5Z","comments":[{{"id":1,"author":{approved_by},"content":"User voted 10","publishedDate":"2026-03-19T11:00:00.5Z","commentType":"system"}}],"identities":{{"1":{approved_by}}},"properties":{{"CodeReviewThreadType":{{"$type":"System.String","$value":"VoteUpdate"}},"CodeReviewVoteResult":{{"$type":"System.String","$value":"10"}},"CodeReviewVotedByIdentity":{{"$type":"System.String","$value":"1"}}}},"isDeleted":false}},
            {{"id":2,"publishedDate":"2026-03-19T12:00:00.657Z","comments":[{{"id":1,"author":{author},"content":"User 2 updated the pull request status to Completed","publishedDate":"2026-03-19T12:00:00.657Z","commentType":"system"}}],"identities":{{"1":{author}}},"properties":{{"BypassPolicy":{{"$type":"System.String","$value":"False"}},"CodeReviewStatus":{{"$type":"System.String","$value":"Completed"}},"CodeReviewThreadType":{{"$type":"System.String","$value":"StatusUpdate"}},"CodeReviewStatusUpdatedByIdentity":{{"$type":"System.String","$value":"1"}}}},"isDeleted":false}},
            {{"id":3,"publishedDate":"2026-03-18T10:00:00.04Z","comments":[{{"id":1,"author":{author},"content":"ready","publishedDate":"2026-03-18T10:00:00.04Z","commentType":"text"}}],"status":"closed","properties":{{}},"identities":null,"isDeleted":false}},
            {{"id":4,"publishedDate":"2026-03-18T10:05:00Z","comments":[{{"id":1,"author":{author},"publishedDate":"2026-03-18T10:05:00Z","commentType":"text","isDeleted":true}}],"status":"closed","properties":{{}},"identities":null,"isDeleted":true}}
        ],"count":4}}"#,
        approved_by = user(approver),
        author = user(2)
    );
    let revisions = [
        revision(1, "New", 0, "2026-03-01T09:00:00.123Z", 1),
        revision(2, "New", 1, "2026-03-01T09:05:00Z", 1),
        revision(3, "Active", 2, "2026-03-03T10:00:00.5Z", 3),
        revision(4, "Closed", 2, "2026-03-20T16:00:00Z", 2),
    ]
    .join(",");
    BTreeMap::from([
        (
            format!("{ROOT}/_apis/connectionData?api-version=7.1-preview.1"),
            ok(r#"{"instanceId":"b55de4ed-4b5a-4215-a8e4-0a0a5f71e7d8"}"#.to_owned()),
        ),
        (
            format!("{ROOT}/_apis/projects/platform?api-version=7.1"),
            ok(format!(
                r#"{{"id":"{PROJECT_ID}","name":"platform","state":"wellFormed","visibility":"private"}}"#
            )),
        ),
        (
            format!("{BASE}/git/repositories?api-version=7.1"),
            ok(format!(
                r#"{{"value":[{{"id":"{REPOSITORY_ID}","name":"service","project":{{"id":"{PROJECT_ID}","name":"platform","visibility":"private"}},"defaultBranch":"refs/heads/main","isDisabled":false}}],"count":1}}"#
            )),
        ),
        (
            format!("{BASE}/git/policy/configurations?repositoryId={REPOSITORY_ID}&refName=refs%2Fheads%2Fmain&%24top=100&api-version=7.1"),
            ok(r#"{"count":1,"value":[{"id":7,"isEnabled":true,"isBlocking":true,"isDeleted":false,"type":{"id":"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd","displayName":"Minimum number of reviewers"},"settings":{"minimumApproverCount":1,"creatorVoteCounts":false}}]}"#.to_owned()),
        ),
        (
            format!("{BASE}/git/pullrequests?searchCriteria.status=all&searchCriteria.minTime=2026-01-01T00%3A00%3A00Z&searchCriteria.maxTime=2026-03-27T00%3A00%3A00Z&searchCriteria.queryTimeRangeType=created&%24top=100&%24skip=0&api-version=7.1"),
            ok(format!(r#"{{"value":[{pull}],"count":1}}"#)),
        ),
        (
            format!("{BASE}/git/repositories/{REPOSITORY_ID}/pullRequests/12/threads?api-version=7.1"),
            ok(threads),
        ),
        (
            format!("{BASE}/git/pullrequests?searchCriteria.status=completed&searchCriteria.minTime=2026-01-01T00%3A00%3A00Z&searchCriteria.maxTime=2026-03-27T00%3A00%3A00Z&searchCriteria.queryTimeRangeType=closed&%24top=100&%24skip=0&api-version=7.1"),
            ok(format!(r#"{{"value":[{pull}],"count":1}}"#)),
        ),
        (
            format!("{BASE}/{EVALUATIONS}"),
            ok(r#"{"count":2,"value":[{"evaluationId":"6a4f9c1e-0d5b-4a52-8f0e-3d2c1b0a9f8e","status":"approved","completedDate":"2026-03-19T10:30:00.1Z","configuration":{"id":9,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241","displayName":"Build"},"settings":{"buildDefinitionId":12,"displayName":"ci"}}},{"evaluationId":"7b5f9c1e-0d5b-4a52-8f0e-3d2c1b0a9f8e","status":"approved","completedDate":"2026-03-19T11:00:00.5Z","configuration":{"id":7,"type":{"id":"fa4e907d-c16b-4a4c-9dfa-4906e5d171dd","displayName":"Minimum number of reviewers"},"settings":{"minimumApproverCount":1}}}]}"#.to_owned()),
        ),
        (
            format!("{BASE}/{PUSHES}"),
            // the first push completed the pull request, the second went around one.
            ok(format!(
                r#"{{"count":2,"value":[{{"pushId":36,"date":"2026-03-19T12:00:00.1Z","pushedBy":{by},"refUpdates":[{{"repositoryId":"{REPOSITORY_ID}","name":"refs/heads/main","oldObjectId":"2adc745e20d7a07fb7f177853d3e78a95b007aef","newObjectId":"af56d96fdbd7c26e9fc94336b6f50dcc6ceff484"}}]}},{{"pushId":31,"date":"2026-02-22T01:21:46.8136905Z","pushedBy":{by},"refUpdates":[{{"repositoryId":"{REPOSITORY_ID}","name":"refs/heads/main","oldObjectId":"f5fd3d0d7b9c3b84ebd58df595fbe7d44f1bcb03","newObjectId":"2adc745e20d7a07fb7f177853d3e78a95b007aef"}}]}}]}}"#,
                by = user(2)
            )),
        ),
        (
            format!("{BASE}/{REVISIONS}"),
            ok(format!(
                r#"{{"values":[{revisions}],"nextLink":"{BASE}/wit/reporting/workItemRevisions?continuationToken=9","continuationToken":"9","isLastBatch":true}}"#
            )),
        ),
        (
            format!("{BASE}/wit/workitemtypes/Bug/states?api-version=7.1"),
            ok(r#"{"count":4,"value":[{"name":"New","color":"b2b2b2","category":"Proposed"},{"name":"Active","color":"007acc","category":"InProgress"},{"name":"Resolved","color":"ff9d00","category":"Resolved"},{"name":"Closed","color":"339933","category":"Completed"}]}"#.to_owned()),
        ),
        (
            format!("{BASE}/wit/workitems?ids=34&%24expand=relations&api-version=7.1"),
            ok(format!(
                r#"{{"count":1,"value":[{{"id":34,"rev":4,"fields":{{"System.Title":"t"}},"relations":[{{"rel":"System.LinkTypes.Hierarchy-Reverse","url":"{BASE}/wit/workItems/30","attributes":{{"name":"Parent"}}}},{{"rel":"ArtifactLink","url":"vstfs:///Git/PullRequestId/{PROJECT_ID}%2f{REPOSITORY_ID}%2f12","attributes":{{"name":"Pull Request"}}}}]}}]}}"#
            )),
        ),
    ])
}

fn collect(responses: &Responses) -> (Collection, Vec<Transcript>) {
    common::collect(
        "azure:example/platform",
        "2026-01-01T00:00:00Z",
        NOW,
        |url| common::answer(responses.get(url), url),
    )
}

fn load(text: &str) -> process::Process {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("process.yaml");
    fs::write(&path, text).unwrap();
    process::load(&path).unwrap()
}

fn outcomes(collection: &Collection) -> Vec<&'static str> {
    let report = process::check(&load(DEFINITION), collection, &[]).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].item, "azure:example/platform#34");
    report.rows[0].outcomes.iter().map(Outcome::label).collect()
}

#[test]
fn a_project_is_read_with_its_work_items_and_pull_requests() {
    let (collection, transcripts) = collect(&project(3));
    assert_eq!(collection.gaps(), 0);
    let derived = &collection.contents.derived;
    let state =
        |name: &str, aspect: &str| summary(collection.statement_about(name, aspect).unwrap());
    assert_eq!(state("azure:example/platform", aspect::PROJECT), "private");
    assert_eq!(state("azure:example/platform", aspect::TICKETS), "1 ticket");
    assert_eq!(state("azure:example/platform", aspect::CHANGES), "1 change");
    assert_eq!(
        state("azure:example/platform/service@main", aspect::REVIEW_POLICY),
        "1 approval (policy 7)"
    );
    // a work item belongs to the project, a pull request to a repository in it.
    let ticket = derived.named("azure:example/platform#34").unwrap();
    assert_eq!(
        (ticket.uid.as_str(), ticket.native_kind.as_str()),
        ("dev.azure.com/ticket/34", "bug")
    );
    let about = derived.statement(&ticket.uid, aspect::TICKET).unwrap();
    let value = about.reading.value().unwrap();
    assert_eq!(value["state"], "closed");
    assert_eq!(value["labels"], serde_json::json!(["security", "backend"]));
    assert_eq!(value["closed_at"], "2026-03-20T16:00:00.000Z");
    let change = derived.named("azure:example/platform/service!12").unwrap();
    assert_eq!(
        (change.uid.as_str(), change.native_kind.as_str()),
        ("dev.azure.com/change/12", "pull request")
    );
    // the source keeps the link between the two, and a parent link is not one.
    let links = derived
        .relations
        .iter()
        .filter(|link| link.kind == relation::REFERS_TO)
        .collect::<Vec<_>>();
    assert_eq!(links.len(), 1);
    assert_eq!(
        (
            links[0].from.as_str(),
            links[0].to.as_str(),
            links[0].basis.as_str()
        ),
        (change.uid.as_str(), ticket.uid.as_str(), relation::LINK)
    );
    // two comments on the work item, and one on the pull request: a system
    // comment and a deleted one are not comments.
    let kinds = |parent: &str, kind: &str| {
        derived
            .entities
            .iter()
            .filter(|entity| entity.parent.as_deref() == Some(parent) && entity.kind == kind)
            .count()
    };
    assert_eq!(kinds(&ticket.uid, "comment"), 2);
    assert_eq!(kinds(&ticket.uid, "closed"), 1);
    assert_eq!(kinds(&change.uid, "comment"), 1);
    assert_eq!(kinds(&change.uid, "approval"), 1);
    assert_eq!(kinds(&change.uid, "merge"), 1);
    let about = derived.statement(&change.uid, aspect::CHANGE).unwrap();
    let value = about.reading.value().unwrap();
    assert_eq!(value["target_branch"], "main");
    assert_eq!(value["targets_default_branch"], true);
    // the build policy is a check, the reviewer policy is not.
    assert_eq!(kinds(&change.uid, "check passed"), 1);
    assert_eq!(
        state("azure:example/platform", aspect::MERGED_CHANGES),
        "1 change"
    );
    // one push completed the pull request and one went around it.
    let branch = derived
        .named("azure:example/platform/service@main")
        .unwrap();
    assert_eq!(kinds(&branch.uid, "merge"), 1);
    assert_eq!(kinds(&branch.uid, "push"), 1);

    let state = tempfile::tempdir().unwrap();
    record::store(state.path(), &collection, &transcripts).unwrap();
    verify::verify(state.path()).unwrap();
}

#[test]
fn the_definition_written_for_github_checks_an_azure_devops_project() {
    assert_eq!(outcomes(&collect(&project(3)).0), ["kept", "kept", "kept"]);
    // the pull request's own author approving it does not count.
    assert_eq!(
        outcomes(&collect(&project(2)).0),
        ["kept", "kept", "broken"]
    );
}

#[test]
fn what_could_not_be_read_leaves_the_steps_unknown() {
    let denied = (
        401,
        r#"{"message":"TF400813: The user is not authorized to access this resource."}"#.to_owned(),
    );
    // without the threads, the pull request's review cannot be told.
    let mut responses = project(3);
    responses.insert(
        format!("{BASE}/git/repositories/{REPOSITORY_ID}/pullRequests/12/threads?api-version=7.1"),
        denied.clone(),
    );
    assert_eq!(
        outcomes(&collect(&responses).0),
        ["kept", "kept", "cannot tell"]
    );
    // without the policy evaluations, the review still stands and only the
    // checks cannot be told.
    let mut responses = project(3);
    responses.insert(format!("{BASE}/{EVALUATIONS}"), denied.clone());
    let (collection, _) = collect(&responses);
    assert_eq!(outcomes(&collection), ["kept", "kept", "kept"]);
    let validated = process::check(
        &load("process: p\nitems:\n  kind: change\n  when: merged\nsteps:\n  - name: validated\n    event: check passed\n    before: merge\n"),
        &collection,
        &[],
    )
    .unwrap();
    assert_eq!(validated.rows[0].outcomes[0].label(), "cannot tell");
    // without the states of its type, a work item cannot be said to be closed.
    let mut responses = project(3);
    responses.insert(
        format!("{BASE}/wit/workitemtypes/Bug/states?api-version=7.1"),
        denied.clone(),
    );
    let (collection, _) = collect(&responses);
    assert_eq!(outcomes(&collection), ["cannot tell", "cannot tell", "n/a"]);
    let ticket = collection
        .contents
        .derived
        .named("azure:example/platform#34")
        .unwrap();
    let about = collection
        .contents
        .derived
        .statement(&ticket.uid, aspect::TICKET)
        .unwrap();
    assert_eq!(about.reading.value().unwrap()["state"], "unknown");
    // without the work items, there is nothing to check, and the record says why.
    let mut responses = project(3);
    responses.insert(format!("{BASE}/{REVISIONS}"), denied);
    let (collection, _) = collect(&responses);
    let tickets = collection
        .statement_about("azure:example/platform", aspect::TICKETS)
        .unwrap();
    assert!(summary(tickets).starts_with("gap: not authenticated"));
}

#[test]
fn a_revision_listing_that_starts_late_is_not_the_whole_history() {
    let mut responses = project(3);
    let late = [
        revision(3, "Active", 2, "2026-03-03T10:00:00.5Z", 3),
        revision(4, "Closed", 2, "2026-03-20T16:00:00Z", 2),
    ]
    .join(",");
    responses.insert(
        format!("{BASE}/{REVISIONS}"),
        (200, format!(r#"{{"values":[{late}],"isLastBatch":true}}"#)),
    );
    assert_eq!(
        outcomes(&collect(&responses).0),
        ["cannot tell", "cannot tell", "n/a"]
    );
}

#[test]
fn an_organisation_is_read_project_by_project() {
    let responses = BTreeMap::from([
        (
            format!("{ROOT}/_apis/connectionData?api-version=7.1-preview.1"),
            (
                200,
                r#"{"instanceId":"b55de4ed-4b5a-4215-a8e4-0a0a5f71e7d8"}"#.to_owned(),
            ),
        ),
        (
            format!("{ROOT}/_apis/projects?%24top=100&api-version=7.1"),
            (
                200,
                format!(
                    r#"{{"count":2,"value":[{{"id":"{PROJECT_ID}","name":"platform","state":"wellFormed","visibility":"private"}},{{"id":"9ee6d478-d288-47f7-aacc-f6e6d082ae6d","name":"Open Source","state":"wellFormed","visibility":"public"}}]}}"#
                ),
            ),
        ),
        (
            format!("{BASE}/git/repositories?api-version=7.1"),
            (200, r#"{"value":[],"count":0}"#.to_owned()),
        ),
        (
            format!("{ROOT}/Open%20Source/_apis/git/repositories?api-version=7.1"),
            (
                403,
                r#"{"message":"TF401019: you do not have permissions"}"#.to_owned(),
            ),
        ),
    ]);
    let (collection, _) = common::collect("azure:example", "2026-01-01T00:00:00Z", NOW, |url| {
        common::answer(responses.get(url), url)
    });
    let state =
        |name: &str, aspect: &str| summary(collection.statement_about(name, aspect).unwrap());
    assert_eq!(state("azure:example", aspect::PROJECTS), "2 projects");
    assert_eq!(
        state("azure:example/platform", aspect::REPOSITORIES),
        "no repositories"
    );
    assert_eq!(
        state("azure:example/Open Source", aspect::PROJECT),
        "public"
    );
    assert!(state("azure:example/Open Source", aspect::REPOSITORIES)
        .starts_with("gap: permission denied"));
}
