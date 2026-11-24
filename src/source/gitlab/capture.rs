//! reading a gitlab group.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::parse_time;
use crate::source::reading::{self, failure, linked_page, percent_encode, Api, Reader};
use crate::source::{Clock, Fetch, Period};
use crate::transcript::{Termination, Transcript};

const ORIGIN: &str = "https://gitlab.com";
static API: Api = Api {
    origin: ORIGIN,
    classify,
    next: linked_page,
};
/// the group itself.
pub const GROUP: &str = "gitlab/group/v1";
/// every project of the group and its subgroups that the credential can see.
pub const PROJECTS: &str = "gitlab/group-projects/v1";
/// every protected branch rule of one project.
pub const PROTECTED_BRANCHES: &str = "gitlab/protected-branches/v1";
/// the merge request approval settings of one project.
pub const APPROVAL_SETTINGS: &str = "gitlab/approval-settings/v1";
/// the merge request approval rules of one project.
pub const APPROVAL_RULES: &str = "gitlab/approval-rules/v1";
/// one project.
pub const PROJECT: &str = "gitlab/project/v1";
/// the issues of one project opened in a period.
pub const ISSUES: &str = "gitlab/issues/v1";
/// the merge requests of one project opened in a period.
pub const MERGE_REQUESTS: &str = "gitlab/merge-requests/v1";
/// the comments and system notes on one issue or merge request.
pub const NOTES: &str = "gitlab/notes/v1";
/// when one issue or merge request was closed, reopened, or merged, and by whom.
pub const STATE_EVENTS: &str = "gitlab/state-events/v1";
/// the merge requests gitlab says close one issue.
pub const CLOSED_BY: &str = "gitlab/closed-by/v1";
/// who approved one merge request, and when.
pub const APPROVALS: &str = "gitlab/approvals/v1";
/// the merged merge requests of one project updated since a time.
pub const MERGED: &str = "gitlab/merged-merge-requests/v1";
/// the pipelines that ran for one merge request.
pub const PIPELINES: &str = "gitlab/merge-request-pipelines/v1";
/// the jobs of one pipeline that ran for a merge request.
pub const JOBS: &str = "gitlab/pipeline-jobs/v1";
/// the pushes to one project between two days.
pub const PUSHES: &str = "gitlab/push-events/v1";

/// read a group or a project.
///
/// a group is read with its projects and the default branch settings of
/// each. a project is read with its default branch settings and the issues
/// and merge requests opened in the period, with what happened to each. the
/// path is tried as a group first; gitlab does not tell the two apart by name.
///
/// a reading that fails is returned as a transcript that says how it ended,
/// not as an error. a project with no default branch has no branch settings
/// to read.
///
/// # Errors
///
/// returns an error when the path is not one gitlab allows, or a transcript
/// cannot be sealed.
pub fn capture(
    path: &str,
    period: &Period,
    clock: &Clock,
    fetch: &mut Fetch,
) -> Result<Vec<Transcript>> {
    let segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if !path.split('/').all(segment) {
        return Err(Error::Invalid(format!(
            "{path:?} is not a gitlab group or project path"
        )));
    }
    let api = format!("{ORIGIN}/api/v4");
    let subject = format!("gitlab:{path}");
    let encoded = percent_encode(path);
    let mut reader = Reader::new(&API, clock, fetch);
    let group = reader.read(
        GROUP,
        &subject,
        &[],
        format!("{api}/groups/{encoded}?with_projects=false"),
    )?;
    let no_such_group = matches!(group.contents.termination, Termination::NotFound { .. });
    let mut transcripts = vec![group];
    if no_such_group && path.contains('/') {
        project(&mut reader, &api, path, period, &mut transcripts)?;
        return Ok(transcripts);
    }
    let listing = reader.read(
        PROJECTS,
        &subject,
        &[],
        format!(
            "{api}/groups/{encoded}/projects?include_subgroups=true&order_by=id&sort=asc&per_page=100"
        ),
    )?;
    let projects = super::facts::listed(&listing);
    transcripts.push(listing);
    for project in projects {
        if let Some(branch) = project.default_branch {
            let subject = format!("gitlab:{}", project.path);
            branch_settings(
                &mut reader,
                &api,
                project.id,
                &subject,
                &branch,
                &mut transcripts,
            )?;
        }
    }
    Ok(transcripts)
}

/// the three readings behind a branch's protection and review policy.
fn branch_settings(
    reader: &mut Reader,
    api: &str,
    project: u64,
    subject: &str,
    branch: &str,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    for (resource, path) in [
        (PROTECTED_BRANCHES, "protected_branches?per_page=100"),
        (APPROVAL_SETTINGS, "approvals"),
        (APPROVAL_RULES, "approval_rules?per_page=100"),
    ] {
        transcripts.push(reader.read(
            resource,
            subject,
            &[("branch", branch)],
            format!("{api}/projects/{project}/{path}"),
        )?);
    }
    Ok(())
}

/// one project: its default branch, and the issues and merge requests opened
/// in the period with what happened to each.
fn project(
    reader: &mut Reader,
    api: &str,
    path: &str,
    period: &Period,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let subject = format!("gitlab:{path}");
    let about = reader.read(
        PROJECT,
        &subject,
        &[],
        format!("{api}/projects/{}", percent_encode(path)),
    )?;
    let identity = super::facts::project_identity(&about);
    transcripts.push(about);
    let Some((id, default_branch)) = identity else {
        return Ok(());
    };
    let base = format!("{api}/projects/{id}");
    let (from, until) = (percent_encode(&period.from), percent_encode(&period.until));
    let parameters = [("from", period.from.as_str()), ("until", &period.until)];
    if let Some(branch) = default_branch {
        branch_settings(reader, api, id, &subject, &branch, transcripts)?;
        // gitlab selects events by day, and leaves both named days out.
        let day = |time: &str, shift: i64| -> Result<String> {
            Ok((parse_time(time)?.date() + time::Duration::days(shift)).to_string())
        };
        transcripts.push(reader.read(
            PUSHES,
            &subject,
            &[parameters[0], parameters[1], ("branch", &branch)],
            format!(
                "{base}/events?action=pushed&after={}&before={}&sort=asc&per_page=100",
                day(&period.from, -1)?,
                day(&period.until, 1)?
            ),
        )?);
    }
    let opened = format!(
        "created_after={from}&created_before={until}&order_by=created_at&sort=asc&per_page=100"
    );
    let issues = reader.read(
        ISSUES,
        &subject,
        &parameters,
        format!("{base}/issues?scope=all&{opened}"),
    )?;
    let numbers = super::work::numbers(&issues);
    transcripts.push(issues);
    details(reader, &base, &subject, "issues", &numbers, transcripts)?;
    let opened = reader.read(
        MERGE_REQUESTS,
        &subject,
        &parameters,
        format!("{base}/merge_requests?scope=all&state=all&{opened}"),
    )?;
    // everything merged in the period was updated in it or later.
    let merged = reader.read(
        MERGED,
        &subject,
        &parameters,
        format!(
            "{base}/merge_requests?scope=all&state=merged&updated_after={from}&order_by=updated_at&sort=asc&per_page=100"
        ),
    )?;
    let mut numbers = super::work::numbers(&opened);
    numbers.extend(super::work::merged_in_period(&merged));
    numbers.sort_unstable();
    numbers.dedup();
    transcripts.extend([opened, merged]);
    details(
        reader,
        &base,
        &subject,
        "merge_requests",
        &numbers,
        transcripts,
    )
}

/// what happened to each of a project's issues or merge requests.
fn details(
    reader: &mut Reader,
    base: &str,
    subject: &str,
    collection: &str,
    numbers: &[u64],
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let (marker, last) = if collection == "issues" {
        ('#', (CLOSED_BY, "closed_by?per_page=100"))
    } else {
        ('!', (APPROVALS, "approvals"))
    };
    let mut readings = vec![
        (NOTES, "notes?sort=asc&per_page=100"),
        (STATE_EVENTS, "resource_state_events?per_page=100"),
        last,
    ];
    if collection != "issues" {
        readings.push((PIPELINES, "pipelines?per_page=100"));
    }
    for number in numbers {
        let number = number.to_string();
        let item = format!("{subject}{marker}{number}");
        for (resource, path) in &readings {
            let read = reader.read(
                resource,
                &item,
                &[("number", &number)],
                format!("{base}/{collection}/{number}/{path}"),
            )?;
            let pipelines = if *resource == PIPELINES {
                super::work::head_pipelines(&read)
            } else {
                Vec::new()
            };
            transcripts.push(read);
            for pipeline in pipelines {
                let pipeline = pipeline.to_string();
                transcripts.push(reader.read(
                    JOBS,
                    &item,
                    &[("number", &number), ("pipeline", &pipeline)],
                    format!("{base}/pipelines/{pipeline}/jobs?per_page=100"),
                )?);
            }
        }
    }
    Ok(())
}

/// find the local gitlab credential: the `glab` configuration, then `GITLAB_TOKEN`.
///
/// # Errors
///
/// returns an error when neither yields a credential.
pub fn token() -> Result<String> {
    reading::credential(
        &["glab", "config", "get", "token", "--host", "gitlab.com"],
        "GITLAB_TOKEN",
        "glab auth login",
    )
}

/// a fetch function that reads the gitlab.com api with a credential.
pub fn client(token: &str) -> Box<Fetch<'static>> {
    reading::client(
        ORIGIN,
        Some(format!("Bearer {token}")),
        vec![token.to_owned()],
        &[("accept", "application/json")],
        &[
            "date",
            "link",
            "location",
            "ratelimit-limit",
            "ratelimit-name",
            "ratelimit-observed",
            "ratelimit-remaining",
            "ratelimit-reset",
            "retry-after",
            "x-next-page",
            "x-page",
            "x-per-page",
            "x-request-id",
            "x-total",
            "x-total-pages",
        ],
    )
}

fn classify(status: u16, body: &str, headers: &BTreeMap<String, String>) -> Termination {
    failure(status, body, headers, "ratelimit-reset")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_may_name_nested_groups_and_nothing_else() {
        let period = Period {
            from: "2026-01-01T00:00:00Z".into(),
            until: "2026-04-01T00:00:00Z".into(),
        };
        let read = |path: &str| {
            capture(
                path,
                &period,
                &|| Ok("2026-11-24T10:00:00Z".to_owned()),
                &mut |_: &str| Err(Error::Collection("offline".into())),
            )
        };
        assert_eq!(read("example/platform").unwrap().len(), 2);
        assert!(read("example//platform").is_err());
        assert!(read("example?x=1").is_err());
    }

    #[test]
    fn failures_are_classified_by_status() {
        let none = BTreeMap::new();
        assert!(matches!(
            classify(403, r#"{"message":"403 Forbidden"}"#, &none),
            Termination::PermissionDenied { diagnostic } if diagnostic == "HTTP 403: 403 Forbidden"
        ));
        assert!(matches!(
            classify(429, "Retry later", &none),
            Termination::RateLimited { .. }
        ));
    }
}
