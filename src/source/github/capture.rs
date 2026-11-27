//! reading a github organisation or repository.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::parse_time;
use crate::source::reading::{self, failure, linked_page, percent_encode, Api, Reader};
use crate::source::{Clock, Fetch, Period, Roots};
use crate::transcript::{Termination, Transcript};

const ORIGIN: &str = "https://api.github.com";
static API: Api = Api {
    origin: ORIGIN,
    classify,
    next: linked_page,
};

/// the organisation itself, including the repository counts it reports.
pub const ORGANISATION: &str = "github/organisation/v1";
/// every repository of the organisation that the credential can see.
pub const REPOSITORIES: &str = "github/organisation-repositories/v1";
/// classic branch protection for one branch.
pub const BRANCH_PROTECTION: &str = "github/branch-protection/v1";
/// the active rules that apply to one branch, from repository and organisation rulesets.
pub const BRANCH_RULES: &str = "github/branch-rules/v1";
/// one repository.
pub const REPOSITORY: &str = "github/repository/v1";
/// the issues and pull requests of one repository updated since a time.
pub const WORK_ITEMS: &str = "github/work-items/v1";
/// everything that happened to one issue or pull request.
pub const TIMELINE: &str = "github/work-item-timeline/v1";
/// one pull request, which names the commit it proposes.
pub const PULL_REQUEST: &str = "github/pull-request/v1";
/// the files one pull request touches.
pub const FILES: &str = "github/pull-request-files/v1";
/// every release of one repository.
pub const RELEASES: &str = "github/releases/v1";
/// the check runs on the commit a pull request proposes.
pub const CHECK_RUNS: &str = "github/check-runs/v1";
/// the commit statuses on the commit a pull request proposes.
pub const STATUSES: &str = "github/commit-statuses/v1";
/// every update of one branch during a span of time before the reading.
pub const ACTIVITY: &str = "github/branch-activity/v1";
/// every code scanning alert of one repository.
pub const CODE_SCANNING: &str = "github/code-scanning-alerts/v1";
/// every dependabot alert of one repository.
pub const DEPENDABOT: &str = "github/dependabot-alerts/v1";
/// every secret scanning alert of one repository.
pub const SECRET_SCANNING: &str = "github/secret-scanning-alerts/v1";

/// read an organisation or a repository.
///
/// an organisation is read with its repositories and the default branch
/// settings of each. a repository is read with its default branch settings
/// and the tickets and changes of the period, with what happened to each.
///
/// a reading that fails is returned as a transcript that says how it ended,
/// not as an error. once the source rate limits a request, the remaining
/// readings are recorded as not attempted.
///
/// # Errors
///
/// returns an error when the path is not `<organisation>` or
/// `<organisation>/<repository>`, or a transcript cannot be sealed.
pub fn capture(
    path: &str,
    period: &Period,
    clock: &Clock,
    fetch: &mut Fetch,
) -> Result<Vec<Transcript>> {
    let allowed = |name: &str, extra: &[u8]| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
    };
    let (owner, repository) = match path.split_once('/') {
        Some((owner, repository)) => (owner, Some(repository)),
        None => (path, None),
    };
    if !allowed(owner, b"-") || repository.is_some_and(|name| !allowed(name, b"-_.")) {
        return Err(Error::Invalid(format!(
            "{path:?} is not a github organisation or organisation/repository"
        )));
    }
    let mut reader = Reader::new(&API, clock, fetch);
    let mut transcripts = Vec::new();
    match repository {
        Some(repository) => {
            one_repository(&mut reader, owner, repository, period, &mut transcripts)?;
        }
        None => organisation(&mut reader, owner, &mut transcripts)?,
    }
    Ok(transcripts)
}

fn organisation(
    reader: &mut Reader,
    organisation: &str,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let subject = format!("github:{organisation}");
    transcripts.push(reader.read(
        ORGANISATION,
        &subject,
        &[],
        format!("{ORIGIN}/orgs/{organisation}"),
    )?);
    let listing = reader.read(
        REPOSITORIES,
        &subject,
        &[],
        format!("{ORIGIN}/orgs/{organisation}/repos?per_page=100&type=all"),
    )?;
    let repositories = super::facts::listed(&listing);
    transcripts.push(listing);
    for repository in repositories {
        branch_settings(
            reader,
            organisation,
            &repository.name,
            &repository.default_branch,
            transcripts,
        )?;
    }
    Ok(())
}

/// the two readings behind a branch's protection, review policy, and checks.
fn branch_settings(
    reader: &mut Reader,
    owner: &str,
    repository: &str,
    branch: &str,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let subject = format!("github:{owner}/{repository}");
    let base = format!("{ORIGIN}/repos/{owner}/{}", percent_encode(repository));
    let encoded = percent_encode(branch);
    for (resource, path) in [
        (BRANCH_PROTECTION, format!("branches/{encoded}/protection")),
        (
            BRANCH_RULES,
            format!("rules/branches/{encoded}?per_page=100"),
        ),
    ] {
        transcripts.push(reader.read(
            resource,
            &subject,
            &[("branch", branch)],
            format!("{base}/{path}"),
        )?);
    }
    Ok(())
}

fn one_repository(
    reader: &mut Reader,
    owner: &str,
    repository: &str,
    period: &Period,
    transcripts: &mut Vec<Transcript>,
) -> Result<()> {
    let subject = format!("github:{owner}/{repository}");
    let base = format!("{ORIGIN}/repos/{owner}/{repository}");
    let about = reader.read(REPOSITORY, &subject, &[], base.clone())?;
    let default_branch = super::facts::default_branch(&about);
    transcripts.push(about);
    let with_files = period.files;
    let period = [("from", period.from.as_str()), ("until", &period.until)];
    // the settings of a branch, and every update of it in the period.
    let governed = |reader: &mut Reader, branch: &str, transcripts: &mut Vec<Transcript>| {
        branch_settings(reader, owner, repository, branch, transcripts)?;
        let span = span(&reader.now()?, period[0].1)?;
        transcripts.push(reader.read(
            ACTIVITY,
            &subject,
            &[period[0], period[1], ("branch", branch)],
            format!(
                "{base}/activity?ref={}&time_period={span}&per_page=100",
                percent_encode(&format!("refs/heads/{branch}"))
            ),
        )?);
        Ok::<(), Error>(())
    };
    if let Some(branch) = &default_branch {
        governed(reader, branch, transcripts)?;
    }
    // github's `since` selects by last update. everything opened or merged in
    // the period was updated in it or later, so the listing holds the whole period.
    let listing = reader.read(
        WORK_ITEMS,
        &subject,
        &period,
        format!(
            "{base}/issues?state=all&sort=created&direction=asc&per_page=100&since={}",
            percent_encode(period[0].1)
        ),
    )?;
    let listed = super::work::in_period(&listing);
    transcripts.push(listing);
    // every other branch a change of the period goes into is read as well.
    let mut targets = std::collections::BTreeSet::new();
    for item in listed {
        let number = item.number.to_string();
        let about = format!("{subject}#{number}");
        let parameters = [("number", number.as_str())];
        transcripts.push(reader.read(
            TIMELINE,
            &about,
            &parameters,
            format!("{base}/issues/{number}/timeline?per_page=100"),
        )?);
        if !item.change {
            continue;
        }
        let pull = reader.read(
            PULL_REQUEST,
            &about,
            &parameters,
            format!("{base}/pulls/{number}"),
        )?;
        let head = super::work::head(&pull);
        targets.extend(super::work::base(&pull));
        transcripts.push(pull);
        if with_files {
            transcripts.push(reader.read(
                FILES,
                &about,
                &parameters,
                format!("{base}/pulls/{number}/files?per_page=100"),
            )?);
        }
        // without the commit there is nothing to read the checks of, and the
        // missing readings say so.
        let Some(head) = head else {
            continue;
        };
        for (resource, path) in [
            (CHECK_RUNS, "check-runs?filter=all&per_page=100"),
            (STATUSES, "status?per_page=100"),
        ] {
            transcripts.push(reader.read(
                resource,
                &about,
                &parameters,
                format!("{base}/commits/{head}/{path}"),
            )?);
        }
    }
    for target in targets {
        if Some(&target) != default_branch.as_ref() {
            governed(reader, &target, transcripts)?;
        }
    }
    transcripts.push(reader.read(
        RELEASES,
        &subject,
        &period,
        format!("{base}/releases?per_page=100"),
    )?);
    for (resource, path) in [
        (CODE_SCANNING, "code-scanning/alerts?state=all&per_page=100"),
        (DEPENDABOT, "dependabot/alerts?per_page=100"),
        (SECRET_SCANNING, "secret-scanning/alerts?per_page=100"),
    ] {
        transcripts.push(reader.read(resource, &subject, &period, format!("{base}/{path}"))?);
    }
    Ok(())
}

/// the shortest span of branch activity github offers that reaches back to
/// `from`, with a margin: its spans are counted in calendar units.
fn span(now: &str, from: &str) -> Result<&'static str> {
    let age = parse_time(now)? - parse_time(from)?;
    let spans = [
        (20, "day"),
        (144, "week"),
        (648, "month"),
        (2040, "quarter"),
    ];
    Ok(spans
        .iter()
        .find(|(hours, _)| age.whole_hours() <= *hours)
        .map_or("year", |(_, span)| span))
}

/// find the local github credential: `gh auth token`, then `GITHUB_TOKEN`.
///
/// # Errors
///
/// returns an error when neither yields a credential.
pub fn token() -> Result<String> {
    reading::credential(&["gh", "auth", "token"], "GITHUB_TOKEN", "gh auth login")
}

/// a fetch function that reads the github api with a credential.
pub fn client(token: &str, roots: &Roots) -> Box<Fetch<'static>> {
    reading::client(
        ORIGIN,
        Some(format!("Bearer {token}")),
        vec![token.to_owned()],
        &[
            ("accept", "application/vnd.github+json"),
            ("x-github-api-version", "2022-11-28"),
        ],
        &[
            "date",
            "etag",
            "link",
            "location",
            "retry-after",
            "x-accepted-oauth-scopes",
            "x-github-api-version-selected",
            "x-github-request-id",
            "x-oauth-scopes",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-ratelimit-resource",
            "x-ratelimit-used",
        ],
        roots,
    )
}

/// github answers 403 both when access is denied and when a rate limit is hit.
fn classify(status: u16, body: &str, headers: &BTreeMap<String, String>) -> Termination {
    let limited = headers.get("x-ratelimit-remaining").map(String::as_str) == Some("0")
        || headers.contains_key("retry-after")
        || body.to_ascii_lowercase().contains("rate limit");
    match failure(status, body, headers, "x-ratelimit-reset") {
        Termination::PermissionDenied { diagnostic } if limited => Termination::RateLimited {
            diagnostic,
            reset_at: headers.get("x-ratelimit-reset").cloned(),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forbidden_response_with_no_quota_left_is_a_rate_limit() {
        let headers = BTreeMap::from([("x-ratelimit-remaining".into(), "0".into())]);
        assert!(matches!(
            classify(403, "{\"message\":\"API rate limit exceeded\"}", &headers),
            Termination::RateLimited { .. }
        ));
        assert!(matches!(
            classify(
                403,
                "{\"message\":\"Resource not accessible\"}",
                &BTreeMap::new()
            ),
            Termination::PermissionDenied { .. }
        ));
    }
}
