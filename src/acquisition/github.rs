use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use time::OffsetDateTime;

use super::http::{build_exchange, format_time, next_link, percent_encode, sanitize_diagnostic};
use super::transcript::{
    seal_transcript, AcquisitionTermination, AcquisitionTranscript, HttpExchange, HttpRequest,
    TranscriptContents, GITHUB_BRANCH_PROTECTION_CONTRACT,
    GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT, GITHUB_CHECK_RUNS_CONTRACT,
    GITHUB_COMMIT_STATUSES_CONTRACT, GITHUB_PULL_REQUEST_REVIEWS_CONTRACT,
    GITHUB_REPOSITORY_MUTATIONS_CONTRACT,
};
use crate::error::{Error, Result};
use crate::model::{Proposition, Subject, TimeRange};

pub(super) const GITHUB_API_ORIGIN: &str = "https://api.github.com";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// the github resources that core can acquire for packs.
pub enum GithubRemoteResource {
    BranchProtection,
    CheckRuns,
    CommitStatuses,
    RepositoryMutations,
    PullRequestReviews,
    BuildValidationHistory,
}

#[derive(Debug, Clone)]
/// one provider-aware github acquisition requested by a pack.
pub struct GithubRemoteCapture {
    pub repository: String,
    pub branch: String,
    pub revision: String,
    pub subject: Subject,
    pub interval: TimeRange,
    pub resource: GithubRemoteResource,
    pub per_page: u16,
    pub max_pages: u16,
    pub captured_at: OffsetDateTime,
}

/// acquire one narrow github resource with credentials held only by core.
///
/// # Errors
///
/// returns an error when the plan is invalid, no credential is available, or
/// github cannot be reached. http failures are retained as transcript outcomes.
pub fn capture_github_remote(options: &GithubRemoteCapture) -> Result<AcquisitionTranscript> {
    validate_github_remote(options)?;
    let token = github_token()?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    capture_github_remote_with(options, |url| github_get(&agent, url, &token))
}

pub(super) fn capture_github_remote_with<F>(
    options: &GithubRemoteCapture,
    mut fetch: F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    validate_github_remote(options)?;
    if matches!(
        options.resource,
        GithubRemoteResource::RepositoryMutations
            | GithubRemoteResource::PullRequestReviews
            | GithubRemoteResource::BuildValidationHistory
    ) {
        return capture_github_history_with(options, &mut fetch);
    }
    if matches!(
        options.resource,
        GithubRemoteResource::CheckRuns | GithubRemoteResource::CommitStatuses
    ) {
        return capture_github_revision_with(options, &mut fetch);
    }
    let captured_at = format_time(options.captured_at)?;
    let (contract, proposition, initial_url) = github_remote_request(options);
    let mut exchanges = Vec::new();
    let mut url = initial_url.clone();
    let termination = loop {
        ensure_github_url(&url)?;
        let exchange = fetch(&url)?;
        let status = exchange.response.status;
        let response_body = exchange.response.body.clone();
        let response_headers = exchange.response.headers.clone();
        exchanges.push(exchange);

        if status != 200 {
            break classify_github_failure(status, &response_body, &response_headers);
        }

        match options.resource {
            GithubRemoteResource::BranchProtection if exchanges.len() == 1 => {
                let body: serde_json::Value =
                    serde_json::from_str(&response_body).map_err(|error| {
                        Error::Invalid(format!("github branch response is not JSON: {error}"))
                    })?;
                let protected = body
                    .get("protected")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| {
                        Error::Invalid(
                            "github branch response has no boolean protected field".into(),
                        )
                    })?;
                if !protected {
                    break AcquisitionTermination::Exhausted;
                }
                url = format!("{initial_url}/protection");
            }
            GithubRemoteResource::BranchProtection => {
                break AcquisitionTermination::Exhausted;
            }
            GithubRemoteResource::CheckRuns
            | GithubRemoteResource::CommitStatuses
            | GithubRemoteResource::RepositoryMutations
            | GithubRemoteResource::PullRequestReviews
            | GithubRemoteResource::BuildValidationHistory => unreachable!(),
        }
    };

    seal_transcript(TranscriptContents {
        collector_contract: contract.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: options.subject.clone(),
        proposition,
        requested_scope: options.interval.clone(),
        captured_at,
        initial_request: HttpRequest {
            method: "GET".into(),
            url: initial_url,
        },
        exchanges,
        termination,
    })
}

pub(super) fn github_remote_request(
    options: &GithubRemoteCapture,
) -> (&'static str, Proposition, String) {
    match options.resource {
        GithubRemoteResource::BranchProtection => (
            GITHUB_BRANCH_PROTECTION_CONTRACT,
            Proposition::BranchConfiguration,
            format!(
                "{GITHUB_API_ORIGIN}/repos/{}/branches/{}",
                options.repository,
                percent_encode(&options.branch)
            ),
        ),
        GithubRemoteResource::CheckRuns => (
            GITHUB_CHECK_RUNS_CONTRACT,
            Proposition::RevisionChecks,
            format!(
                "{GITHUB_API_ORIGIN}/repos/{}/commits/{}/check-runs?per_page={}&page=1",
                options.repository,
                percent_encode(&options.revision),
                options.per_page
            ),
        ),
        GithubRemoteResource::CommitStatuses => (
            GITHUB_COMMIT_STATUSES_CONTRACT,
            Proposition::RevisionChecks,
            format!(
                "{GITHUB_API_ORIGIN}/repos/{}/commits/{}/status?per_page={}&page=1",
                options.repository,
                percent_encode(&options.revision),
                options.per_page
            ),
        ),
        GithubRemoteResource::RepositoryMutations
        | GithubRemoteResource::PullRequestReviews
        | GithubRemoteResource::BuildValidationHistory => {
            unreachable!()
        }
    }
}

fn capture_github_revision_with<F>(
    options: &GithubRemoteCapture,
    fetch: &mut F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    let captured_at = format_time(options.captured_at)?;
    let (contract, proposition, url) = github_remote_request(options);
    let initial_url = format!("{GITHUB_API_ORIGIN}/repos/{}", options.repository);
    let mut exchanges = Vec::new();
    let (mut termination, alias) =
        github_repository_lookup(&initial_url, &options.repository, fetch, &mut exchanges)?;
    if termination.is_none() {
        let alias = alias.as_deref().map(|alias| (initial_url.as_str(), alias));
        termination = fetch_github_pages(&url, options.max_pages, fetch, &mut exchanges, alias)?;
    }
    seal_transcript(TranscriptContents {
        collector_contract: contract.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: options.subject.clone(),
        proposition,
        requested_scope: options.interval.clone(),
        captured_at,
        initial_request: HttpRequest {
            method: "GET".into(),
            url: initial_url,
        },
        exchanges,
        termination: termination.unwrap_or(AcquisitionTermination::Exhausted),
    })
}

fn capture_github_history_with<F>(
    options: &GithubRemoteCapture,
    fetch: &mut F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    let captured_at = format_time(options.captured_at)?;
    let initial_url = format!("{GITHUB_API_ORIGIN}/repos/{}", options.repository);
    let mut exchanges = Vec::new();
    let (mut termination, alias) =
        github_repository_lookup(&initial_url, &options.repository, fetch, &mut exchanges)?;
    let alias = alias.as_deref().map(|alias| (initial_url.as_str(), alias));
    if termination.is_none() {
        let url = github_activity_url(options);
        termination = fetch_github_pages(&url, options.max_pages, fetch, &mut exchanges, alias)?;
    }
    if termination.is_none() {
        let heads = github_activity_heads(&exchanges, options)?;
        for head in heads {
            let url =
                github_history_url(options, &format!("commits/{}/pulls", percent_encode(&head)));
            termination =
                fetch_github_pages(&url, options.max_pages, fetch, &mut exchanges, alias)?;
            if termination.is_some() {
                break;
            }
        }
    }
    if termination.is_none() && options.resource == GithubRemoteResource::PullRequestReviews {
        for number in github_associated_pull_requests(&exchanges) {
            let url = github_history_url(options, &format!("pulls/{number}/reviews"));
            termination =
                fetch_github_pages(&url, options.max_pages, fetch, &mut exchanges, alias)?;
            if termination.is_some() {
                break;
            }
        }
    }
    if termination.is_none() && options.resource == GithubRemoteResource::BuildValidationHistory {
        for revision in github_validation_revisions(&exchanges)? {
            for suffix in ["check-runs", "status"] {
                let path = format!("commits/{}/{suffix}", percent_encode(&revision));
                let url = github_history_url(options, &path);
                termination =
                    fetch_github_pages(&url, options.max_pages, fetch, &mut exchanges, alias)?;
                if termination.is_some() {
                    break;
                }
            }
            if termination.is_some() {
                break;
            }
        }
    }
    let (contract, proposition) = match options.resource {
        GithubRemoteResource::RepositoryMutations => (
            GITHUB_REPOSITORY_MUTATIONS_CONTRACT,
            Proposition::RepositoryMutations,
        ),
        GithubRemoteResource::PullRequestReviews => (
            GITHUB_PULL_REQUEST_REVIEWS_CONTRACT,
            Proposition::PullRequestReviews,
        ),
        GithubRemoteResource::BuildValidationHistory => (
            GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT,
            Proposition::BuildValidationResults,
        ),
        _ => unreachable!(),
    };
    seal_transcript(TranscriptContents {
        collector_contract: contract.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: options.subject.clone(),
        proposition,
        requested_scope: options.interval.clone(),
        captured_at,
        initial_request: HttpRequest {
            method: "GET".into(),
            url: initial_url,
        },
        exchanges,
        termination: termination.unwrap_or(AcquisitionTermination::Exhausted),
    })
}

pub(super) fn github_activity_url(options: &GithubRemoteCapture) -> String {
    format!(
        "{GITHUB_API_ORIGIN}/repos/{}/activity?ref={}&time_period=year&per_page={}",
        options.repository,
        percent_encode(&options.branch),
        options.per_page,
    )
}

/// the first page of the history population at `path` below the repository.
pub(super) fn github_history_url(options: &GithubRemoteCapture, path: &str) -> String {
    format!(
        "{GITHUB_API_ORIGIN}/repos/{}/{path}?per_page={}",
        options.repository, options.per_page,
    )
}

/// fetch every page of one github resource.
///
/// `alias` pairs the `/repos/{owner}/{name}` prefix with the `/repositories/{id}`
/// prefix a retained repository lookup proved equivalent; github pagination links
/// may use either.
fn fetch_github_pages<F>(
    initial_url: &str,
    max_pages: u16,
    fetch: &mut F,
    exchanges: &mut Vec<HttpExchange>,
    alias: Option<(&str, &str)>,
) -> Result<Option<AcquisitionTermination>>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    let mut url = initial_url.to_owned();
    for page in 0..max_pages {
        ensure_github_url(&url)?;
        let exchange = fetch(&url)?;
        let status = exchange.response.status;
        let next = next_link(&exchange.response.headers);
        let body = exchange.response.body.clone();
        let headers = exchange.response.headers.clone();
        exchanges.push(exchange);
        if status != 200 {
            return Ok(Some(classify_github_failure(status, &body, &headers)));
        }
        let Some(next_url) = next else {
            return Ok(None);
        };
        ensure_github_next_url(initial_url, &next_url, alias)?;
        if page + 1 == max_pages {
            return Ok(Some(AcquisitionTermination::Truncated { next_url }));
        }
        url = next_url;
    }
    unreachable!()
}

/// refuse a next link outside github or onto a resource other than `initial_url`'s.
fn ensure_github_next_url(
    initial_url: &str,
    next_url: &str,
    alias: Option<(&str, &str)>,
) -> Result<()> {
    ensure_github_url(next_url)?;
    let path = |url: &str| canonical_github_path(url.split('?').next().unwrap_or(""), alias);
    if path(next_url) != path(initial_url) {
        return Err(Error::Provenance(
            "github pagination changed the requested resource".into(),
        ));
    }
    Ok(())
}

/// fetch and retain the repository lookup that proves its numeric id.
fn github_repository_lookup<F>(
    url: &str,
    repository: &str,
    fetch: &mut F,
    exchanges: &mut Vec<HttpExchange>,
) -> Result<(Option<AcquisitionTermination>, Option<String>)>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    ensure_github_url(url)?;
    let lookup = fetch(url)?;
    let status = lookup.response.status;
    let failure = (status != 200)
        .then(|| classify_github_failure(status, &lookup.response.body, &lookup.response.headers));
    exchanges.push(lookup);
    if failure.is_some() {
        return Ok((failure, None));
    }
    let alias = github_repository_alias(exchanges, repository).ok_or_else(|| {
        Error::Provenance(format!(
            "github did not identify repository {repository} by id"
        ))
    })?;
    Ok((None, Some(alias)))
}

/// the `/repositories/{id}` prefix a retained, successful repository lookup proves
/// equivalent to `/repos/{repository}`.
pub(super) fn github_repository_alias(
    exchanges: &[HttpExchange],
    repository: &str,
) -> Option<String> {
    let lookup = exchanges.first()?;
    if lookup.request.url != format!("{GITHUB_API_ORIGIN}/repos/{repository}")
        || lookup.response.status != 200
    {
        return None;
    }
    let body = serde_json::from_str::<serde_json::Value>(&lookup.response.body).ok()?;
    let id = body.get("id").and_then(serde_json::Value::as_u64)?;
    body.get("full_name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(repository))
        .then(|| format!("{GITHUB_API_ORIGIN}/repositories/{id}"))
}

/// rewrite an aliased `/repositories/{id}` path, including the `/status/{ref}` route github
/// pages a combined status through, onto its `/repos/{owner}/{name}` form.
pub(super) fn canonical_github_path(path: &str, alias: Option<(&str, &str)>) -> String {
    alias
        .and_then(|(canonical, alias)| {
            path.strip_prefix(alias)
                .filter(|rest| rest.is_empty() || rest.starts_with('/'))
                .map(|rest| match rest.strip_prefix("/status/") {
                    Some(reference) if !reference.is_empty() && !reference.contains('/') => {
                        format!("{canonical}/commits/{reference}/status")
                    }
                    _ => format!("{canonical}{rest}"),
                })
        })
        .unwrap_or_else(|| path.into())
}

pub(super) fn github_activity_heads(
    exchanges: &[HttpExchange],
    options: &GithubRemoteCapture,
) -> Result<std::collections::BTreeSet<String>> {
    let from = crate::parse_timestamp(&options.interval.from)?;
    let until = crate::parse_timestamp(&options.interval.until)?;
    let reference = format!("refs/heads/{}", options.branch);
    let mut heads = std::collections::BTreeSet::new();
    for exchange in exchanges
        .iter()
        .filter(|exchange| exchange.request.url.contains("/activity?"))
    {
        let values: Vec<serde_json::Value> = serde_json::from_str(&exchange.response.body)
            .map_err(|error| {
                Error::Invalid(format!("github activity response is not JSON: {error}"))
            })?;
        for value in values {
            let Some(timestamp) = value.get("timestamp").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let timestamp = crate::parse_timestamp(timestamp)?;
            if value.get("ref").and_then(serde_json::Value::as_str) == Some(&reference)
                && timestamp >= from
                && timestamp < until
            {
                if let Some(head) = value.get("after").and_then(serde_json::Value::as_str) {
                    heads.insert(head.into());
                }
            }
        }
    }
    Ok(heads)
}

pub(super) fn github_associated_pull_requests(
    exchanges: &[HttpExchange],
) -> std::collections::BTreeSet<u64> {
    exchanges
        .iter()
        .filter(|exchange| {
            exchange.request.url.contains("/commits/") && exchange.request.url.contains("/pulls?")
        })
        .filter_map(|exchange| {
            serde_json::from_str::<Vec<serde_json::Value>>(&exchange.response.body).ok()
        })
        .flatten()
        .filter_map(|pull| pull.get("number").and_then(serde_json::Value::as_u64))
        .collect()
}

pub(super) fn github_validation_revisions(
    exchanges: &[HttpExchange],
) -> Result<std::collections::BTreeSet<String>> {
    let mut revisions = std::collections::BTreeSet::new();
    for exchange in exchanges.iter().filter(|exchange| {
        exchange.request.url.contains("/commits/") && exchange.request.url.contains("/pulls?")
    }) {
        let pulls: Vec<serde_json::Value> =
            serde_json::from_str(&exchange.response.body).map_err(|error| {
                Error::Invalid(format!("github pull response is not JSON: {error}"))
            })?;
        for pull in pulls {
            for field in ["merge_commit_sha", "head"] {
                let revision = if field == "head" {
                    pull.pointer("/head/sha")
                } else {
                    pull.get(field)
                };
                if let Some(revision) = revision
                    .and_then(serde_json::Value::as_str)
                    .filter(|revision| !revision.is_empty())
                {
                    revisions.insert(revision.to_owned());
                }
            }
        }
    }
    Ok(revisions)
}

fn validate_github_remote(options: &GithubRemoteCapture) -> Result<()> {
    if options.per_page == 0
        || options.per_page > 100
        || options.max_pages == 0
        || options.max_pages > 1_000
    {
        return Err(Error::Invalid(
            "github per-page must be between 1 and 100 and max-pages between 1 and 1000".into(),
        ));
    }
    let parts = options.repository.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(Error::Invalid(
            "github repository must be an owner/name pair".into(),
        ));
    }
    if options.branch.is_empty() || options.revision.is_empty() {
        return Err(Error::Invalid(
            "github acquisition requires branch and revision context".into(),
        ));
    }
    if matches!(
        options.resource,
        GithubRemoteResource::CheckRuns | GithubRemoteResource::CommitStatuses
    ) && !(matches!(options.revision.len(), 40 | 64)
        && options
            .revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(Error::Invalid(
            "github check runs and commit statuses require a full lowercase commit id".into(),
        ));
    }
    Ok(())
}

fn github_token() -> Result<String> {
    if let Ok(output) = Command::new("gh").args(["auth", "token"]).output() {
        if output.status.success() {
            let token = String::from_utf8(output.stdout).map_err(|_| {
                Error::Invalid("github credential helper returned non-utf8 data".into())
            })?;
            let token = token.trim().to_owned();
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(token);
        }
    }
    Err(Error::Collection(
        "GitHub source requires authentication; authenticate with `gh auth login` or set GITHUB_TOKEN"
            .into(),
    ))
}

fn github_get(agent: &ureq::Agent, url: &str, token: &str) -> Result<HttpExchange> {
    ensure_github_url(url)?;
    let mut response = agent
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("authorization", &format!("Bearer {token}"))
        .header(
            "user-agent",
            concat!("divinate/", env!("CARGO_PKG_VERSION")),
        )
        .header("x-github-api-version", "2022-11-28")
        .call()
        .map_err(|error| {
            Error::Collection(format!(
                "github request failed before receiving a response: {}",
                sanitize_diagnostic(&error.to_string())
            ))
        })?;
    let status = response.status().as_u16();
    let headers = retained_github_headers(response.headers());
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| Error::Collection("github response body could not be read".into()))?;
    reject_reflected_credential(&body, &headers, token)?;
    build_exchange(url, status, headers, body, "github")
}

fn reject_reflected_credential(
    body: &str,
    headers: &BTreeMap<String, String>,
    token: &str,
) -> Result<()> {
    if body.contains(token) || headers.values().any(|value| value.contains(token)) {
        return Err(Error::Collection(
            "github response reflected credential material; response was not retained".into(),
        ));
    }
    Ok(())
}

fn retained_github_headers(headers: &ureq::http::HeaderMap) -> BTreeMap<String, String> {
    const ALLOWED: &[&str] = &[
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
    ];
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            ALLOWED
                .contains(&name.as_str())
                .then(|| value.to_str().ok().map(|value| (name, value.to_owned())))?
        })
        .collect()
}

pub(super) fn ensure_github_url(url: &str) -> Result<()> {
    let allowed = url
        .strip_prefix(GITHUB_API_ORIGIN)
        .is_some_and(|path| path.starts_with('/'));
    if !allowed || url.contains('@') || url.contains('#') {
        return Err(Error::Invalid(format!(
            "github acquisition refused URL outside {GITHUB_API_ORIGIN}"
        )));
    }
    Ok(())
}

fn classify_github_failure(
    status: u16,
    body: &str,
    headers: &BTreeMap<String, String>,
) -> AcquisitionTermination {
    let diagnostic = github_diagnostic(status, body);
    match status {
        301 | 302 | 303 | 307 | 308 => AcquisitionTermination::UnsafeRedirect {
            location: headers.get("location").cloned().unwrap_or_default(),
        },
        401 => AcquisitionTermination::Unauthenticated { diagnostic },
        403 if !github_rate_limited(&diagnostic, headers) => {
            AcquisitionTermination::PermissionDenied { diagnostic }
        }
        403 | 429 => AcquisitionTermination::RateLimited {
            diagnostic,
            reset_at: headers.get("x-ratelimit-reset").cloned(),
        },
        404 => AcquisitionTermination::NotFound { diagnostic },
        _ => AcquisitionTermination::Failed { diagnostic },
    }
}

fn github_rate_limited(diagnostic: &str, headers: &BTreeMap<String, String>) -> bool {
    headers.get("x-ratelimit-remaining").map(String::as_str) == Some("0")
        || headers.contains_key("retry-after")
        || mentions_rate_limit(diagnostic)
}

fn mentions_rate_limit(diagnostic: &str) -> bool {
    diagnostic.to_ascii_lowercase().contains("rate limit")
}

fn github_diagnostic(status: u16, body: &str) -> String {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "request failed".into());
    sanitize_diagnostic(&format!("HTTP {status}: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::assessment::{assess, ContractRegistry, EnumerationStatus};
    use crate::acquisition::test_support::{exchange, github_lookup, remote, REVISION};
    use crate::hex_digest;

    #[test]
    fn unprotected_branch_is_complete_configuration_evidence() {
        let options = remote(GithubRemoteResource::BranchProtection);
        let transcript = capture_github_remote_with(&options, |url| {
            Ok(exchange(
                url,
                200,
                r#"{"protected":false}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.authority, vec![Proposition::BranchConfiguration]);
        assert_eq!(
            transcript.contents.exchanges[0].response.body,
            r#"{"protected":false}"#
        );
    }

    #[test]
    fn permission_denial_is_not_an_unprotected_branch() {
        let options = remote(GithubRemoteResource::BranchProtection);
        let transcript = capture_github_remote_with(&options, |url| {
            Ok(exchange(
                url,
                403,
                r#"{"message":"Resource not accessible"}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::PermissionDenied);
        assert_eq!(assessment.authority, []);
        assert_eq!(transcript.contents.exchanges.len(), 1);
    }

    #[test]
    fn protected_branch_collects_the_detailed_policy() {
        let options = remote(GithubRemoteResource::BranchProtection);
        let mut request = 0;
        let transcript = capture_github_remote_with(&options, |url| {
            request += 1;
            if request == 1 {
                Ok(exchange(url, 200, r#"{"protected":true}"#, BTreeMap::new()))
            } else {
                assert!(url.ends_with("/branches/main/protection"));
                Ok(exchange(
                    url,
                    200,
                    r#"{"required_pull_request_reviews":{"required_approving_review_count":2}}"#,
                    BTreeMap::new(),
                ))
            }
        })
        .unwrap();
        assert_eq!(transcript.contents.exchanges.len(), 2);
        assert_eq!(
            assess(&transcript, &ContractRegistry::default()).enumeration,
            EnumerationStatus::Complete
        );
    }

    #[test]
    fn check_run_pagination_retains_incomplete_state() {
        let mut options = remote(GithubRemoteResource::CheckRuns);
        options.max_pages = 1;
        let transcript = capture_github_remote_with(&options, |url| {
            if let Some(lookup) = github_lookup(url) {
                return Ok(lookup);
            }
            Ok(exchange(
                url,
                200,
                r#"{"total_count":2,"check_runs":[{"name":"ci"}]}"#,
                BTreeMap::from([(
                    "link".into(),
                    format!("<https://api.github.com/repos/cyberwitchery/divinate/commits/{REVISION}/check-runs?per_page=100&page=2>; rel=\"next\""),
                )]),
            ))
        })
        .unwrap();
        assert_eq!(
            assess(&transcript, &ContractRegistry::default()).enumeration,
            EnumerationStatus::Truncated
        );
    }

    #[test]
    fn count_mismatch_cannot_establish_complete_coverage() {
        for (resource, body) in [
            (
                GithubRemoteResource::CheckRuns,
                r#"{"total_count":2,"check_runs":[{"name":"ci"}]}"#,
            ),
            (
                GithubRemoteResource::CommitStatuses,
                r#"{"state":"success","total_count":2,"statuses":[{"context":"ci","state":"success"}]}"#,
            ),
        ] {
            let transcript = capture_github_remote_with(&remote(resource), |url| {
                if let Some(lookup) = github_lookup(url) {
                    return Ok(lookup);
                }
                Ok(exchange(url, 200, body, BTreeMap::new()))
            })
            .unwrap();
            let assessment = assess(&transcript, &ContractRegistry::default());
            assert_eq!(
                assessment.enumeration,
                EnumerationStatus::Truncated,
                "{resource:?}"
            );
            assert_eq!(assessment.authority, [], "{resource:?}");
        }
    }

    #[test]
    fn commit_statuses_retain_complete_paginated_current_state() {
        let options = remote(GithubRemoteResource::CommitStatuses);
        let mut page = 0;
        let transcript = capture_github_remote_with(&options, |url| {
            if let Some(lookup) = github_lookup(url) {
                return Ok(lookup);
            }
            page += 1;
            if page == 1 {
                assert!(url.ends_with(&format!("/commits/{REVISION}/status?per_page=100&page=1")));
                Ok(exchange(
                    url,
                    200,
                    r#"{"state":"failure","total_count":2,"statuses":[{"context":"ci","state":"success"}]}"#,
                    BTreeMap::from([(
                        "link".into(),
                        format!("<https://api.github.com/repos/cyberwitchery/divinate/commits/{REVISION}/status?per_page=100&page=2>; rel=\"next\""),
                    )]),
                ))
            } else {
                Ok(exchange(
                    url,
                    200,
                    r#"{"state":"failure","total_count":2,"statuses":[{"context":"security","state":"failure"}]}"#,
                    BTreeMap::new(),
                ))
            }
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.items, 2);
        assert_eq!(assessment.authority, vec![Proposition::RevisionChecks]);
    }

    #[test]
    fn rate_limit_and_redirect_are_distinct_failures() {
        const PRIMARY: &str = "API rate limit exceeded for user ID 1.";
        const SECONDARY: &str = "You have exceeded a secondary rate limit. Please wait a few minutes before you try again.";
        const ABUSE: &str = "You have triggered an abuse detection mechanism. Please wait a few minutes before you try again.";
        const DENIED: &str = "Resource not accessible by integration";
        let exhausted = [("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "123")];
        let remaining = [
            ("x-ratelimit-remaining", "4999"),
            ("x-ratelimit-reset", "123"),
        ];
        let retry = [("x-ratelimit-remaining", "4999"), ("retry-after", "60")];
        for (status, message, headers, kind, reset_at) in [
            (403, PRIMARY, &exhausted[..], "rate_limited", Some("123")),
            (429, PRIMARY, &exhausted[..], "rate_limited", Some("123")),
            (403, "", &exhausted[..], "rate_limited", Some("123")),
            (403, ABUSE, &retry[..], "rate_limited", None),
            (403, SECONDARY, &remaining[..], "rate_limited", Some("123")),
            (429, SECONDARY, &[][..], "rate_limited", None),
            (403, DENIED, &remaining[..], "permission_denied", None),
        ] {
            let body = serde_json::json!({ "message": message }).to_string();
            let headers = headers
                .iter()
                .map(|&(name, value)| (name.to_owned(), value.to_owned()))
                .collect();
            let outcome =
                serde_json::to_value(classify_github_failure(status, &body, &headers)).unwrap();
            assert_eq!(outcome["kind"], kind, "{status} {message}");
            assert_eq!(outcome["reset_at"].as_str(), reset_at, "{status} {message}");
        }
        let redirect = classify_github_failure(
            302,
            r#"{"message":"Moved"}"#,
            &BTreeMap::from([("location".into(), "https://evil.invalid/".into())]),
        );
        assert!(matches!(
            redirect,
            AcquisitionTermination::UnsafeRedirect { .. }
        ));
        assert!(matches!(
            classify_github_failure(404, r#"{"message":"Not Found"}"#, &BTreeMap::new()),
            AcquisitionTermination::NotFound { .. }
        ));
        assert!(ensure_github_url("https://evil.invalid/steal").is_err());
    }

    #[test]
    fn retained_headers_never_include_credentials() {
        let token = "divinate-test-token-4f6c0f504a";
        let mut headers = ureq::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert("set-cookie", format!("session={token}").parse().unwrap());
        headers.insert("x-github-request-id", "request-1".parse().unwrap());
        let retained = retained_github_headers(&headers);
        let serialized = serde_json::to_string(&retained).unwrap();
        assert_eq!(
            retained.get("x-github-request-id").map(String::as_str),
            Some("request-1")
        );
        assert!(!serialized.contains(token));
        assert!(!retained.contains_key("authorization"));
        assert!(!retained.contains_key("set-cookie"));
        assert!(reject_reflected_credential("safe", &retained, token).is_ok());
        assert!(reject_reflected_credential(token, &retained, token).is_err());
        assert!(reject_reflected_credential(
            "safe",
            &BTreeMap::from([(
                "location".into(),
                format!("https://example.invalid/{token}")
            )]),
            token,
        )
        .is_err());
    }

    #[test]
    fn github_build_validation_history_requires_both_status_mechanisms() {
        let options = remote(GithubRemoteResource::BuildValidationHistory);
        let transcript = capture_github_remote_with(&options, |url| {
            if let Some(lookup) = github_lookup(url) {
                return Ok(lookup);
            }
            let body = if url.contains("/activity?") {
                r#"[{"id":"a","activity_type":"pr_merge","timestamp":"2026-09-11T12:00:00Z","ref":"refs/heads/main","after":"merge"}]"#
            } else if url.contains("/pulls?") {
                r#"[{"number":1,"merge_commit_sha":"merge","merged_at":"2026-09-11T12:00:00Z","base":{"ref":"main"},"head":{"sha":"head"}}]"#
            } else if url.contains("/check-runs?") {
                r#"{"total_count":1,"check_runs":[{"name":"ci","conclusion":"success","completed_at":"1969-12-31T23:59:00Z"}]}"#
            } else {
                r#"{"state":"success","total_count":1,"statuses":[{"context":"ci","state":"success","updated_at":"1969-12-31T23:59:00Z"}]}"#
            };
            Ok(exchange(url, 200, body, BTreeMap::new()))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(
            assessment.authority,
            vec![Proposition::BuildValidationResults]
        );
        assert_eq!(transcript.contents.exchanges.len(), 7);
        assert!(transcript
            .contents
            .exchanges
            .iter()
            .any(|exchange| exchange.request.url.contains("/commits/head/check-runs?")));

        let mut contents = transcript.contents.clone();
        contents
            .exchanges
            .retain(|exchange| !exchange.request.url.contains("/commits/head/status?"));
        let runs = contents
            .exchanges
            .iter_mut()
            .find(|exchange| exchange.request.url.contains("/commits/merge/check-runs?"))
            .unwrap();
        runs.response.body = runs.response.body.replace(":1,", ":2,");
        runs.response.body_sha256 = hex_digest(runs.response.body.as_bytes());
        let assessment = assess(
            &seal_transcript(contents).unwrap(),
            &ContractRegistry::default(),
        );
        assert_eq!(
            assessment.reasons,
            ["github history lacks status enumeration for an integration revision"]
        );
    }

    #[test]
    fn github_build_validation_history_counts_pages_on_the_repository_alias() {
        for (route, records) in [
            ("commits/{revision}/check-runs", "check_runs"),
            ("status/{revision}", "statuses"),
        ] {
            let page = |revision: &str| {
                let route = route.replace("{revision}", revision);
                format!("https://api.github.com/repositories/123/{route}?per_page=100&page=2")
            };
            let options = remote(GithubRemoteResource::BuildValidationHistory);
            let transcript = capture_github_remote_with(&options, |url| {
                if let Some(lookup) = github_lookup(url) {
                    return Ok(lookup);
                }
                let mut headers = BTreeMap::new();
                let body = if url.contains("/activity?") {
                    r#"[{"id":"a","activity_type":"pr_merge","timestamp":"2026-09-11T12:00:00Z","ref":"refs/heads/main","after":"merge"}]"#.into()
                } else if url.contains("/pulls?") {
                    r#"[{"number":1,"merge_commit_sha":"merge","merged_at":"2026-09-11T12:00:00Z","base":{"ref":"main"},"head":{"sha":"head"}}]"#.into()
                } else {
                    let field = if url.contains("/check-runs?") {
                        "check_runs"
                    } else {
                        "statuses"
                    };
                    if field == records && url.contains("/repos/") {
                        let revision = url.split("/commits/").nth(1).unwrap().split('/').next();
                        let next = page(revision.unwrap());
                        headers.insert("link".into(), format!("<{next}>; rel=\"next\""));
                    }
                    let total = if field == records { 2 } else { 1 };
                    format!(r#"{{"total_count":{total},"{field}":[{{}}]}}"#)
                };
                Ok(exchange(url, 200, &body, headers))
            })
            .unwrap();
            let assessment = assess(&transcript, &ContractRegistry::default());
            assert_eq!(
                assessment.enumeration,
                EnumerationStatus::Complete,
                "{records}: {:?}",
                assessment.reasons
            );
            assert_eq!(
                assessment.authority,
                vec![Proposition::BuildValidationResults]
            );

            let mut elsewhere = transcript.contents.clone();
            let second = elsewhere
                .exchanges
                .iter()
                .position(|exchange| exchange.request.url == page("head"))
                .unwrap();
            elsewhere.exchanges[second - 1]
                .response
                .headers
                .insert("link".into(), format!("<{}>; rel=\"next\"", page("other")));
            elsewhere.exchanges[second].request.url = page("other");
            let assessment = assess(
                &seal_transcript(elsewhere).unwrap(),
                &ContractRegistry::default(),
            );
            assert_eq!(assessment.enumeration, EnumerationStatus::Failed);
            assert!(
                assessment
                    .reasons
                    .iter()
                    .any(|reason| reason.ends_with("but 1 were retained")),
                "{records}: {:?}",
                assessment.reasons
            );

            let mut overstated = transcript.contents.clone();
            let first = &mut overstated.exchanges[second - 1].response;
            first.body = first.body.replace(":2,", ":3,");
            first.body_sha256 = hex_digest(first.body.as_bytes());
            let mut unrequested = transcript.contents.clone();
            unrequested.exchanges.remove(second - 1);
            for (contents, reason) in [
                (overstated, "github reported 3 "),
                (unrequested, "github history lacks "),
            ] {
                let assessment = assess(
                    &seal_transcript(contents).unwrap(),
                    &ContractRegistry::default(),
                );
                assert!(
                    assessment.reasons.iter().any(|r| r.starts_with(reason)),
                    "{records}: {:?}",
                    assessment.reasons
                );
            }
        }
    }

    #[test]
    fn github_history_follows_pagination_onto_the_numeric_repository_path() {
        let options = remote(GithubRemoteResource::RepositoryMutations);
        let fetch = |repository_id: u64| {
            move |url: &str| {
                let mut headers = BTreeMap::new();
                let body = if url == "https://api.github.com/repos/cyberwitchery/divinate" {
                    format!(r#"{{"id":{repository_id},"full_name":"cyberwitchery/divinate"}}"#)
                } else if url.contains("/repos/cyberwitchery/divinate/activity?") {
                    headers.insert(
                        "link".into(),
                        "<https://api.github.com/repositories/123/activity?ref=main&time_period=year&per_page=100&after=cursor>; rel=\"next\"".into(),
                    );
                    r#"[{"id":1,"activity_type":"push","ref":"refs/heads/main","timestamp":"2026-09-11T12:00:00Z","after":"one"}]"#.into()
                } else if url.starts_with("https://api.github.com/repositories/123/activity?") {
                    r#"[{"id":2,"activity_type":"push","ref":"refs/heads/main","timestamp":"2026-09-11T11:00:00Z","after":"two"}]"#.into()
                } else {
                    assert!(url.contains("/pulls?"), "{url}");
                    "[]".into()
                };
                Ok(exchange(url, 200, &body, headers))
            }
        };
        let transcript = capture_github_remote_with(&options, fetch(123)).unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.authority, vec![Proposition::RepositoryMutations]);
        assert!(transcript
            .contents
            .exchanges
            .iter()
            .any(|exchange| exchange.request.url.contains("/repositories/123/activity?")));

        let error = capture_github_remote_with(&options, fetch(999)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("github pagination changed the requested resource"),
            "{error}"
        );
    }

    #[test]
    fn github_revision_pagination_stays_on_the_proven_repository_and_revision() {
        for (resource, route, records) in [
            (
                GithubRemoteResource::CheckRuns,
                "commits/{revision}/check-runs",
                "check_runs",
            ),
            (
                GithubRemoteResource::CommitStatuses,
                "status/{revision}",
                "statuses",
            ),
        ] {
            let page = |repository_id: u64, revision: &str| {
                let route = route.replace("{revision}", revision);
                format!("https://api.github.com/repositories/{repository_id}/{route}?per_page=100&page=2")
            };
            let fetch = |next: String| {
                move |url: &str| {
                    if let Some(lookup) = github_lookup(url) {
                        return Ok(lookup);
                    }
                    let mut headers = BTreeMap::new();
                    if url.contains("/repos/") {
                        headers.insert("link".into(), format!("<{next}>; rel=\"next\""));
                    }
                    let body = format!(r#"{{"total_count":2,"{records}":[{{}}]}}"#);
                    Ok(exchange(url, 200, &body, headers))
                }
            };
            let transcript =
                capture_github_remote_with(&remote(resource), fetch(page(123, REVISION))).unwrap();
            let assessment = assess(&transcript, &ContractRegistry::default());
            assert_eq!(
                assessment.enumeration,
                EnumerationStatus::Complete,
                "{resource:?}"
            );
            assert_eq!(assessment.items, 2, "{resource:?}");
            assert_eq!(assessment.authority, vec![Proposition::RevisionChecks]);

            for next in [page(999, REVISION), page(123, &"f".repeat(40))] {
                let error = capture_github_remote_with(&remote(resource), fetch(next)).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("github pagination changed the requested resource"),
                    "{resource:?}: {error}"
                );
            }
            for revision in ["main".to_owned(), REVISION[..7].to_owned(), "g".repeat(40)] {
                let mut by_ref = remote(resource);
                by_ref.revision = revision;
                let error =
                    capture_github_remote_with(&by_ref, fetch(page(123, REVISION))).unwrap_err();
                assert!(
                    error.to_string().contains("full lowercase commit id"),
                    "{error}"
                );
            }

            let mut unproven = transcript.contents.clone();
            unproven.exchanges.remove(0);
            unproven.initial_request = unproven.exchanges[0].request.clone();
            let assessment = assess(
                &seal_transcript(unproven).unwrap(),
                &ContractRegistry::default(),
            );
            assert_eq!(
                assessment.enumeration,
                EnumerationStatus::Complete,
                "{resource:?}"
            );

            let mut moved = transcript.contents.clone();
            moved.exchanges[1].response.headers.insert(
                "link".into(),
                format!("<{}>; rel=\"next\"", page(999, REVISION)),
            );
            moved.exchanges[2].request.url = page(999, REVISION);
            let assessment = assess(
                &seal_transcript(moved).unwrap(),
                &ContractRegistry::default(),
            );
            assert_eq!(
                assessment.enumeration,
                EnumerationStatus::Failed,
                "{resource:?}"
            );
        }
    }

    #[test]
    fn github_history_retains_mutation_association_and_review_requests() {
        let options = remote(GithubRemoteResource::PullRequestReviews);
        let transcript = capture_github_remote_with(&options, |url| {
            if let Some(lookup) = github_lookup(url) {
                return Ok(lookup);
            }
            let body = if url.contains("/activity?") {
                r#"[{"id":1,"ref":"refs/heads/main","timestamp":"2026-09-11T12:00:00Z","after":"integrated"}]"#
            } else if url.contains("/commits/integrated/pulls?") {
                r#"[{"number":42,"base":{"ref":"main"},"merged_at":"2026-09-11T12:00:00Z","merge_commit_sha":"integrated"}]"#
            } else {
                assert!(url.contains("/pulls/42/reviews?"));
                r#"[{"state":"APPROVED","submitted_at":"2026-09-11T11:00:00Z","user":{"login":"reviewer"}}]"#
            };
            Ok(exchange(url, 200, body, BTreeMap::new()))
        }).unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.authority, vec![Proposition::PullRequestReviews]);
        assert_eq!(transcript.contents.exchanges.len(), 4);
        let mut missing = transcript.contents.clone();
        missing.exchanges.pop();
        let missing = seal_transcript(missing).unwrap();
        assert_eq!(
            assess(&missing, &ContractRegistry::default()).enumeration,
            EnumerationStatus::Failed
        );
    }
}
