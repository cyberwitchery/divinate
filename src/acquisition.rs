//! http and api acquisition transcripts.
//!
//! [`AcquisitionTranscript`] stores request urls, exact response bodies,
//! pagination metadata, and termination. [`assess`] verifies the transcript and
//! applies its versioned source contract. [`ContractRegistry`] can withdraw
//! current authority without changing retained evidence.
//!
//! authorization headers and cookies are invalid transcript data. [`compare`]
//! requires equal contracts, subjects, propositions, scopes, and initial requests.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::hex_digest;
use crate::model::{Proposition, Subject, TimeRange};

/// the acquisition transcript format version this build reads and writes.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1.0";
/// commit ancestry visible through one repository ref and credential.
///
/// this contract does not establish how a commit reached the ref.
pub const GITHUB_COMMITS_CONTRACT: &str = "github-commits/v1";
/// one branch-protection response. establishes configured intent only.
pub const GITHUB_BRANCH_PROTECTION_CONTRACT: &str = "github-branch-protection/v1";
/// check runs reported for one exact repository revision.
pub const GITHUB_CHECK_RUNS_CONTRACT: &str = "github-check-runs/v1";
/// latest classic commit status for each context on one exact repository revision.
pub const GITHUB_COMMIT_STATUSES_CONTRACT: &str = "github-commit-statuses/v1";
/// current azure devops policies that apply to one repository branch.
pub const AZURE_DEVOPS_BRANCH_POLICY_CONTRACT: &str = "azure-devops-branch-policy/v1";

const GITHUB_API_ORIGIN: &str = "https://api.github.com";
const AZURE_DEVOPS_API_ORIGIN: &str = "https://dev.azure.com";
const AZURE_DEVOPS_RESOURCE: &str = "499b84ac-1321-427f-aa17-267ca6975798";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// the github resources that core can acquire for packs.
pub enum GithubRemoteResource {
    BranchProtection,
    CheckRuns,
    CommitStatuses,
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

#[derive(Debug, Clone)]
/// one provider-aware azure devops acquisition requested by a pack.
pub struct AzureDevopsRemoteCapture {
    pub organization: String,
    pub project: String,
    pub repository: String,
    pub branch: String,
    pub subject: Subject,
    pub interval: TimeRange,
    pub max_pages: u16,
    pub captured_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
/// options for capturing a github commit enumeration.
pub struct GithubCapture {
    pub repository: String,
    pub branch: String,
    pub interval: TimeRange,
    pub per_page: u16,
    pub max_pages: u16,
    pub captured_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
/// options for capturing one github branch-protection response.
pub struct GithubBranchProtectionCapture {
    pub repository: String,
    pub branch: String,
    pub interval: TimeRange,
    pub captured_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one preserved http or api interaction, addressed by the digest of its contents.
pub struct AcquisitionTranscript {
    pub id: String,
    pub schema_version: String,
    pub contents: TranscriptContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// the request, responses, and termination stored in a transcript.
pub struct TranscriptContents {
    /// the versioned semantic identity of what this endpoint establishes.
    pub collector_contract: String,
    /// the implementation version, recorded separately from the contract.
    pub collector_version: String,
    pub subject: Subject,
    pub proposition: Proposition,
    /// the interval asked for, which the response may not have covered.
    pub requested_scope: TimeRange,
    pub captured_at: String,
    pub initial_request: HttpRequest,
    pub exchanges: Vec<HttpExchange>,
    pub termination: AcquisitionTermination,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the method and url of one request, with no headers retained.
pub struct HttpRequest {
    pub method: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one request and the response it produced.
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// a response with exact body bytes.
///
/// retained headers are limited to pagination and contract inputs.
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// digest of the retained body, recomputed on every verification.
    pub body_sha256: String,
    /// items in this response, checked against the retained body on verification.
    pub item_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// how enumeration ended.
pub enum AcquisitionTermination {
    Exhausted,
    Truncated {
        next_url: String,
    },
    Unauthenticated {
        diagnostic: String,
    },
    PermissionDenied {
        diagnostic: String,
    },
    NotFound {
        diagnostic: String,
    },
    RateLimited {
        diagnostic: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reset_at: Option<String>,
    },
    UnsafeRedirect {
        location: String,
    },
    Failed {
        diagnostic: String,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// integrity, contract, enumeration, and authority from offline replay.
pub struct AcquisitionAssessment {
    pub transcript_id: String,
    pub integrity: IntegrityStatus,
    pub contract: ContractStatus,
    pub enumeration: EnumerationStatus,
    pub authority: Vec<Proposition>,
    pub pages: u64,
    pub items: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether the retained bytes still match their digests.
pub enum IntegrityStatus {
    Verified,
    Failed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
/// whether the collector contract is accepted, unknown, or withdrawn.
///
/// [`Self::Invalidated`] withdraws current authority.
pub enum ContractStatus {
    Accepted,
    Unsupported,
    Invalidated {
        discovered_at: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether enumeration was complete, truncated, denied, or failed.
pub enum EnumerationStatus {
    Complete,
    Truncated,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    RateLimited,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// the contracts currently known to be unsound.
pub struct ContractRegistry {
    pub invalidations: Vec<ContractInvalidation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// one withdrawal, with when it was discovered and why.
pub struct ContractInvalidation {
    pub contract: String,
    pub discovered_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// the result of comparing two acquisitions of the same fixed scope.
pub struct RerunComparison {
    pub left_transcript_id: String,
    pub right_transcript_id: String,
    pub outcome: RerunOutcome,
    pub added_identities: Vec<String>,
    pub removed_identities: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// how two reruns of one scope relate.
///
/// records that disappeared between equal-scope runs.
pub enum RerunOutcome {
    Consistent,
    ContentChanged,
    CoverageChanged,
    NotComparable,
}

/// capture an authenticated github commit enumeration through the local `gh` cli.
///
/// # Errors
///
/// returns an error when options are invalid, `gh` cannot execute, or a response
/// cannot be parsed.
pub fn capture_github_commits(options: &GithubCapture) -> Result<AcquisitionTranscript> {
    if options.per_page == 0 || options.max_pages == 0 {
        return Err(Error::Invalid(
            "per-page and max-pages must be positive".into(),
        ));
    }
    let captured_at = format_time(options.captured_at)?;
    let initial_url = commits_url(options);
    let mut url = initial_url.clone();
    let mut exchanges = Vec::new();
    let termination;

    loop {
        let output = Command::new("gh")
            .args(["api", "--include", &url])
            .output()
            .map_err(|source| Error::Io {
                path: "gh".into(),
                source,
            })?;
        if !output.status.success() {
            let diagnostic = sanitize_diagnostic(&String::from_utf8_lossy(&output.stderr));
            termination = if diagnostic.to_ascii_lowercase().contains("authentication")
                || diagnostic.contains("HTTP 401")
                || diagnostic.contains("HTTP 403")
            {
                AcquisitionTermination::PermissionDenied { diagnostic }
            } else {
                AcquisitionTermination::Failed { diagnostic }
            };
            break;
        }

        let exchange = parse_exchange(&url, &output.stdout)?;
        let next = next_link(&exchange.response.headers);
        exchanges.push(exchange);
        if let Some(next_url) = next {
            if exchanges.len() == usize::from(options.max_pages) {
                termination = AcquisitionTermination::Truncated { next_url };
                break;
            }
            url = next_url;
        } else {
            termination = AcquisitionTermination::Exhausted;
            break;
        }
    }

    seal_transcript(TranscriptContents {
        collector_contract: GITHUB_COMMITS_CONTRACT.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: Subject {
            kind: "repository".into(),
            id: format!("github:{}", options.repository),
            qualifiers: BTreeMap::from([(
                "branch".into(),
                serde_json::Value::String(options.branch.clone()),
            )]),
        },
        proposition: Proposition::CommitAncestry,
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

/// capture one branch-protection response and its acquisition conditions.
///
/// # Errors
///
/// returns an error when `gh` cannot execute or emits an invalid response.
pub fn capture_github_branch_protection(
    options: &GithubBranchProtectionCapture,
) -> Result<AcquisitionTranscript> {
    let captured_at = format_time(options.captured_at)?;
    let url = format!(
        "repos/{}/branches/{}/protection",
        options.repository,
        percent_encode(&options.branch)
    );
    let output = Command::new("gh")
        .args(["api", "--include", &url])
        .output()
        .map_err(|source| Error::Io {
            path: "gh".into(),
            source,
        })?;
    let (exchanges, termination) = if output.status.success() {
        (
            vec![parse_exchange(&url, &output.stdout)?],
            AcquisitionTermination::Exhausted,
        )
    } else {
        let diagnostic = sanitize_diagnostic(&String::from_utf8_lossy(&output.stderr));
        let termination = if diagnostic.to_ascii_lowercase().contains("authentication")
            || diagnostic.contains("HTTP 401")
            || diagnostic.contains("HTTP 403")
        {
            AcquisitionTermination::PermissionDenied { diagnostic }
        } else {
            AcquisitionTermination::Failed { diagnostic }
        };
        (vec![], termination)
    };
    seal_transcript(TranscriptContents {
        collector_contract: GITHUB_BRANCH_PROTECTION_CONTRACT.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: Subject {
            kind: "repository".into(),
            id: format!("github:{}", options.repository),
            qualifiers: BTreeMap::from([(
                "branch".into(),
                serde_json::Value::String(options.branch.clone()),
            )]),
        },
        proposition: Proposition::BranchConfiguration,
        requested_scope: options.interval.clone(),
        captured_at,
        initial_request: HttpRequest {
            method: "GET".into(),
            url,
        },
        exchanges,
        termination,
    })
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

fn capture_github_remote_with<F>(
    options: &GithubRemoteCapture,
    mut fetch: F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    validate_github_remote(options)?;
    let captured_at = format_time(options.captured_at)?;
    let (contract, proposition, initial_url) = match options.resource {
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
    };
    let mut exchanges = Vec::new();
    let mut url = initial_url.clone();
    let termination = loop {
        ensure_github_url(&url)?;
        let exchange = fetch(&url)?;
        let status = exchange.response.status;
        let next = next_link(&exchange.response.headers);
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
                url = format!(
                    "{GITHUB_API_ORIGIN}/repos/{}/branches/{}/protection",
                    options.repository,
                    percent_encode(&options.branch)
                );
            }
            GithubRemoteResource::BranchProtection => {
                break AcquisitionTermination::Exhausted;
            }
            GithubRemoteResource::CheckRuns | GithubRemoteResource::CommitStatuses => {
                if let Some(next_url) = next {
                    ensure_github_url(&next_url)?;
                    if exchanges.len() == usize::from(options.max_pages) {
                        break AcquisitionTermination::Truncated { next_url };
                    }
                    url = next_url;
                } else {
                    break AcquisitionTermination::Exhausted;
                }
            }
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
        .map_err(|_| {
            Error::Collection("github request failed before receiving a response".into())
        })?;
    let status = response.status().as_u16();
    let headers = retained_github_headers(response.headers());
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| Error::Collection("github response body could not be read".into()))?;
    reject_reflected_credential(&body, &headers, token)?;
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| Error::Invalid(format!("github response body is not JSON: {error}")))?;
    Ok(HttpExchange {
        request: HttpRequest {
            method: "GET".into(),
            url: url.into(),
        },
        response: HttpResponse {
            status,
            headers,
            body_sha256: hex_digest(body.as_bytes()),
            item_count: json_item_count(&parsed),
            body,
        },
    })
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

fn ensure_github_url(url: &str) -> Result<()> {
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
        403 if headers.get("x-ratelimit-remaining").map(String::as_str) == Some("0") => {
            AcquisitionTermination::RateLimited {
                diagnostic,
                reset_at: headers.get("x-ratelimit-reset").cloned(),
            }
        }
        403 => AcquisitionTermination::PermissionDenied { diagnostic },
        404 => AcquisitionTermination::NotFound { diagnostic },
        429 => AcquisitionTermination::RateLimited {
            diagnostic,
            reset_at: headers.get("x-ratelimit-reset").cloned(),
        },
        _ => AcquisitionTermination::Failed { diagnostic },
    }
}

/// acquire the current branch policy from azure devops with credentials held by core.
///
/// # Errors
///
/// returns an error when the request context is invalid, no credential is
/// available, or the provider cannot be reached.
pub fn capture_azure_devops_branch_policy(
    options: &AzureDevopsRemoteCapture,
) -> Result<AcquisitionTranscript> {
    validate_azure_devops_remote(options)?;
    let credential = azure_devops_credential()?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    capture_azure_devops_branch_policy_with(options, |url| {
        azure_devops_get(&agent, url, &options.organization, &credential)
    })
}

fn capture_azure_devops_branch_policy_with<F>(
    options: &AzureDevopsRemoteCapture,
    mut fetch: F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    validate_azure_devops_remote(options)?;
    let captured_at = format_time(options.captured_at)?;
    let initial_url = format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/{}?api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(&options.repository),
    );
    let mut url = initial_url.clone();
    let mut exchanges = Vec::new();
    let termination = loop {
        ensure_azure_devops_url(&url, &options.organization)?;
        let exchange = fetch(&url)?;
        let status = exchange.response.status;
        let next = azure_devops_next_url(&url, &exchange.response.headers);
        let body = exchange.response.body.clone();
        let headers = exchange.response.headers.clone();
        exchanges.push(exchange);
        if status != 200 {
            break classify_azure_devops_failure(status, &body, &headers);
        }
        if exchanges.len() == 1 {
            let repository: serde_json::Value = serde_json::from_str(&body).map_err(|error| {
                Error::Invalid(format!(
                    "azure devops repository response is not JSON: {error}"
                ))
            })?;
            let id = repository
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| is_uuid(id))
                .ok_or_else(|| {
                    Error::Invalid("azure devops repository response has no valid id".into())
                })?;
            let name = repository
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    Error::Invalid("azure devops repository response has no name".into())
                })?;
            if name != options.repository {
                return Err(Error::Provenance(format!(
                    "azure devops resolved repository {:?}, not {:?}",
                    name, options.repository
                )));
            }
            url = format!(
                "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/policy/configurations?repositoryId={}&refName={}&%24top=100&api-version=7.1",
                percent_encode(&options.organization),
                percent_encode(&options.project),
                percent_encode(id),
                percent_encode(&format!("refs/heads/{}", options.branch)),
            );
            continue;
        }
        if let Some(next_url) = next {
            if exchanges.len().saturating_sub(1) == usize::from(options.max_pages) {
                break AcquisitionTermination::Truncated { next_url };
            }
            url = next_url;
        } else {
            break AcquisitionTermination::Exhausted;
        }
    };
    seal_transcript(TranscriptContents {
        collector_contract: AZURE_DEVOPS_BRANCH_POLICY_CONTRACT.into(),
        collector_version: env!("CARGO_PKG_VERSION").into(),
        subject: options.subject.clone(),
        proposition: Proposition::BranchConfiguration,
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

fn validate_azure_devops_remote(options: &AzureDevopsRemoteCapture) -> Result<()> {
    if options.max_pages == 0 || options.max_pages > 1_000 {
        return Err(Error::Invalid(
            "azure devops max-pages must be between 1 and 1000".into(),
        ));
    }
    for (label, value) in [
        ("organization", options.organization.as_str()),
        ("project", options.project.as_str()),
        ("repository", options.repository.as_str()),
        ("branch", options.branch.as_str()),
    ] {
        if value.is_empty()
            || value == "."
            || value == ".."
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Error::Invalid(format!(
                "azure devops {label} contains unsupported characters"
            )));
        }
    }
    Ok(())
}

enum AzureDevopsCredential {
    Bearer(String),
    Pat(String),
}

impl AzureDevopsCredential {
    fn secret(&self) -> &str {
        match self {
            Self::Bearer(value) | Self::Pat(value) => value,
        }
    }

    fn authorization(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::Pat(token) => format!("Basic {}", base64(&format!(":{token}"))),
        }
    }
}

fn azure_devops_credential() -> Result<AzureDevopsCredential> {
    if let Ok(output) = Command::new("az")
        .args([
            "account",
            "get-access-token",
            "--resource",
            AZURE_DEVOPS_RESOURCE,
            "--query",
            "accessToken",
            "--output",
            "tsv",
        ])
        .output()
    {
        if output.status.success() {
            let token = String::from_utf8(output.stdout).map_err(|_| {
                Error::Invalid("azure credential helper returned non-utf8 data".into())
            })?;
            let token = token.trim().to_owned();
            if !token.is_empty() {
                return Ok(AzureDevopsCredential::Bearer(token));
            }
        }
    }
    if let Ok(token) = std::env::var("AZURE_DEVOPS_EXT_PAT") {
        if !token.trim().is_empty() {
            return Ok(AzureDevopsCredential::Pat(token));
        }
    }
    Err(Error::Collection(
        "Azure DevOps source requires authentication; run `az login` or set AZURE_DEVOPS_EXT_PAT"
            .into(),
    ))
}

fn azure_devops_get(
    agent: &ureq::Agent,
    url: &str,
    organization: &str,
    credential: &AzureDevopsCredential,
) -> Result<HttpExchange> {
    ensure_azure_devops_url(url, organization)?;
    let authorization = credential.authorization();
    let mut response = agent
        .get(url)
        .header("accept", "application/json")
        .header("authorization", &authorization)
        .header(
            "user-agent",
            concat!("divinate/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|_| {
            Error::Collection("azure devops request failed before receiving a response".into())
        })?;
    let status = response.status().as_u16();
    let headers = retained_azure_devops_headers(response.headers());
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| Error::Collection("azure devops response body could not be read".into()))?;
    reject_reflected_azure_credential(&body, &headers, credential.secret(), &authorization)?;
    let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|error| {
        Error::Invalid(format!("azure devops response body is not JSON: {error}"))
    })?;
    Ok(HttpExchange {
        request: HttpRequest {
            method: "GET".into(),
            url: url.into(),
        },
        response: HttpResponse {
            status,
            headers,
            body_sha256: hex_digest(body.as_bytes()),
            item_count: json_item_count(&parsed),
            body,
        },
    })
}

fn retained_azure_devops_headers(headers: &ureq::http::HeaderMap) -> BTreeMap<String, String> {
    const ALLOWED: &[&str] = &[
        "date",
        "etag",
        "location",
        "retry-after",
        "x-ms-continuationtoken",
        "x-vss-e2eid",
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

fn reject_reflected_azure_credential(
    body: &str,
    headers: &BTreeMap<String, String>,
    secret: &str,
    authorization: &str,
) -> Result<()> {
    if body.contains(secret)
        || body.contains(authorization)
        || headers
            .values()
            .any(|value| value.contains(secret) || value.contains(authorization))
    {
        return Err(Error::Collection(
            "azure devops response reflected credential material; response was not retained".into(),
        ));
    }
    Ok(())
}

fn ensure_azure_devops_url(url: &str, organization: &str) -> Result<()> {
    let allowed_prefix = format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/",
        percent_encode(organization)
    );
    if !url.starts_with(&allowed_prefix) || url.contains('@') || url.contains('#') {
        return Err(Error::Invalid(format!(
            "azure devops acquisition refused URL outside {allowed_prefix}"
        )));
    }
    Ok(())
}

fn azure_devops_next_url(current: &str, headers: &BTreeMap<String, String>) -> Option<String> {
    let token = headers.get("x-ms-continuationtoken")?;
    let base = current
        .split("&continuationToken=")
        .next()
        .unwrap_or(current);
    Some(format!(
        "{base}&continuationToken={}",
        percent_encode(token)
    ))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn classify_azure_devops_failure(
    status: u16,
    body: &str,
    headers: &BTreeMap<String, String>,
) -> AcquisitionTermination {
    let diagnostic = azure_devops_diagnostic(status, body);
    match status {
        301 | 302 | 303 | 307 | 308 => AcquisitionTermination::UnsafeRedirect {
            location: headers.get("location").cloned().unwrap_or_default(),
        },
        401 => AcquisitionTermination::Unauthenticated { diagnostic },
        403 => AcquisitionTermination::PermissionDenied { diagnostic },
        404 => AcquisitionTermination::NotFound { diagnostic },
        429 => AcquisitionTermination::RateLimited {
            diagnostic,
            reset_at: headers.get("retry-after").cloned(),
        },
        _ => AcquisitionTermination::Failed { diagnostic },
    }
}

fn azure_devops_diagnostic(status: u16, body: &str) -> String {
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

fn base64(value: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    encoded
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

/// verify transcript integrity, pagination, collector contract, and authority.
#[must_use]
pub fn assess(
    transcript: &AcquisitionTranscript,
    registry: &ContractRegistry,
) -> AcquisitionAssessment {
    let mut reasons = Vec::new();
    let integrity = verify_integrity(transcript, &mut reasons);
    let contract = assess_contract(transcript, registry, &mut reasons);
    let enumeration = assess_enumeration(transcript, &mut reasons);
    let authority = if integrity == IntegrityStatus::Verified
        && contract == ContractStatus::Accepted
        && enumeration == EnumerationStatus::Complete
    {
        contract_authority(&transcript.contents.collector_contract)
    } else {
        vec![]
    };
    let evidence_exchanges = evidence_exchanges(transcript);
    AcquisitionAssessment {
        transcript_id: transcript.id.clone(),
        integrity,
        contract,
        enumeration,
        authority,
        pages: u64::try_from(evidence_exchanges.len()).unwrap_or(u64::MAX),
        items: evidence_exchanges
            .iter()
            .map(|exchange| exchange.response.item_count)
            .sum(),
        reasons,
    }
}

fn evidence_exchanges(transcript: &AcquisitionTranscript) -> &[HttpExchange] {
    if transcript.contents.collector_contract == AZURE_DEVOPS_BRANCH_POLICY_CONTRACT {
        transcript.contents.exchanges.get(1..).unwrap_or_default()
    } else {
        &transcript.contents.exchanges
    }
}

/// compare two acquisitions only when their contract, subject, proposition, and
/// requested scope match exactly.
#[must_use]
pub fn compare(left: &AcquisitionTranscript, right: &AcquisitionTranscript) -> RerunComparison {
    let mut result = RerunComparison {
        left_transcript_id: left.id.clone(),
        right_transcript_id: right.id.clone(),
        outcome: RerunOutcome::Consistent,
        added_identities: vec![],
        removed_identities: vec![],
        reasons: vec![],
    };
    if left.contents.collector_contract != right.contents.collector_contract
        || left.contents.subject != right.contents.subject
        || left.contents.proposition != right.contents.proposition
        || left.contents.requested_scope != right.contents.requested_scope
        || left.contents.initial_request != right.contents.initial_request
    {
        result.outcome = RerunOutcome::NotComparable;
        result
            .reasons
            .push("contract, subject, proposition, scope, or request identity differs".into());
        return result;
    }
    if left.contents.termination != right.contents.termination {
        result.outcome = RerunOutcome::CoverageChanged;
        result
            .reasons
            .push("the acquisition attempts ended with different coverage states".into());
        return result;
    }
    let left_ids = observed_identities(left);
    let right_ids = observed_identities(right);
    result.added_identities = right_ids.difference(&left_ids).cloned().collect();
    result.removed_identities = left_ids.difference(&right_ids).cloned().collect();
    if !result.added_identities.is_empty() || !result.removed_identities.is_empty() {
        result.outcome = RerunOutcome::ContentChanged;
        result.reasons.push(
            "the same fixed acquisition scope returned a different identity population".into(),
        );
    }
    result
}

fn verify_integrity(
    transcript: &AcquisitionTranscript,
    reasons: &mut Vec<String>,
) -> IntegrityStatus {
    if transcript.schema_version != TRANSCRIPT_SCHEMA_VERSION {
        reasons.push(format!(
            "transcript schema {} is not supported",
            transcript.schema_version
        ));
        return IntegrityStatus::Failed;
    }
    let expected = seal_transcript(transcript.contents.clone()).map(|sealed| sealed.id);
    if !matches!(expected.as_deref(), Ok(expected) if expected == transcript.id) {
        reasons.push("transcript digest does not match its contents".into());
        return IntegrityStatus::Failed;
    }
    for exchange in &transcript.contents.exchanges {
        if hex_digest(exchange.response.body.as_bytes()) != exchange.response.body_sha256 {
            reasons.push(format!(
                "response body digest failed for {}",
                exchange.request.url
            ));
            return IntegrityStatus::Failed;
        }
        let item_count = serde_json::from_str::<serde_json::Value>(&exchange.response.body)
            .ok()
            .map(|body| json_item_count(&body));
        if item_count != Some(exchange.response.item_count) {
            reasons.push(format!(
                "response item count failed for {}",
                exchange.request.url
            ));
            return IntegrityStatus::Failed;
        }
        if exchange
            .response
            .headers
            .keys()
            .any(|name| matches!(name.as_str(), "authorization" | "cookie" | "set-cookie"))
        {
            reasons.push("transcript contains a credential-bearing header".into());
            return IntegrityStatus::Failed;
        }
    }
    IntegrityStatus::Verified
}

fn observed_identities(transcript: &AcquisitionTranscript) -> std::collections::BTreeSet<String> {
    transcript
        .contents
        .exchanges
        .iter()
        .filter_map(|exchange| {
            serde_json::from_str::<serde_json::Value>(&exchange.response.body).ok()
        })
        .filter_map(|body| body.as_array().cloned())
        .flatten()
        .filter_map(|item| {
            item.get("sha")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn assess_contract(
    transcript: &AcquisitionTranscript,
    registry: &ContractRegistry,
    reasons: &mut Vec<String>,
) -> ContractStatus {
    if contract_authority(&transcript.contents.collector_contract).is_empty() {
        reasons.push(format!(
            "collector contract {} is not supported",
            transcript.contents.collector_contract
        ));
        return ContractStatus::Unsupported;
    }
    if let Some(invalidation) = registry
        .invalidations
        .iter()
        .find(|item| item.contract == transcript.contents.collector_contract)
    {
        reasons.push(format!(
            "collector contract was invalidated: {}",
            invalidation.reason
        ));
        return ContractStatus::Invalidated {
            discovered_at: invalidation.discovered_at.clone(),
            reason: invalidation.reason.clone(),
        };
    }
    ContractStatus::Accepted
}

fn assess_enumeration(
    transcript: &AcquisitionTranscript,
    reasons: &mut Vec<String>,
) -> EnumerationStatus {
    if let Some(reason) = invalid_exchange_sequence(transcript) {
        reasons.push(reason.into());
        return EnumerationStatus::Failed;
    }
    match &transcript.contents.termination {
        AcquisitionTermination::Exhausted => {
            if let Some(status) = assess_github_result_count(transcript, reasons) {
                return status;
            }
            let terminal = transcript
                .contents
                .exchanges
                .last()
                .is_some_and(|exchange| {
                    exchange.response.status == 200
                        && next_request_url(
                            &transcript.contents.collector_contract,
                            &exchange.request.url,
                            &exchange.response.headers,
                        )
                        .is_none()
                });
            if terminal {
                EnumerationStatus::Complete
            } else {
                reasons.push("exhausted transcript lacks a terminal successful response".into());
                EnumerationStatus::Failed
            }
        }
        AcquisitionTermination::Truncated { next_url } => {
            if transcript
                .contents
                .exchanges
                .last()
                .and_then(|exchange| {
                    next_request_url(
                        &transcript.contents.collector_contract,
                        &exchange.request.url,
                        &exchange.response.headers,
                    )
                })
                .as_deref()
                != Some(next_url.as_str())
            {
                reasons.push("truncation next url does not match the last response".into());
                return EnumerationStatus::Failed;
            }
            reasons.push("collection stopped while a next page was available".into());
            EnumerationStatus::Truncated
        }
        AcquisitionTermination::Unauthenticated { diagnostic } => {
            reasons.push(format!("source is unauthenticated: {diagnostic}"));
            EnumerationStatus::Unauthenticated
        }
        AcquisitionTermination::PermissionDenied { diagnostic } => {
            reasons.push(format!("source access denied: {diagnostic}"));
            EnumerationStatus::PermissionDenied
        }
        AcquisitionTermination::NotFound { diagnostic } => {
            reasons.push(format!("source resource was not found: {diagnostic}"));
            EnumerationStatus::NotFound
        }
        AcquisitionTermination::RateLimited {
            diagnostic,
            reset_at,
        } => {
            reasons.push(reset_at.as_ref().map_or_else(
                || format!("source rate limit reached: {diagnostic}"),
                |reset| format!("source rate limit reached: {diagnostic}; reset {reset}"),
            ));
            EnumerationStatus::RateLimited
        }
        AcquisitionTermination::UnsafeRedirect { location } => {
            reasons.push(format!("authenticated redirect refused: {location}"));
            EnumerationStatus::Failed
        }
        AcquisitionTermination::Failed { diagnostic } => {
            reasons.push(format!("collector failed: {diagnostic}"));
            EnumerationStatus::Failed
        }
    }
}

fn invalid_exchange_sequence(transcript: &AcquisitionTranscript) -> Option<&'static str> {
    if transcript
        .contents
        .exchanges
        .first()
        .is_some_and(|first| first.request != transcript.contents.initial_request)
    {
        return Some("first exchange does not match the initial request");
    }
    for pair in transcript.contents.exchanges.windows(2) {
        let planned_branch_detail = transcript.contents.collector_contract
            == GITHUB_BRANCH_PROTECTION_CONTRACT
            && pair[1].request.url == format!("{}/protection", pair[0].request.url);
        let planned_azure_policy = transcript.contents.collector_contract
            == AZURE_DEVOPS_BRANCH_POLICY_CONTRACT
            && azure_policy_url_from_repository_exchange(
                &pair[0],
                transcript.contents.subject.qualifier("branch"),
            )
            .as_deref()
                == Some(pair[1].request.url.as_str());
        if !planned_branch_detail
            && !planned_azure_policy
            && next_request_url(
                &transcript.contents.collector_contract,
                &pair[0].request.url,
                &pair[0].response.headers,
            )
            .as_deref()
                != Some(pair[1].request.url.as_str())
        {
            return Some("response pagination link does not match the following request");
        }
    }
    None
}

fn azure_policy_url_from_repository_exchange(
    exchange: &HttpExchange,
    branch: Option<&str>,
) -> Option<String> {
    if !exchange.request.url.contains("/_apis/git/repositories/") {
        return None;
    }
    let body: serde_json::Value = serde_json::from_str(&exchange.response.body).ok()?;
    let id = body.get("id")?.as_str().filter(|id| is_uuid(id))?;
    let prefix = exchange.request.url.split("/_apis/").next()?;
    Some(format!(
        "{prefix}/_apis/git/policy/configurations?repositoryId={}&refName={}&%24top=100&api-version=7.1",
        percent_encode(id),
        percent_encode(&format!("refs/heads/{}", branch?)),
    ))
}

fn assess_github_result_count(
    transcript: &AcquisitionTranscript,
    reasons: &mut Vec<String>,
) -> Option<EnumerationStatus> {
    let label = match transcript.contents.collector_contract.as_str() {
        GITHUB_CHECK_RUNS_CONTRACT => "check run",
        GITHUB_COMMIT_STATUSES_CONTRACT => "commit status",
        _ => return None,
    };
    let reported = transcript
        .contents
        .exchanges
        .first()
        .and_then(|exchange| {
            serde_json::from_str::<serde_json::Value>(&exchange.response.body).ok()
        })
        .and_then(|body| body.get("total_count").and_then(serde_json::Value::as_u64));
    let fetched = transcript
        .contents
        .exchanges
        .iter()
        .map(|exchange| exchange.response.item_count)
        .sum::<u64>();
    match reported {
        Some(reported) if reported != fetched => {
            reasons.push(format!(
                "github reported {reported} {label}(s), but {fetched} were retained"
            ));
            Some(EnumerationStatus::Truncated)
        }
        None => {
            reasons.push(format!("github {label} response has no total_count"));
            Some(EnumerationStatus::Failed)
        }
        Some(_) => None,
    }
}

fn contract_authority(contract: &str) -> Vec<Proposition> {
    match contract {
        GITHUB_COMMITS_CONTRACT => vec![Proposition::CommitAncestry],
        GITHUB_BRANCH_PROTECTION_CONTRACT | AZURE_DEVOPS_BRANCH_POLICY_CONTRACT => {
            vec![Proposition::BranchConfiguration]
        }
        GITHUB_CHECK_RUNS_CONTRACT | GITHUB_COMMIT_STATUSES_CONTRACT => {
            vec![Proposition::RevisionChecks]
        }
        _ => vec![],
    }
}

fn next_request_url(
    contract: &str,
    current: &str,
    headers: &BTreeMap<String, String>,
) -> Option<String> {
    if contract == AZURE_DEVOPS_BRANCH_POLICY_CONTRACT {
        azure_devops_next_url(current, headers)
    } else {
        next_link(headers)
    }
}

fn json_item_count(value: &serde_json::Value) -> u64 {
    if let Some(items) = value
        .get("check_runs")
        .and_then(serde_json::Value::as_array)
    {
        return u64::try_from(items.len()).unwrap_or(u64::MAX);
    }
    if let Some(items) = value.get("statuses").and_then(serde_json::Value::as_array) {
        return u64::try_from(items.len()).unwrap_or(u64::MAX);
    }
    if let Some(items) = value.get("value").and_then(serde_json::Value::as_array) {
        return u64::try_from(items.len()).unwrap_or(u64::MAX);
    }
    value
        .as_array()
        .and_then(|items| u64::try_from(items.len()).ok())
        .unwrap_or_else(|| u64::from(!value.is_null()))
}

/// create a content-addressed transcript from sanitized acquisition contents.
///
/// # Errors
///
/// returns an error when the contents cannot be serialized.
pub fn seal_transcript(contents: TranscriptContents) -> Result<AcquisitionTranscript> {
    let bytes = serde_json::to_vec(&contents).map_err(Error::Serialize)?;
    Ok(AcquisitionTranscript {
        id: format!("acq_{}", &hex_digest(&bytes)[..20]),
        schema_version: TRANSCRIPT_SCHEMA_VERSION.into(),
        contents,
    })
}

fn commits_url(options: &GithubCapture) -> String {
    format!(
        "repos/{}/commits?sha={}&since={}&until={}&per_page={}&page=1",
        options.repository,
        percent_encode(&options.branch),
        percent_encode(&options.interval.from),
        percent_encode(&options.interval.until),
        options.per_page
    )
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn parse_exchange(url: &str, bytes: &[u8]) -> Result<HttpExchange> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Error::Invalid(format!("gh emitted non-utf8 response: {error}")))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| Error::Invalid("gh response did not contain HTTP headers".into()))?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::Invalid("gh response had no HTTP status".into()))?;
    let allowed = [
        "date",
        "etag",
        "link",
        "x-accepted-oauth-scopes",
        "x-github-api-version-selected",
        "x-github-request-id",
        "x-oauth-scopes",
    ];
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .filter(|(name, _)| allowed.contains(&name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| Error::Invalid(format!("github response body is not JSON: {error}")))?;
    let item_count = json_item_count(&parsed);
    Ok(HttpExchange {
        request: HttpRequest {
            method: "GET".into(),
            url: url.into(),
        },
        response: HttpResponse {
            status,
            headers,
            body: body.into(),
            body_sha256: hex_digest(body.as_bytes()),
            item_count,
        },
    })
}

fn next_link(headers: &BTreeMap<String, String>) -> Option<String> {
    headers.get("link").and_then(|links| {
        links.split(',').find_map(|link| {
            let (url, relation) = link.trim().split_once(';')?;
            (relation.trim() == "rel=\"next\"").then(|| {
                url.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .into()
            })
        })
    })
}

fn sanitize_diagnostic(value: &str) -> String {
    value.trim().chars().take(500).collect()
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format timestamp: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(resource: GithubRemoteResource) -> GithubRemoteCapture {
        GithubRemoteCapture {
            repository: "cyberwitchery/divinate".into(),
            branch: "main".into(),
            revision: "abc123".into(),
            subject: Subject {
                kind: "repository".into(),
                id: "github:cyberwitchery/divinate".into(),
                qualifiers: BTreeMap::from([
                    ("branch".into(), serde_json::json!("main")),
                    ("revision".into(), serde_json::json!("abc123")),
                ]),
            },
            interval: TimeRange {
                from: "2026-09-11T00:00:00Z".into(),
                until: "2026-09-12T00:00:00Z".into(),
            },
            resource,
            per_page: 100,
            max_pages: 10,
            captured_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn azure_remote() -> AzureDevopsRemoteCapture {
        AzureDevopsRemoteCapture {
            organization: "ibw-ag".into(),
            project: "uTraxx".into(),
            repository: "uTraxx.Platform".into(),
            branch: "develop".into(),
            subject: Subject {
                kind: "repository".into(),
                id: "azure-devops:ibw-ag/uTraxx/uTraxx.Platform".into(),
                qualifiers: BTreeMap::from([
                    ("branch".into(), serde_json::json!("develop")),
                    ("revision".into(), serde_json::json!("abc123")),
                ]),
            },
            interval: TimeRange {
                from: "2026-09-11T00:00:00Z".into(),
                until: "2026-09-12T00:00:00Z".into(),
            },
            max_pages: 10,
            captured_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn exchange(
        url: &str,
        status: u16,
        body: &str,
        headers: BTreeMap<String, String>,
    ) -> HttpExchange {
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        HttpExchange {
            request: HttpRequest {
                method: "GET".into(),
                url: url.into(),
            },
            response: HttpResponse {
                status,
                headers,
                body: body.into(),
                body_sha256: hex_digest(body.as_bytes()),
                item_count: json_item_count(&parsed),
            },
        }
    }

    #[test]
    fn next_link_is_extracted() {
        let headers = BTreeMap::from([(
            "link".into(),
            "<https://api.github.com/example?page=2>; rel=\"next\", <https://api.github.com/example?page=4>; rel=\"last\"".into(),
        )]);
        assert_eq!(
            next_link(&headers).as_deref(),
            Some("https://api.github.com/example?page=2")
        );
    }

    #[test]
    fn response_parser_preserves_body_digest() {
        let exchange = parse_exchange(
            "repos/example/commits?page=1",
            b"HTTP/2.0 200 OK\nLink: <next>; rel=\"next\"\nETag: abc\nAuthorization: secret\n\n[{\"sha\":\"abc\"}]\n",
        )
        .unwrap();
        assert_eq!(exchange.response.item_count, 1);
        assert!(!exchange.response.headers.contains_key("authorization"));
        assert_eq!(
            exchange.response.body_sha256,
            hex_digest(exchange.response.body.as_bytes())
        );
    }

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
        assert!(assessment.authority.is_empty());
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
            Ok(exchange(
                url,
                200,
                r#"{"total_count":2,"check_runs":[{"name":"ci"}]}"#,
                BTreeMap::from([(
                    "link".into(),
                    "<https://api.github.com/repos/cyberwitchery/divinate/commits/abc123/check-runs?per_page=100&page=2>; rel=\"next\"".into(),
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
    fn check_run_count_mismatch_cannot_establish_complete_coverage() {
        let options = remote(GithubRemoteResource::CheckRuns);
        let transcript = capture_github_remote_with(&options, |url| {
            Ok(exchange(
                url,
                200,
                r#"{"total_count":2,"check_runs":[{"name":"ci"}]}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Truncated);
        assert!(assessment.authority.is_empty());
    }

    #[test]
    fn commit_statuses_retain_complete_paginated_current_state() {
        let options = remote(GithubRemoteResource::CommitStatuses);
        let mut page = 0;
        let transcript = capture_github_remote_with(&options, |url| {
            page += 1;
            if page == 1 {
                assert!(url.ends_with("/commits/abc123/status?per_page=100&page=1"));
                Ok(exchange(
                    url,
                    200,
                    r#"{"state":"failure","total_count":2,"statuses":[{"context":"ci","state":"success"}]}"#,
                    BTreeMap::from([(
                        "link".into(),
                        "<https://api.github.com/repos/cyberwitchery/divinate/commits/abc123/status?per_page=100&page=2>; rel=\"next\"".into(),
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
    fn commit_status_count_mismatch_cannot_establish_complete_coverage() {
        let options = remote(GithubRemoteResource::CommitStatuses);
        let transcript = capture_github_remote_with(&options, |url| {
            Ok(exchange(
                url,
                200,
                r#"{"state":"success","total_count":2,"statuses":[{"context":"ci","state":"success"}]}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Truncated);
        assert!(assessment.authority.is_empty());
    }

    #[test]
    fn rate_limit_and_redirect_are_distinct_failures() {
        let rate = classify_github_failure(
            403,
            r#"{"message":"API rate limit exceeded"}"#,
            &BTreeMap::from([
                ("x-ratelimit-remaining".into(), "0".into()),
                ("x-ratelimit-reset".into(), "123".into()),
            ]),
        );
        assert!(matches!(rate, AcquisitionTermination::RateLimited { .. }));
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
        let options = remote(GithubRemoteResource::CommitStatuses);
        let transcript = capture_github_remote_with(&options, |url| {
            Ok(exchange(
                url,
                200,
                r#"{"state":"pending","total_count":0,"statuses":[]}"#,
                retained.clone(),
            ))
        })
        .unwrap();
        assert!(!serde_json::to_string(&transcript).unwrap().contains(token));
    }

    #[test]
    fn azure_branch_policy_pagination_retains_complete_authority() {
        let options = azure_remote();
        let transcript = capture_azure_devops_branch_policy_with(&options, |url| {
            if url.contains("/_apis/git/repositories/") {
                Ok(exchange(
                    url,
                    200,
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"uTraxx.Platform"}"#,
                    BTreeMap::new(),
                ))
            } else if url.contains("continuationToken=next") {
                Ok(exchange(
                    url,
                    200,
                    r#"{"count":1,"value":[{"id":2}]}"#,
                    BTreeMap::new(),
                ))
            } else {
                Ok(exchange(
                    url,
                    200,
                    r#"{"count":1,"value":[{"id":1}]}"#,
                    BTreeMap::from([("x-ms-continuationtoken".into(), "next".into())]),
                ))
            }
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.pages, 2);
        assert_eq!(assessment.items, 2);
        assert_eq!(assessment.authority, vec![Proposition::BranchConfiguration]);
        assert_eq!(transcript.contents.exchanges.len(), 3);
        assert!(transcript.contents.exchanges[1]
            .request
            .url
            .contains("repositoryId=11111111-2222-3333-4444-555555555555"));
        assert!(transcript.contents.exchanges[1]
            .request
            .url
            .contains("refName=refs%2Fheads%2Fdevelop"));
    }

    #[test]
    fn azure_credentials_and_cross_origin_redirects_are_refused() {
        let token = "divinate-azure-test-token-98d4a67f";
        assert_eq!(base64(":pat"), "OnBhdA==");
        let authorization = AzureDevopsCredential::Pat(token.into()).authorization();
        let mut headers = ureq::http::HeaderMap::new();
        headers.insert("authorization", authorization.parse().unwrap());
        headers.insert("set-cookie", format!("session={token}").parse().unwrap());
        headers.insert("x-vss-e2eid", "request-1".parse().unwrap());
        let retained = retained_azure_devops_headers(&headers);
        let serialized = serde_json::to_string(&retained).unwrap();
        assert!(!serialized.contains(token));
        assert!(!retained.contains_key("authorization"));
        assert!(!retained.contains_key("set-cookie"));
        assert!(
            reject_reflected_azure_credential("safe", &retained, token, &authorization).is_ok()
        );
        assert!(
            reject_reflected_azure_credential(token, &retained, token, &authorization).is_err()
        );
        assert!(reject_reflected_azure_credential(
            &authorization,
            &retained,
            token,
            &authorization
        )
        .is_err());
        assert!(ensure_azure_devops_url("https://evil.invalid/steal", "ibw-ag").is_err());
        let failure = classify_azure_devops_failure(
            302,
            r#"{"message":"Moved"}"#,
            &BTreeMap::from([("location".into(), "https://evil.invalid/".into())]),
        );
        assert!(matches!(
            failure,
            AcquisitionTermination::UnsafeRedirect { .. }
        ));

        let options = azure_remote();
        let transcript = capture_azure_devops_branch_policy_with(&options, |url| {
            if url.contains("/_apis/git/repositories/") {
                Ok(exchange(
                    url,
                    200,
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"uTraxx.Platform"}"#,
                    retained.clone(),
                ))
            } else {
                Ok(exchange(
                    url,
                    200,
                    r#"{"count":0,"value":[]}"#,
                    BTreeMap::new(),
                ))
            }
        })
        .unwrap();
        assert!(!serde_json::to_string(&transcript).unwrap().contains(token));
    }

    #[test]
    fn azure_permission_denial_has_no_branch_configuration_authority() {
        let options = azure_remote();
        let transcript = capture_azure_devops_branch_policy_with(&options, |url| {
            Ok(exchange(
                url,
                403,
                r#"{"message":"access denied"}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::PermissionDenied);
        assert!(assessment.authority.is_empty());
    }
}
