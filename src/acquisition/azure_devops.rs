use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use time::OffsetDateTime;

use super::http::{build_exchange, format_time, percent_encode, sanitize_diagnostic};
use super::transcript::{
    seal_transcript, AcquisitionTermination, AcquisitionTranscript, HttpExchange, HttpRequest,
    TranscriptContents, AZURE_DEVOPS_BRANCH_POLICY_CONTRACT,
    AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT, AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT,
    AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT,
};
use crate::error::{Error, Result};
use crate::model::{Proposition, Subject, TimeRange};

pub(super) const AZURE_DEVOPS_API_ORIGIN: &str = "https://dev.azure.com";
const AZURE_DEVOPS_RESOURCE: &str = "499b84ac-1321-427f-aa17-267ca6975798";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// the azure devops resources that core can acquire for packs.
pub enum AzureDevopsRemoteResource {
    BranchPolicy,
    RepositoryMutations,
    PullRequestReviews,
    BuildValidationHistory,
}

#[derive(Debug, Clone)]
/// one provider-aware azure devops acquisition requested by a pack.
pub struct AzureDevopsRemoteCapture {
    pub organization: String,
    pub project: String,
    pub repository: String,
    pub branch: String,
    pub resource: AzureDevopsRemoteResource,
    pub subject: Subject,
    pub interval: TimeRange,
    pub max_pages: u16,
    pub captured_at: OffsetDateTime,
}

/// acquire one narrow azure devops resource with credentials held by core.
///
/// # Errors
///
/// returns an error when the request context is invalid, no credential is
/// available, or the provider cannot be reached.
pub fn capture_azure_devops_remote(
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
    let mut fetch = |url: &str| azure_devops_get(&agent, url, &options.organization, &credential);
    match options.resource {
        AzureDevopsRemoteResource::BranchPolicy => {
            capture_azure_devops_branch_policy_with(options, &mut fetch)
        }
        AzureDevopsRemoteResource::RepositoryMutations
        | AzureDevopsRemoteResource::PullRequestReviews
        | AzureDevopsRemoteResource::BuildValidationHistory => {
            capture_azure_devops_history_with(options, &mut fetch)
        }
    }
}

pub(super) fn capture_azure_devops_branch_policy_with<F>(
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
        let page = u64::try_from(exchanges.len().saturating_sub(1)).unwrap_or(u64::MAX);
        let next = azure_devops_next_page_url(&exchange, page);
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
            url = azure_devops_policy_configurations_url(options, id);
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

pub(super) fn capture_azure_devops_history_with<F>(
    options: &AzureDevopsRemoteCapture,
    fetch: &mut F,
) -> Result<AcquisitionTranscript>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    validate_azure_devops_remote(options)?;
    let captured_at = format_time(options.captured_at)?;
    let initial_url = azure_devops_repository_url(options);
    let repository_exchange = fetch_azure_exchange(&initial_url, options, fetch)?;
    let (contract, proposition) = match options.resource {
        AzureDevopsRemoteResource::RepositoryMutations => (
            AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT,
            Proposition::RepositoryMutations,
        ),
        AzureDevopsRemoteResource::PullRequestReviews => (
            AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT,
            Proposition::PullRequestReviews,
        ),
        AzureDevopsRemoteResource::BuildValidationHistory => (
            AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT,
            Proposition::BuildValidationResults,
        ),
        AzureDevopsRemoteResource::BranchPolicy => unreachable!(),
    };
    if repository_exchange.response.status != 200 {
        let termination = classify_azure_devops_failure(
            repository_exchange.response.status,
            &repository_exchange.response.body,
            &repository_exchange.response.headers,
        );
        return seal_transcript(TranscriptContents {
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
            exchanges: vec![repository_exchange],
            termination,
        });
    }
    let repository_id = azure_devops_repository_id(options, &repository_exchange)?;
    let mut exchanges = vec![repository_exchange];
    let mut termination = None;

    if options.resource == AzureDevopsRemoteResource::RepositoryMutations {
        let base = azure_devops_pushes_url(options, &repository_id, 0);
        termination = fetch_azure_list_pages(base, options, fetch, &mut exchanges)?;
    }
    if termination.is_none() {
        let base = azure_devops_pull_requests_url(options, &repository_id, 0);
        termination = fetch_azure_list_pages(base, options, fetch, &mut exchanges)?;
    }
    if termination.is_none() && options.resource == AzureDevopsRemoteResource::PullRequestReviews {
        for number in azure_devops_pull_request_ids(&exchanges) {
            let url = azure_devops_threads_url(options, &repository_id, number);
            let exchange = fetch_azure_exchange(&url, options, fetch)?;
            let status = exchange.response.status;
            let body = exchange.response.body.clone();
            let headers = exchange.response.headers.clone();
            exchanges.push(exchange);
            if status != 200 {
                termination = Some(classify_azure_devops_failure(status, &body, &headers));
                break;
            }
        }
    }
    if termination.is_none()
        && options.resource == AzureDevopsRemoteResource::BuildValidationHistory
    {
        termination = fetch_azure_policy_evaluations(options, fetch, &mut exchanges)?;
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

fn fetch_azure_policy_evaluations<F>(
    options: &AzureDevopsRemoteCapture,
    fetch: &mut F,
    exchanges: &mut Vec<HttpExchange>,
) -> Result<Option<AcquisitionTermination>>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    let project_id = azure_devops_project_id(&exchanges[0])?;
    for number in azure_devops_pull_request_ids(exchanges) {
        let url = azure_devops_policy_evaluations_url(options, &project_id, number);
        if let Some(termination) = fetch_azure_list_pages(url, options, fetch, exchanges)? {
            return Ok(Some(termination));
        }
    }
    Ok(None)
}

pub(super) fn azure_devops_threads_url(
    options: &AzureDevopsRemoteCapture,
    repository_id: &str,
    number: u64,
) -> String {
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/{repository_id}/pullRequests/{number}/threads?api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
    )
}

pub(super) fn azure_devops_policy_evaluations_url(
    options: &AzureDevopsRemoteCapture,
    project_id: &str,
    number: u64,
) -> String {
    let artifact = format!("vstfs:///CodeReview/CodeReviewId/{project_id}/{number}");
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/policy/evaluations?artifactId={}&includeNotApplicable=true&%24top=100&%24skip=0&api-version=7.1-preview.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(&artifact),
    )
}

pub(super) fn azure_devops_policy_configurations_url(
    options: &AzureDevopsRemoteCapture,
    repository_id: &str,
) -> String {
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/policy/configurations?repositoryId={}&refName={}&%24top=100&api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(repository_id),
        percent_encode(&format!("refs/heads/{}", options.branch)),
    )
}

fn azure_devops_repository_url(options: &AzureDevopsRemoteCapture) -> String {
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/{}?api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(&options.repository),
    )
}

fn fetch_azure_exchange<F>(
    url: &str,
    options: &AzureDevopsRemoteCapture,
    fetch: &mut F,
) -> Result<HttpExchange>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    ensure_azure_devops_url(url, &options.organization)?;
    fetch(url)
}

pub(super) fn azure_devops_repository_id(
    options: &AzureDevopsRemoteCapture,
    exchange: &HttpExchange,
) -> Result<String> {
    if exchange.response.status != 200 {
        return Err(Error::Collection(format!(
            "azure devops repository identity request returned HTTP {}",
            exchange.response.status
        )));
    }
    let repository: serde_json::Value =
        serde_json::from_str(&exchange.response.body).map_err(|error| {
            Error::Invalid(format!(
                "azure devops repository response is not JSON: {error}"
            ))
        })?;
    let id = repository
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| is_uuid(id))
        .ok_or_else(|| Error::Invalid("azure devops repository response has no valid id".into()))?;
    let name = repository
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Invalid("azure devops repository response has no name".into()))?;
    if name != options.repository {
        return Err(Error::Provenance(format!(
            "azure devops resolved repository {:?}, not {:?}",
            name, options.repository
        )));
    }
    Ok(id.into())
}

pub(super) fn azure_devops_pushes_url(
    options: &AzureDevopsRemoteCapture,
    repository_id: &str,
    skip: u64,
) -> String {
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/{repository_id}/pushes?searchCriteria.refName={}&searchCriteria.fromDate={}&searchCriteria.toDate={}&searchCriteria.includeRefUpdates=true&%24top=100&%24skip={skip}&api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(&format!("refs/heads/{}", options.branch)),
        percent_encode(&options.interval.from),
        percent_encode(&options.interval.until),
    )
}

pub(super) fn azure_devops_pull_requests_url(
    options: &AzureDevopsRemoteCapture,
    repository_id: &str,
    skip: u64,
) -> String {
    let time_filter = if options.resource == AzureDevopsRemoteResource::RepositoryMutations {
        String::new()
    } else {
        format!("&searchCriteria.minTime={}&searchCriteria.maxTime={}&searchCriteria.queryTimeRangeType=Closed", percent_encode(&options.interval.from), percent_encode(&options.interval.until))
    };
    format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/{repository_id}/pullrequests?searchCriteria.status=completed&searchCriteria.targetRefName={}{time_filter}&%24top=100&%24skip={skip}&api-version=7.1",
        percent_encode(&options.organization),
        percent_encode(&options.project),
        percent_encode(&format!("refs/heads/{}", options.branch)),
    )
}

fn fetch_azure_list_pages<F>(
    initial_url: String,
    options: &AzureDevopsRemoteCapture,
    fetch: &mut F,
    exchanges: &mut Vec<HttpExchange>,
) -> Result<Option<AcquisitionTermination>>
where
    F: FnMut(&str) -> Result<HttpExchange>,
{
    let mut url = initial_url;
    for page in 0..options.max_pages {
        let exchange = fetch_azure_exchange(&url, options, fetch)?;
        let status = exchange.response.status;
        let next_url = azure_devops_next_page_url(&exchange, u64::from(page));
        let body = exchange.response.body.clone();
        let headers = exchange.response.headers.clone();
        exchanges.push(exchange);
        if status != 200 {
            return Ok(Some(classify_azure_devops_failure(status, &body, &headers)));
        }
        if azure_devops_listed_items(&body).is_none() {
            return Err(Error::Invalid(
                "azure devops list response has no value array".into(),
            ));
        }
        let Some(next_url) = next_url else {
            return Ok(None);
        };
        if page + 1 == options.max_pages {
            return Ok(Some(AcquisitionTermination::Truncated { next_url }));
        }
        url = next_url;
    }
    unreachable!()
}

/// the page an azure collector requests after `exchange`, the zero-based `page` of its
/// population: the continuation token, else the `$skip` step after a full list page.
pub(super) fn azure_devops_next_page_url(exchange: &HttpExchange, page: u64) -> Option<String> {
    let url = &exchange.request.url;
    azure_devops_next_url(url, &exchange.response.headers).or_else(|| {
        (azure_devops_listed_items(&exchange.response.body) == Some(100))
            .then(|| replace_azure_skip(url, (page + 1) * 100))
            .flatten()
    })
}

fn azure_devops_listed_items(body: &str) -> Option<usize> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("value")?
        .as_array()
        .map(Vec::len)
}

fn replace_azure_skip(url: &str, skip: u64) -> Option<String> {
    let marker = "%24skip=";
    let value_start = url.find(marker)? + marker.len();
    let value_end = url[value_start..]
        .find('&')
        .map_or(url.len(), |offset| value_start + offset);
    Some(format!(
        "{}{}{}",
        &url[..value_start],
        skip,
        &url[value_end..]
    ))
}

pub(super) fn azure_devops_pull_request_ids(
    exchanges: &[HttpExchange],
) -> std::collections::BTreeSet<u64> {
    exchanges
        .iter()
        .filter(|exchange| exchange.request.url.contains("/pullrequests?"))
        .filter_map(|exchange| {
            serde_json::from_str::<serde_json::Value>(&exchange.response.body).ok()
        })
        .filter_map(|value| {
            value
                .get("value")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .flatten()
        .filter_map(|pull| {
            pull.get("pullRequestId")
                .and_then(serde_json::Value::as_u64)
        })
        .collect()
}

pub(super) fn azure_devops_project_id(exchange: &HttpExchange) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(&exchange.response.body).map_err(|error| {
            Error::Invalid(format!("azure repository response is not JSON: {error}"))
        })?;
    value
        .pointer("/project/id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| is_uuid(id))
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid("azure repository response has no valid project id".into()))
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
    let mut response = azure_devops_request(agent, url, &authorization)
        .call()
        .map_err(|error| {
            Error::Collection(format!(
                "azure devops request failed before receiving a response: {}",
                sanitize_diagnostic(&error.to_string())
            ))
        })?;
    let status = response.status().as_u16();
    let headers = retained_azure_devops_headers(response.headers());
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| Error::Collection("azure devops response body could not be read".into()))?;
    reject_reflected_azure_credential(&body, &headers, credential.secret(), &authorization)?;
    build_exchange(url, status, headers, body, "azure devops")
}

fn azure_devops_request(
    agent: &ureq::Agent,
    url: &str,
    authorization: &str,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    agent
        .get(url)
        .header("accept", "application/json")
        .header("authorization", authorization)
        .header(
            "user-agent",
            concat!("divinate/", env!("CARGO_PKG_VERSION")),
        )
        .header("x-tfs-fedauthredirect", "Suppress")
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

pub(super) fn ensure_azure_devops_url(url: &str, organization: &str) -> Result<()> {
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

pub(super) fn is_uuid(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::assessment::{assess, ContractRegistry, EnumerationStatus};
    use crate::acquisition::test_support::{azure_remote, exchange};

    #[test]
    fn azure_branch_policy_pagination_retains_complete_authority() {
        let options = azure_remote();
        let transcript = capture_azure_devops_branch_policy_with(&options, |url| {
            if url.contains("/_apis/git/repositories/") {
                Ok(exchange(
                    url,
                    200,
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository"}"#,
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
    fn azure_build_validation_history_is_scoped_to_each_completed_pull_request() {
        let mut options = azure_remote();
        options.resource = AzureDevopsRemoteResource::BuildValidationHistory;
        let transcript = capture_azure_devops_history_with(&options, &mut |url| {
            let body = if url.contains("/repositories/example-repository?") {
                r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository","project":{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}"#
            } else if url.contains("/pullrequests?") {
                r#"{"count":1,"value":[{"pullRequestId":42,"closedDate":"2026-09-11T12:00:00Z","lastMergeCommit":{"commitId":"merge"}}]}"#
            } else if url.contains("continuationToken=next") {
                r#"{"count":0,"value":[]}"#
            } else {
                r#"{"count":1,"value":[{"status":"approved","completedDate":"1969-12-31T23:59:00Z","configuration":{"id":7,"type":{"id":"0609b952-1397-4640-95ec-e00a01b2c241"}}}]}"#
            };
            let headers = if url.contains("/_apis/policy/evaluations?")
                && !url.contains("continuationToken=next")
            {
                BTreeMap::from([("x-ms-continuationtoken".into(), "next".into())])
            } else {
                BTreeMap::new()
            };
            Ok(exchange(url, 200, body, headers))
        })
        .unwrap();
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(
            assessment.authority,
            vec![Proposition::BuildValidationResults]
        );
        assert!(transcript.contents.exchanges[2]
            .request
            .url
            .contains("CodeReviewId%2Faaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee%2F42"));
        assert_eq!(transcript.contents.exchanges.len(), 4);
        let mut unfollowed = transcript.contents.clone();
        unfollowed.exchanges.pop();
        assert_eq!(
            assess(
                &seal_transcript(unfollowed).unwrap(),
                &ContractRegistry::default()
            )
            .enumeration,
            EnumerationStatus::Failed
        );
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
        assert!(ensure_azure_devops_url("https://evil.invalid/steal", "example-org").is_err());
        let failure = classify_azure_devops_failure(
            302,
            r#"{"message":"Moved"}"#,
            &BTreeMap::from([("location".into(), "https://evil.invalid/".into())]),
        );
        assert!(matches!(
            failure,
            AcquisitionTermination::UnsafeRedirect { .. }
        ));
        let request = azure_devops_request(
            &ureq::Agent::new_with_defaults(),
            "https://dev.azure.com/example-org/_apis/projects",
            &authorization,
        );
        assert_eq!(
            request.headers_ref().unwrap()["x-tfs-fedauthredirect"],
            "Suppress"
        );

        let options = azure_remote();
        let transcript = capture_azure_devops_branch_policy_with(&options, |url| {
            if url.contains("/_apis/git/repositories/") {
                Ok(exchange(
                    url,
                    200,
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository"}"#,
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
        assert_eq!(assessment.authority, []);
    }

    #[test]
    fn azure_history_retains_exact_interval_and_vote_history() {
        let mut options = azure_remote();
        options.resource = AzureDevopsRemoteResource::PullRequestReviews;
        let transcript = capture_azure_devops_history_with(&options, &mut |url: &str| {
            let body = if url.contains("/pullrequests?") {
                assert!(url.contains("searchCriteria.targetRefName=refs%2Fheads%2Fdevelop"));
                assert!(url.contains("searchCriteria.minTime="));
                r#"{"value":[{"pullRequestId":42}]}"#
            } else if url.contains("/threads?") {
                r#"{"value":[{"publishedDate":"2026-09-11T11:00:00Z","properties":{"CodeReviewVoteResult":{"$value":10}}}]}"#
            } else {
                r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository"}"#
            };
            Ok(exchange(url, 200, body, BTreeMap::new()))
        }).unwrap();
        assert_eq!(
            assess(&transcript, &ContractRegistry::default()).enumeration,
            EnumerationStatus::Complete
        );
        assert_eq!(transcript.contents.exchanges.len(), 3);
        let mut missing = transcript.contents.clone();
        missing.exchanges.pop();
        assert_eq!(
            assess(
                &seal_transcript(missing).unwrap(),
                &ContractRegistry::default()
            )
            .enumeration,
            EnumerationStatus::Failed
        );
    }
}
