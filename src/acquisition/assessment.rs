use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::azure_devops::{
    azure_devops_next_page_url, azure_devops_policy_configurations_url,
    azure_devops_policy_evaluations_url, azure_devops_project_id, azure_devops_pull_request_ids,
    azure_devops_pull_requests_url, azure_devops_pushes_url, azure_devops_repository_id,
    azure_devops_threads_url, ensure_azure_devops_url, is_uuid, AzureDevopsRemoteCapture,
    AzureDevopsRemoteResource, AZURE_DEVOPS_API_ORIGIN,
};
use super::github::{
    canonical_github_path, ensure_github_url, github_activity_heads, github_activity_url,
    github_associated_pull_requests, github_history_url, github_remote_request,
    github_repository_alias, github_validation_revisions, GithubRemoteCapture,
    GithubRemoteResource, GITHUB_API_ORIGIN,
};
use super::http::{next_link, percent_encode, response_item_count};
use super::transcript::{
    seal_transcript, AcquisitionTermination, AcquisitionTranscript, HttpExchange, HttpRequest,
    TranscriptContents, AZURE_DEVOPS_BRANCH_POLICY_CONTRACT,
    AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT, AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT,
    AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT, GITHUB_BRANCH_PROTECTION_CONTRACT,
    GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT, GITHUB_CHECK_RUNS_CONTRACT, GITHUB_COMMITS_CONTRACT,
    GITHUB_COMMIT_STATUSES_CONTRACT, GITHUB_PULL_REQUEST_REVIEWS_CONTRACT,
    GITHUB_REPOSITORY_MUTATIONS_CONTRACT, TRANSCRIPT_SCHEMA_VERSION,
};
use crate::error::{Error, Result};
use crate::hex_digest;
use crate::model::{Proposition, TimeRange};

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
        && (enumeration == EnumerationStatus::Complete
            || (is_historical_composite_contract(&transcript.contents.collector_contract)
                && enumeration == EnumerationStatus::Truncated))
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
    if matches!(
        transcript.contents.collector_contract.as_str(),
        AZURE_DEVOPS_BRANCH_POLICY_CONTRACT
            | AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT
            | AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT
            | AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT
    ) {
        transcript.contents.exchanges.get(1..).unwrap_or_default()
    } else {
        exchanges_after_github_lookup(transcript)
    }
}

/// the exchanges after the repository lookup that opens a check-run, commit-status,
/// commit, or history transcript, and every exchange of any other transcript.
#[must_use]
pub fn exchanges_after_github_lookup(transcript: &AcquisitionTranscript) -> &[HttpExchange] {
    let contents = &transcript.contents;
    let history = matches!(
        contents.collector_contract.as_str(),
        GITHUB_REPOSITORY_MUTATIONS_CONTRACT
            | GITHUB_PULL_REQUEST_REVIEWS_CONTRACT
            | GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT
    );
    let opens_with_lookup = contents
        .subject
        .id
        .strip_prefix("github:")
        .is_some_and(|repository| {
            contents.initial_request.url == format!("{GITHUB_API_ORIGIN}/repos/{repository}")
        });
    if (history && opens_with_lookup) || github_looked_up_resource(contents).is_some() {
        contents.exchanges.get(1..).unwrap_or_default()
    } else {
        &contents.exchanges
    }
}

/// the resource every page after a leading repository lookup must name.
fn github_looked_up_resource(contents: &TranscriptContents) -> Option<String> {
    let repository = contents.subject.id.strip_prefix("github:")?;
    let lookup = format!("{GITHUB_API_ORIGIN}/repos/{repository}");
    if contents.initial_request.url != lookup {
        return None;
    }
    let suffix = match contents.collector_contract.as_str() {
        GITHUB_COMMITS_CONTRACT => return Some(format!("{lookup}/commits")),
        GITHUB_CHECK_RUNS_CONTRACT => "check-runs",
        GITHUB_COMMIT_STATUSES_CONTRACT => "status",
        _ => return None,
    };
    let revision = contents.subject.qualifier("revision")?;
    Some(format!("{lookup}/commits/{revision}/{suffix}"))
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
        let item_count =
            response_item_count(exchange.response.status, &exchange.response.body).ok();
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
    let next_pages = next_pages(transcript);
    if is_historical_composite_contract(&transcript.contents.collector_contract) {
        return assess_composite_enumeration(transcript, &next_pages, reasons);
    }
    if let Some(reason) = invalid_exchange_sequence(transcript, &next_pages) {
        reasons.push(reason.into());
        return EnumerationStatus::Failed;
    }
    match &transcript.contents.termination {
        AcquisitionTermination::Exhausted => {
            if let Some(status) = assess_github_result_count(transcript, reasons) {
                return status;
            }
            let terminal = exchanges_after_github_lookup(transcript)
                .last()
                .is_some_and(|exchange| exchange.response.status == 200)
                && next_pages.last().is_some_and(Option::is_none);
            if !terminal {
                reasons.push("exhausted transcript lacks a terminal successful response".into());
                EnumerationStatus::Failed
            } else if transcript.contents.exchanges.len() == 1
                && planned_successor(&transcript.contents, None).is_some()
            {
                reasons.push("exhausted transcript lacks its planned detail request".into());
                EnumerationStatus::Failed
            } else {
                EnumerationStatus::Complete
            }
        }
        AcquisitionTermination::Truncated { next_url } => {
            if !truncated_at(&next_pages, next_url) {
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

fn is_historical_composite_contract(contract: &str) -> bool {
    matches!(
        contract,
        GITHUB_REPOSITORY_MUTATIONS_CONTRACT
            | GITHUB_PULL_REQUEST_REVIEWS_CONTRACT
            | GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT
            | AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT
            | AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT
            | AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT
    )
}

fn assess_composite_enumeration(
    transcript: &AcquisitionTranscript,
    next_pages: &[Option<String>],
    reasons: &mut Vec<String>,
) -> EnumerationStatus {
    if let Some(reason) = invalid_composite_sequence(transcript, next_pages) {
        reasons.push(reason);
        return EnumerationStatus::Failed;
    }
    match &transcript.contents.termination {
        AcquisitionTermination::Exhausted => {
            if let Some(reason) = incomplete_composite_population(transcript, next_pages)
                .or_else(|| unplanned_composite_population(transcript, next_pages))
            {
                reasons.push(reason);
                EnumerationStatus::Failed
            } else {
                EnumerationStatus::Complete
            }
        }
        AcquisitionTermination::Truncated { next_url } => {
            if ensure_provider_url(transcript, next_url).is_err() {
                reasons.push("truncation next url is outside the provider origin".into());
                EnumerationStatus::Failed
            } else if !truncated_at(next_pages, next_url) {
                reasons.push("truncation next url does not match the last response".into());
                EnumerationStatus::Failed
            } else if let Some(reason) = unplanned_composite_population(transcript, next_pages) {
                reasons.push(reason);
                EnumerationStatus::Failed
            } else {
                reasons.push("collection stopped while a next page was available".into());
                EnumerationStatus::Truncated
            }
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

fn invalid_composite_sequence(
    transcript: &AcquisitionTranscript,
    next_pages: &[Option<String>],
) -> Option<String> {
    let Some(first) = transcript.contents.exchanges.first() else {
        return Some("composite acquisition has no exchanges".into());
    };
    if first.request != transcript.contents.initial_request {
        return Some("first exchange does not match the initial request".into());
    }
    for exchange in &transcript.contents.exchanges {
        if ensure_provider_url(transcript, &exchange.request.url).is_err() {
            return Some(
                "composite acquisition contains a request outside the provider origin".into(),
            );
        }
        if !historical_request_allowed(transcript, &exchange.request) {
            return Some("historical request does not match the declared repository, branch, interval, or named resource".into());
        }
    }
    for (pair, next) in transcript.contents.exchanges.windows(2).zip(next_pages) {
        if next
            .as_ref()
            .is_some_and(|next| pair[1].request.url != *next)
        {
            return Some("response pagination link does not match the following request".into());
        }
    }
    None
}

fn github_request_allowed(
    contents: &TranscriptContents,
    repository: &str,
    branch: &str,
    request: &HttpRequest,
    path: &str,
) -> bool {
    let prefix = format!("{GITHUB_API_ORIGIN}/repos/{repository}");
    if path == prefix {
        return request == &contents.initial_request;
    }
    let alias = github_repository_alias(&contents.exchanges, repository);
    let path = canonical_github_path(path, alias.as_deref().map(|alias| (prefix.as_str(), alias)));
    let path = path.as_str();
    if path == format!("{prefix}/activity") {
        return query_parameter(&request.url, "ref") == Some(percent_encode(branch).as_str())
            && query_parameter(&request.url, "time_period") == Some("year");
    }
    if let Some(suffix) = path.strip_prefix(&format!("{prefix}/commits/")) {
        return ["/pulls", "/check-runs", "/status"].iter().any(|ending| {
            suffix.strip_suffix(ending).is_some_and(|revision| {
                !revision.is_empty()
                    && !revision.contains('/')
                    && (*ending == "/pulls"
                        || contents.collector_contract == GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT)
            })
        });
    }
    if let Some(suffix) = path.strip_prefix(&format!("{prefix}/pulls/")) {
        return contents.collector_contract == GITHUB_PULL_REQUEST_REVIEWS_CONTRACT
            && suffix
                .strip_suffix("/reviews")
                .is_some_and(|number| number.parse::<u64>().is_ok());
    }
    false
}

fn historical_request_allowed(transcript: &AcquisitionTranscript, request: &HttpRequest) -> bool {
    if request.method != "GET" {
        return false;
    }
    let contents = &transcript.contents;
    let Some(branch) = contents.subject.qualifier("branch") else {
        return false;
    };
    let path = request.url.split('?').next().unwrap_or("");
    if let Some(repository) = contents.subject.id.strip_prefix("github:") {
        return github_request_allowed(contents, repository, branch, request, path);
    }
    let Some(identity) = contents.subject.id.strip_prefix("azure-devops:") else {
        return false;
    };
    let parts = identity.split('/').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let prefix = format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/git/repositories/",
        percent_encode(parts[0]),
        percent_encode(parts[1])
    );
    if path == format!("{prefix}{}", percent_encode(parts[2])) {
        return request == &contents.initial_request;
    }
    let Some(first) = contents.exchanges.first() else {
        return false;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(&first.response.body) else {
        return false;
    };
    let Some(id) = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| is_uuid(id))
    else {
        return false;
    };
    if body.get("name").and_then(serde_json::Value::as_str) != Some(parts[2]) {
        return false;
    }
    let prefix = format!("{prefix}{id}");
    let branch = percent_encode(&format!("refs/heads/{branch}"));
    if path == format!("{prefix}/pushes") {
        return contents.collector_contract == AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT
            && query_parameter(&request.url, "searchCriteria.refName") == Some(branch.as_str())
            && query_parameter(&request.url, "searchCriteria.fromDate")
                == Some(percent_encode(&contents.requested_scope.from).as_str())
            && query_parameter(&request.url, "searchCriteria.toDate")
                == Some(percent_encode(&contents.requested_scope.until).as_str());
    }
    if path == format!("{prefix}/pullrequests") {
        return query_parameter(&request.url, "searchCriteria.targetRefName")
            == Some(branch.as_str())
            && query_parameter(&request.url, "searchCriteria.status") == Some("completed");
    }
    if path
        .strip_prefix(&format!("{prefix}/pullRequests/"))
        .and_then(|suffix| suffix.strip_suffix("/threads"))
        .is_some_and(|number| {
            contents.collector_contract == AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT
                && number.parse::<u64>().is_ok()
        })
    {
        return true;
    }
    let policy_path = format!(
        "{AZURE_DEVOPS_API_ORIGIN}/{}/{}/_apis/policy/evaluations",
        percent_encode(parts[0]),
        percent_encode(parts[1])
    );
    path == policy_path
        && contents.collector_contract == AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT
        && query_parameter(&request.url, "artifactId").is_some_and(|artifact| {
            artifact.starts_with("vstfs%3A%2F%2F%2FCodeReview%2FCodeReviewId%2F")
        })
}

fn query_parameter<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|item| item.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn incomplete_composite_population(
    transcript: &AcquisitionTranscript,
    next_pages: &[Option<String>],
) -> Option<String> {
    let requested = requested_urls(&transcript.contents.exchanges);
    if transcript
        .contents
        .exchanges
        .iter()
        .zip(next_pages)
        .any(|(exchange, next)| {
            exchange.response.status != 200
                || next
                    .as_deref()
                    .is_some_and(|next| !requested.contains(next))
        })
    {
        return Some(
            "composite acquisition lacks a successful terminal page for a requested population"
                .into(),
        );
    }
    let planned = match planned_history(&transcript.contents) {
        Ok(planned) => planned,
        Err(reason) => return Some(reason),
    };
    if let Some((_, reason)) = planned
        .into_iter()
        .find(|(url, _)| !requested.contains(url.as_str()))
    {
        return Some(reason);
    }
    incomplete_github_validation_history(&transcript.contents)
}

/// a population that does not open with a request the collector plans for this transcript, or a
/// planned population missing before the last one the transcript reached.
fn unplanned_composite_population(
    transcript: &AcquisitionTranscript,
    next_pages: &[Option<String>],
) -> Option<String> {
    let contents = &transcript.contents;
    let planned = match planned_history(contents) {
        Ok(planned) => planned,
        Err(reason) => return Some(reason),
    };
    let planned_urls = planned
        .iter()
        .map(|(url, _)| url.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let unplanned = contents
        .exchanges
        .windows(2)
        .zip(next_pages)
        .any(|(pair, next)| {
            let url = pair[1].request.url.as_str();
            next.as_deref() != Some(url) && !planned_urls.contains(url)
        });
    if unplanned {
        let provider = if contents.collector_contract.starts_with("github-") {
            "github"
        } else {
            "azure"
        };
        return Some(format!(
            "{provider} history contains a request its collector does not plan"
        ));
    }
    let requested = requested_urls(&contents.exchanges);
    let reached = planned
        .iter()
        .rposition(|(url, _)| requested.contains(url.as_str()))
        .unwrap_or(0);
    planned
        .into_iter()
        .take(reached + 1)
        .find(|(url, _)| !requested.contains(url.as_str()))
        .map(|(_, reason)| reason)
}

fn requested_urls(exchanges: &[HttpExchange]) -> std::collections::BTreeSet<&str> {
    exchanges
        .iter()
        .map(|exchange| exchange.request.url.as_str())
        .collect()
}

/// every population's planned first request, in fetch order, with the gap its absence leaves.
fn planned_history(
    contents: &TranscriptContents,
) -> std::result::Result<Vec<(String, String)>, String> {
    if contents.collector_contract.starts_with("github-") {
        planned_github_history(contents)
    } else {
        planned_azure_history(contents)
    }
}

fn github_options(
    contents: &TranscriptContents,
    resource: GithubRemoteResource,
    per_page: u16,
) -> Option<GithubRemoteCapture> {
    Some(GithubRemoteCapture {
        repository: contents.subject.id.strip_prefix("github:")?.into(),
        branch: contents
            .subject
            .qualifier("branch")
            .unwrap_or_default()
            .into(),
        revision: contents
            .subject
            .qualifier("revision")
            .unwrap_or_default()
            .into(),
        subject: contents.subject.clone(),
        interval: contents.requested_scope.clone(),
        resource,
        per_page,
        max_pages: 1,
        captured_at: OffsetDateTime::UNIX_EPOCH,
    })
}

/// the history capture whose activity request opens this transcript's enumeration.
fn github_history_options(contents: &TranscriptContents) -> Option<GithubRemoteCapture> {
    let resource = match contents.collector_contract.as_str() {
        GITHUB_REPOSITORY_MUTATIONS_CONTRACT => GithubRemoteResource::RepositoryMutations,
        GITHUB_PULL_REQUEST_REVIEWS_CONTRACT => GithubRemoteResource::PullRequestReviews,
        GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT => GithubRemoteResource::BuildValidationHistory,
        _ => return None,
    };
    let repository = contents.subject.id.strip_prefix("github:")?;
    let activity =
        if contents.initial_request.url == format!("{GITHUB_API_ORIGIN}/repos/{repository}") {
            &contents.exchanges.get(1)?.request
        } else {
            &contents.initial_request
        };
    let per_page = query_parameter(&activity.url, "per_page")?.parse().ok()?;
    github_options(contents, resource, per_page)
}

fn planned_github_history(
    contents: &TranscriptContents,
) -> std::result::Result<Vec<(String, String)>, String> {
    let mismatch = "github history initial request does not match the repository activity resource";
    let options = github_history_options(contents).ok_or_else(|| mismatch.to_owned())?;
    let heads = github_activity_heads(&contents.exchanges, &options)
        .map_err(|_| "github activity population has invalid records".to_owned())?;
    let mut planned = vec![(github_activity_url(&options), mismatch.to_owned())];
    for head in heads {
        planned.push((
            github_history_url(
                &options,
                &format!("commits/{}/pulls", percent_encode(&head)),
            ),
            "github history lacks pull-request association enumeration for a branch mutation"
                .into(),
        ));
    }
    if options.resource == GithubRemoteResource::PullRequestReviews {
        for number in github_associated_pull_requests(&contents.exchanges) {
            planned.push((
                github_history_url(&options, &format!("pulls/{number}/reviews")),
                "github history lacks review enumeration for an associated pull request".into(),
            ));
        }
    }
    if options.resource == GithubRemoteResource::BuildValidationHistory {
        let revisions = github_validation_revisions(&contents.exchanges)
            .map_err(|_| "github integration population has invalid records".to_owned())?;
        for revision in revisions {
            for suffix in ["check-runs", "status"] {
                let path = format!("commits/{}/{suffix}", percent_encode(&revision));
                planned.push((
                    github_history_url(&options, &path),
                    format!(
                        "github history lacks {suffix} enumeration for an integration revision"
                    ),
                ));
            }
        }
    }
    Ok(planned)
}

fn incomplete_github_validation_history(contents: &TranscriptContents) -> Option<String> {
    if contents.collector_contract != GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT {
        return None;
    }
    let repository = contents.subject.id.strip_prefix("github:")?;
    let pages = github_canonical_pages(contents, repository);
    github_validation_revisions(&contents.exchanges)
        .ok()?
        .iter()
        .find_map(|revision| incomplete_github_validation_population(&pages, repository, revision))
}

fn azure_devops_options(contents: &TranscriptContents) -> Option<AzureDevopsRemoteCapture> {
    let resource = match contents.collector_contract.as_str() {
        AZURE_DEVOPS_BRANCH_POLICY_CONTRACT => AzureDevopsRemoteResource::BranchPolicy,
        AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT => {
            AzureDevopsRemoteResource::RepositoryMutations
        }
        AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT => AzureDevopsRemoteResource::PullRequestReviews,
        AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT => {
            AzureDevopsRemoteResource::BuildValidationHistory
        }
        _ => return None,
    };
    let identity = contents.subject.id.strip_prefix("azure-devops:")?;
    let parts = identity.split('/').collect::<Vec<_>>();
    let [organization, project, repository] = parts.as_slice() else {
        return None;
    };
    Some(AzureDevopsRemoteCapture {
        organization: (*organization).into(),
        project: (*project).into(),
        repository: (*repository).into(),
        branch: contents.subject.qualifier("branch")?.into(),
        resource,
        subject: contents.subject.clone(),
        interval: contents.requested_scope.clone(),
        max_pages: 1,
        captured_at: OffsetDateTime::UNIX_EPOCH,
    })
}

fn planned_azure_history(
    contents: &TranscriptContents,
) -> std::result::Result<Vec<(String, String)>, String> {
    let unverified = || "azure history has no verified repository identifier".to_owned();
    let options = azure_devops_options(contents).ok_or_else(unverified)?;
    let repository = contents.exchanges.first().ok_or_else(unverified)?;
    let repository_id =
        azure_devops_repository_id(&options, repository).map_err(|_| unverified())?;
    let mut planned = Vec::new();
    if options.resource == AzureDevopsRemoteResource::RepositoryMutations {
        planned.push((
            azure_devops_pushes_url(&options, &repository_id, 0),
            "azure history lacks branch mutation enumeration".to_owned(),
        ));
    }
    planned.push((
        azure_devops_pull_requests_url(&options, &repository_id, 0),
        "azure history lacks completed pull-request enumeration".into(),
    ));
    let pulls = azure_devops_pull_request_ids(&contents.exchanges);
    if options.resource == AzureDevopsRemoteResource::PullRequestReviews {
        for &number in &pulls {
            planned.push((
                azure_devops_threads_url(&options, &repository_id, number),
                "azure history lacks vote-history enumeration for a completed pull request".into(),
            ));
        }
    }
    if options.resource == AzureDevopsRemoteResource::BuildValidationHistory && !pulls.is_empty() {
        let project_id = azure_devops_project_id(repository)
            .map_err(|_| "azure history has no verified project identifier".to_owned())?;
        for number in pulls {
            planned.push((
                azure_devops_policy_evaluations_url(&options, &project_id, number),
                "azure history lacks policy evaluation for a completed pull request".into(),
            ));
        }
    }
    Ok(planned)
}

fn github_canonical_pages<'a>(
    contents: &'a TranscriptContents,
    repository: &str,
) -> BTreeMap<String, Vec<&'a HttpExchange>> {
    let prefix = format!("{GITHUB_API_ORIGIN}/repos/{repository}");
    let alias = github_repository_alias(&contents.exchanges, repository);
    let alias = alias.as_deref().map(|alias| (prefix.as_str(), alias));
    let mut pages = BTreeMap::<_, Vec<_>>::new();
    for exchange in &contents.exchanges {
        let requested = exchange.request.url.split('?').next().unwrap_or("");
        pages
            .entry(canonical_github_path(requested, alias))
            .or_default()
            .push(exchange);
    }
    pages
}

fn incomplete_github_validation_population(
    pages: &BTreeMap<String, Vec<&HttpExchange>>,
    repository: &str,
    revision: &str,
) -> Option<String> {
    let prefix = format!("{GITHUB_API_ORIGIN}/repos/{repository}");
    for (suffix, field, label) in [
        ("check-runs", "check_runs", "check run"),
        ("status", "statuses", "commit status"),
    ] {
        let path = format!("{prefix}/commits/{revision}/{suffix}");
        let mut reported = None;
        let mut retained = 0_u64;
        for exchange in pages.get(&path).into_iter().flatten() {
            let Ok(body) = serde_json::from_str::<serde_json::Value>(&exchange.response.body)
            else {
                return Some(format!("github {label} history contains invalid JSON"));
            };
            if reported.is_none() {
                reported = body.get("total_count").and_then(serde_json::Value::as_u64);
            }
            retained += body
                .get(field)
                .and_then(serde_json::Value::as_array)
                .map_or(0, |items| items.len() as u64);
        }
        let Some(reported) = reported else {
            return Some(format!("github {label} history has no total_count"));
        };
        if reported != retained {
            return Some(format!(
                "github reported {reported} {label}(s) for an integration revision, but {retained} were retained"
            ));
        }
        if suffix == "check-runs" && reported > 1_000 {
            return Some(
                "github check-run history exceeds the provider's 1,000-suite enumeration limit"
                    .into(),
            );
        }
    }
    None
}

fn ensure_provider_url(transcript: &AcquisitionTranscript, url: &str) -> Result<()> {
    if transcript
        .contents
        .collector_contract
        .starts_with("github-")
    {
        ensure_github_url(url)
    } else {
        let organization = transcript
            .contents
            .subject
            .id
            .strip_prefix("azure-devops:")
            .and_then(|identity| identity.split('/').next())
            .ok_or_else(|| {
                Error::Invalid("azure transcript has no organization identity".into())
            })?;
        ensure_azure_devops_url(url, organization)
    }
}

fn invalid_exchange_sequence(
    transcript: &AcquisitionTranscript,
    next_pages: &[Option<String>],
) -> Option<&'static str> {
    if transcript
        .contents
        .exchanges
        .first()
        .is_some_and(|first| first.request != transcript.contents.initial_request)
    {
        return Some("first exchange does not match the initial request");
    }
    let looked_up = github_looked_up_resource(&transcript.contents);
    if let (Some(resource), Some(repository)) = (
        &looked_up,
        transcript.contents.subject.id.strip_prefix("github:"),
    ) {
        let alias = github_repository_alias(&transcript.contents.exchanges, repository);
        let lookup = transcript.contents.initial_request.url.as_str();
        let alias = alias.as_deref().map(|alias| (lookup, alias));
        if transcript
            .contents
            .exchanges
            .iter()
            .skip(1)
            .any(|exchange| {
                canonical_github_path(exchange.request.url.split('?').next().unwrap_or(""), alias)
                    != *resource
            })
        {
            return Some("github pagination changed the requested resource");
        }
    }
    for (index, (pair, next)) in transcript
        .contents
        .exchanges
        .windows(2)
        .zip(next_pages)
        .enumerate()
    {
        let planned = (index == 0)
            .then(|| planned_successor(&transcript.contents, Some(&pair[1])))
            .flatten();
        if planned.is_some() && planned.as_deref() != Some(pair[1].request.url.as_str()) {
            return Some("request does not match the one its collector plans");
        }
        if planned.is_none() && next.as_deref() != Some(pair[1].request.url.as_str()) {
            return Some("response pagination link does not match the following request");
        }
    }
    None
}

/// the request a single-resource collector plans after its first exchange: the first page after
/// a repository lookup, or a protected branch's or a repository's policy detail.
fn planned_successor(
    contents: &TranscriptContents,
    following: Option<&HttpExchange>,
) -> Option<String> {
    let first = contents
        .exchanges
        .first()
        .filter(|first| first.response.status == 200)?;
    match contents.collector_contract.as_str() {
        GITHUB_BRANCH_PROTECTION_CONTRACT => {
            let options = github_options(contents, GithubRemoteResource::BranchProtection, 1)?;
            let body = serde_json::from_str::<serde_json::Value>(&first.response.body).ok()?;
            (first.request.url == github_remote_request(&options).2
                && body.get("protected") == Some(&serde_json::Value::Bool(true)))
            .then(|| format!("{}/protection", first.request.url))
        }
        AZURE_DEVOPS_BRANCH_POLICY_CONTRACT => {
            let options = azure_devops_options(contents)?;
            let repository_id = azure_devops_repository_id(&options, first).ok()?;
            Some(azure_devops_policy_configurations_url(
                &options,
                &repository_id,
            ))
        }
        contract => {
            github_looked_up_resource(contents)?;
            let per_page = query_parameter(&following?.request.url, "per_page")?
                .parse()
                .ok()?;
            let resource = match contract {
                GITHUB_CHECK_RUNS_CONTRACT => GithubRemoteResource::CheckRuns,
                GITHUB_COMMIT_STATUSES_CONTRACT => GithubRemoteResource::CommitStatuses,
                _ => {
                    return Some(commits_url(
                        contents.subject.id.strip_prefix("github:")?,
                        contents.subject.qualifier("branch")?,
                        &contents.requested_scope,
                        per_page,
                    ));
                }
            };
            Some(github_remote_request(&github_options(contents, resource, per_page)?).2)
        }
    }
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
    let pages = exchanges_after_github_lookup(transcript);
    let reported = pages
        .first()
        .and_then(|exchange| {
            serde_json::from_str::<serde_json::Value>(&exchange.response.body).ok()
        })
        .and_then(|body| body.get("total_count").and_then(serde_json::Value::as_u64));
    let fetched = pages
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
        GITHUB_REPOSITORY_MUTATIONS_CONTRACT | AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT => {
            vec![Proposition::RepositoryMutations]
        }
        GITHUB_PULL_REQUEST_REVIEWS_CONTRACT | AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT => {
            vec![Proposition::PullRequestReviews]
        }
        GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT
        | AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT => {
            vec![Proposition::BuildValidationResults]
        }
        _ => vec![],
    }
}

/// the page the collector requests after `exchange`, the zero-based `page` of its population.
fn next_page_url(contract: &str, exchange: &HttpExchange, page: u64) -> Option<String> {
    if exchange.response.status != 200 {
        None
    } else if contract.starts_with("azure-devops-") {
        azure_devops_next_page_url(exchange, page)
    } else {
        next_link(&exchange.response.headers)
    }
}

/// the next page of every exchange, counting pages along each population's chain.
fn next_pages(transcript: &AcquisitionTranscript) -> Vec<Option<String>> {
    let contract = transcript.contents.collector_contract.as_str();
    let mut next_pages = Vec::<Option<String>>::new();
    let mut page = 0;
    for exchange in &transcript.contents.exchanges {
        let continues = next_pages
            .last()
            .and_then(Option::as_deref)
            .is_some_and(|next| next == exchange.request.url);
        page = if continues { page + 1 } else { 0 };
        next_pages.push(next_page_url(contract, exchange, page));
    }
    next_pages
}

fn truncated_at(next_pages: &[Option<String>], next_url: &str) -> bool {
    next_pages.last().and_then(Option::as_deref) == Some(next_url)
}

fn commits_url(repository: &str, branch: &str, interval: &TimeRange, per_page: u16) -> String {
    format!(
        "{GITHUB_API_ORIGIN}/repos/{repository}/commits?sha={}&since={}&until={}&per_page={per_page}&page=1",
        percent_encode(branch),
        percent_encode(&interval.from),
        percent_encode(&interval.until),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::azure_devops::{
        capture_azure_devops_branch_policy_with, capture_azure_devops_history_with,
    };
    use crate::acquisition::github::capture_github_remote_with;
    use crate::acquisition::http::build_exchange;
    use crate::acquisition::test_support::{
        azure_remote, exchange, github_lookup, remote, REVISION,
    };
    use crate::model::Subject;

    fn github_commits(interval: TimeRange) -> AcquisitionTranscript {
        let lookup = "https://api.github.com/repos/cyberwitchery/divinate";
        let first = commits_url("cyberwitchery/divinate", "main", &interval, 100);
        let second = "https://api.github.com/repositories/123/commits?sha=main&per_page=100&page=2";
        let next = BTreeMap::from([("link".into(), format!("<{second}>; rel=\"next\""))]);
        seal_transcript(TranscriptContents {
            collector_contract: GITHUB_COMMITS_CONTRACT.into(),
            collector_version: env!("CARGO_PKG_VERSION").into(),
            subject: Subject {
                kind: "repository".into(),
                id: "github:cyberwitchery/divinate".into(),
                qualifiers: BTreeMap::from([("branch".into(), "main".into())]),
            },
            proposition: Proposition::CommitAncestry,
            requested_scope: interval,
            captured_at: "1970-01-01T00:00:00Z".into(),
            initial_request: HttpRequest {
                method: "GET".into(),
                url: lookup.into(),
            },
            exchanges: vec![
                github_lookup(lookup).unwrap(),
                exchange(&first, 200, r#"[{"sha":"one"}]"#, next),
                exchange(second, 200, r#"[{"sha":"two"}]"#, BTreeMap::new()),
            ],
            termination: AcquisitionTermination::Exhausted,
        })
        .unwrap()
    }

    #[test]
    fn github_commit_pagination_stays_on_the_proven_repository() {
        let transcript = github_commits(TimeRange {
            from: "2026-09-11T00:00:00Z".into(),
            until: "2026-09-12T00:00:00Z".into(),
        });
        let assessment = assess(&transcript, &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Complete);
        assert_eq!(assessment.items, 2);
        assert_eq!(assessment.authority, vec![Proposition::CommitAncestry]);

        let mut gap = transcript.contents.clone();
        gap.exchanges[2].request.url = gap.exchanges[2].request.url.replace("page=2", "page=3");
        let assessment = assess(&seal_transcript(gap).unwrap(), &ContractRegistry::default());
        assert_eq!(assessment.enumeration, EnumerationStatus::Failed);

        let mut moved = transcript.contents.clone();
        let other = moved.exchanges[2].request.url.replace("/123/", "/999/");
        moved.exchanges[1]
            .response
            .headers
            .insert("link".into(), format!("<{other}>; rel=\"next\""));
        moved.exchanges[2].request.url = other;
        let assessment = assess(
            &seal_transcript(moved).unwrap(),
            &ContractRegistry::default(),
        );
        assert_eq!(assessment.enumeration, EnumerationStatus::Failed);
    }

    #[test]
    fn historical_permission_and_pagination_failures_remain_gaps() {
        let mut options = remote(GithubRemoteResource::RepositoryMutations);
        options.max_pages = 1;
        let transcript = capture_github_remote_with(&options, |url| {
            if let Some(lookup) = github_lookup(url) {
                return Ok(lookup);
            }
            Ok(exchange(
                url,
                200,
                "[]",
                BTreeMap::from([("link".into(), format!("<{url}&page=2>; rel=\"next\""))]),
            ))
        })
        .unwrap();
        assert_eq!(
            assess(&transcript, &ContractRegistry::default()).enumeration,
            EnumerationStatus::Truncated
        );
        let mut azure = azure_remote();
        azure.resource = AzureDevopsRemoteResource::RepositoryMutations;
        let transcript = capture_azure_devops_history_with(&azure, &mut |url: &str| {
            Ok(exchange(
                url,
                403,
                r#"{"message":"access denied"}"#,
                BTreeMap::new(),
            ))
        })
        .unwrap();
        assert_eq!(
            assess(&transcript, &ContractRegistry::default()).enumeration,
            EnumerationStatus::PermissionDenied
        );
    }

    #[test]
    fn empty_history_is_complete_authoritative_coverage() {
        for (github, azure, authority, azure_pages) in [
            (
                GithubRemoteResource::RepositoryMutations,
                AzureDevopsRemoteResource::RepositoryMutations,
                Proposition::RepositoryMutations,
                2,
            ),
            (
                GithubRemoteResource::PullRequestReviews,
                AzureDevopsRemoteResource::PullRequestReviews,
                Proposition::PullRequestReviews,
                1,
            ),
            (
                GithubRemoteResource::BuildValidationHistory,
                AzureDevopsRemoteResource::BuildValidationHistory,
                Proposition::BuildValidationResults,
                1,
            ),
        ] {
            let github = capture_github_remote_with(&remote(github), |url| {
                Ok(github_lookup(url).unwrap_or_else(|| exchange(url, 200, "[]", BTreeMap::new())))
            })
            .unwrap();
            let mut without_lookup = github.contents.clone();
            without_lookup.exchanges.remove(0);
            without_lookup.initial_request = without_lookup.exchanges[0].request.clone();
            let mut options = azure_remote();
            options.resource = azure;
            let azure = capture_azure_devops_history_with(&options, &mut |url: &str| {
                let body = if url.contains("/pushes?") || url.contains("/pullrequests?") {
                    r#"{"value":[]}"#
                } else {
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository","project":{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}"#
                };
                Ok(exchange(url, 200, body, BTreeMap::new()))
            })
            .unwrap();
            for (transcript, pages) in [
                (github, 1),
                (seal_transcript(without_lookup).unwrap(), 1),
                (azure, azure_pages),
            ] {
                let assessment = assess(&transcript, &ContractRegistry::default());
                assert_eq!(
                    (
                        assessment.enumeration,
                        assessment.authority,
                        assessment.pages,
                        assessment.items
                    ),
                    (EnumerationStatus::Complete, vec![authority], pages, 0),
                    "{} from {}",
                    transcript.contents.collector_contract,
                    transcript.contents.initial_request.url
                );
            }
        }
    }

    #[test]
    fn non_json_error_bodies_are_retained_as_classified_failures() {
        let html = "<!DOCTYPE html><html><body>Sign in</body></html>";
        let github = |status: u16, body: &str| {
            capture_github_remote_with(&remote(GithubRemoteResource::BranchProtection), |url| {
                Ok(exchange(url, status, body, BTreeMap::new()))
            })
        };
        let azure = |status: u16, body: &str| {
            capture_azure_devops_branch_policy_with(&azure_remote(), |url| {
                Ok(exchange(url, status, body, BTreeMap::new()))
            })
        };
        let failed = AcquisitionTermination::Failed {
            diagnostic: "HTTP 500: request failed".into(),
        };
        for (transcript, termination, enumeration) in [
            (github(500, ""), failed.clone(), EnumerationStatus::Failed),
            (github(500, html), failed, EnumerationStatus::Failed),
            (
                azure(401, html),
                AcquisitionTermination::Unauthenticated {
                    diagnostic: "HTTP 401: request failed".into(),
                },
                EnumerationStatus::Unauthenticated,
            ),
        ] {
            let transcript = transcript.unwrap();
            assert_eq!(transcript.contents.termination, termination);
            assert_eq!(transcript.contents.exchanges.len(), 1);
            assert_eq!(transcript.contents.exchanges[0].response.item_count, 0);
            let assessment = assess(&transcript, &ContractRegistry::default());
            assert_eq!(
                assessment.integrity,
                IntegrityStatus::Verified,
                "{:?}",
                assessment.reasons
            );
            assert_eq!(assessment.enumeration, enumeration);
            assert_eq!(assessment.authority, []);
        }
    }

    #[test]
    fn only_error_responses_may_carry_a_non_json_body() {
        let recorded =
            capture_github_remote_with(&remote(GithubRemoteResource::BranchProtection), |url| {
                Ok(exchange(url, 500, "", BTreeMap::new()))
            })
            .unwrap();
        for (status, retained) in [
            (200, false),
            (204, false),
            (299, false),
            (300, true),
            (302, true),
            (401, true),
            (500, true),
        ] {
            for body in ["", "<html><body>error</body></html>"] {
                let built = build_exchange(
                    GITHUB_API_ORIGIN,
                    status,
                    BTreeMap::new(),
                    body.into(),
                    "github",
                );
                assert_eq!(built.is_ok(), retained, "{status} {body:?}");
                let mut contents = recorded.contents.clone();
                let response = &mut contents.exchanges[0].response;
                response.status = status;
                response.body = body.into();
                response.body_sha256 = hex_digest(body.as_bytes());
                let mut reasons = Vec::new();
                let integrity = verify_integrity(&seal_transcript(contents).unwrap(), &mut reasons);
                assert_eq!(
                    integrity == IntegrityStatus::Verified,
                    retained,
                    "{status} {body:?} {reasons:?}"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn altered_transcripts_cannot_claim_the_collector_plan() {
        const DIRECT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const MERGE: &str = "cccccccccccccccccccccccccccccccccccccccc";
        let reseal = |transcript: &AcquisitionTranscript,
                      alter: &dyn Fn(&mut TranscriptContents)| {
            let mut contents = transcript.contents.clone();
            alter(&mut contents);
            seal_transcript(contents).unwrap()
        };
        let history = |url: &str| {
            let activity = |id, kind, head| {
                format!(
                    r#"[{{"id":{id},"ref":"refs/heads/main","timestamp":"2026-09-11T1{id}:00:00Z","after":"{head}","activity_type":"{kind}"}}]"#
                )
            };
            Ok(github_lookup(url).unwrap_or_else(|| {
                if url.ends_with("&after=cursor2") {
                    exchange(url, 200, &activity(2, "pr_merge", MERGE), BTreeMap::new())
                } else if url.contains("/activity?") {
                    let next = format!("<{url}&after=cursor2>; rel=\"next\"");
                    let headers = BTreeMap::from([("link".into(), next)]);
                    exchange(url, 200, &activity(1, "push", DIRECT), headers)
                } else if url.contains(&format!("/commits/{MERGE}/pulls?")) {
                    let pulls = format!(r#"[{{"number":7,"merge_commit_sha":"{MERGE}","head":{{"sha":"{REVISION}"}}}}]"#);
                    exchange(url, 200, &pulls, BTreeMap::new())
                } else if url.contains("/reviews?") {
                    exchange(url, 403, r#"{"message":"Resource not accessible"}"#, BTreeMap::new())
                } else if url.contains("/check-runs?") {
                    exchange(url, 200, r#"{"total_count":2,"check_runs":[{"name":"lint"},{"name":"build"}]}"#, BTreeMap::new())
                } else if url.ends_with("/protection") {
                    exchange(url, 200, r#"{"required_signatures":{"enabled":true}}"#, BTreeMap::new())
                } else if url.contains("/branches/") {
                    exchange(url, 200, r#"{"protected":true}"#, BTreeMap::new())
                } else {
                    exchange(url, 200, "[]", BTreeMap::new())
                }
            }))
        };
        let github = |resource, max_pages| {
            let options = GithubRemoteCapture {
                max_pages,
                ..remote(resource)
            };
            capture_github_remote_with(&options, history).unwrap()
        };
        let commits = github_commits(remote(GithubRemoteResource::CheckRuns).interval);
        let full = (0..100)
            .map(|id| format!(r#"{{"pushId":{id}}}"#))
            .collect::<Vec<_>>();
        let full = format!(r#"{{"value":[{}]}}"#, full.join(","));
        let azure = |resource, max_pages| {
            let options = AzureDevopsRemoteCapture {
                resource,
                max_pages,
                ..azure_remote()
            };
            let mut fetch = |url: &str| {
                let body = if url.contains("/pushes?") && url.contains("%24skip=200") {
                    r#"{"value":[{"pushId":200}]}"#
                } else if url.contains("/pushes?") {
                    full.as_str()
                } else if url.contains("/pullrequests?") {
                    r#"{"value":[{"pullRequestId":1},{"pullRequestId":2}]}"#
                } else if url.contains("/threads?") || url.contains("/evaluations?") {
                    r#"{"value":[{"id":1}]}"#
                } else if url.contains("/configurations?") {
                    r#"{"value":[{"id":1,"isBlocking":true}]}"#
                } else {
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository","project":{"id":"22222222-3333-4444-5555-666666666666"}}"#
                };
                Ok(exchange(url, 200, body, BTreeMap::new()))
            };
            if resource == AzureDevopsRemoteResource::BranchPolicy {
                capture_azure_devops_branch_policy_with(&options, fetch).unwrap()
            } else {
                capture_azure_devops_history_with(&options, &mut fetch).unwrap()
            }
        };
        let mutations = github(GithubRemoteResource::RepositoryMutations, 10);
        let truncated = github(GithubRemoteResource::RepositoryMutations, 1);
        let denied = github(GithubRemoteResource::PullRequestReviews, 10);
        let runs = github(GithubRemoteResource::CheckRuns, 10);
        let protection = github(GithubRemoteResource::BranchProtection, 10);
        let pushes = azure(AzureDevopsRemoteResource::RepositoryMutations, 10);
        let skipped = azure(AzureDevopsRemoteResource::RepositoryMutations, 1);
        let votes = azure(AzureDevopsRemoteResource::PullRequestReviews, 10);
        let evaluations = azure(AzureDevopsRemoteResource::BuildValidationHistory, 10);
        let policy = azure(AzureDevopsRemoteResource::BranchPolicy, 10);
        let chain = |resource, paged: &str| {
            let heads = [DIRECT, MERGE, "dddddddddddddddddddddddddddddddddddddddd"];
            let options = GithubRemoteCapture {
                max_pages: 1,
                ..remote(resource)
            };
            capture_github_remote_with(&options, |url: &str| {
                if let Some(lookup) = github_lookup(url) {
                    return Ok(lookup);
                }
                let body = if url.contains("/activity?") {
                    let records = heads.map(|head| {
                        format!(r#"{{"ref":"refs/heads/main","timestamp":"2026-09-11T10:00:00Z","after":"{head}"}}"#)
                    });
                    format!("[{}]", records.join(","))
                } else if let Some(n) = heads
                    .iter()
                    .position(|head| url.contains(&format!("/commits/{head}/pulls?")))
                {
                    format!(r#"[{{"number":{}}}]"#, n + 7)
                } else {
                    "[]".into()
                };
                let mut headers = BTreeMap::new();
                if url.contains(paged) {
                    headers.insert("link".into(), format!("<{url}&page=2>; rel=\"next\""));
                }
                Ok(exchange(url, 200, &body, headers))
            })
            .unwrap()
        };
        let reviewed = chain(
            GithubRemoteResource::PullRequestReviews,
            "/pulls/9/reviews?",
        );
        let pulled = chain(
            GithubRemoteResource::RepositoryMutations,
            &format!("/commits/{MERGE}/pulls?"),
        );
        let evaluated = capture_azure_devops_history_with(
            &AzureDevopsRemoteCapture {
                resource: AzureDevopsRemoteResource::BuildValidationHistory,
                max_pages: 1,
                ..azure_remote()
            },
            &mut |url: &str| {
                let body = if url.contains("/pullrequests?") {
                    r#"{"value":[{"pullRequestId":1},{"pullRequestId":2},{"pullRequestId":3}]}"#
                } else if url.contains("%2F3&") {
                    full.as_str()
                } else if url.contains("/evaluations?") {
                    r#"{"value":[{"id":1}]}"#
                } else {
                    r#"{"id":"11111111-2222-3333-4444-555555555555","name":"example-repository","project":{"id":"22222222-3333-4444-5555-666666666666"}}"#
                };
                Ok(exchange(url, 200, body, BTreeMap::new()))
            },
        )
        .unwrap();
        let complete = EnumerationStatus::Complete;
        for (transcript, expected) in [
            (
                &commits,
                (complete, vec![Proposition::CommitAncestry], 2, 2),
            ),
            (&runs, (complete, vec![Proposition::RevisionChecks], 1, 2)),
            (
                &protection,
                (complete, vec![Proposition::BranchConfiguration], 2, 2),
            ),
            (
                &mutations,
                (complete, vec![Proposition::RepositoryMutations], 4, 3),
            ),
            (
                &truncated,
                (
                    EnumerationStatus::Truncated,
                    vec![Proposition::RepositoryMutations],
                    1,
                    1,
                ),
            ),
            (&denied, (EnumerationStatus::PermissionDenied, vec![], 5, 4)),
            (
                &pushes,
                (complete, vec![Proposition::RepositoryMutations], 4, 203),
            ),
            (
                &skipped,
                (
                    EnumerationStatus::Truncated,
                    vec![Proposition::RepositoryMutations],
                    1,
                    100,
                ),
            ),
            (
                &votes,
                (complete, vec![Proposition::PullRequestReviews], 3, 4),
            ),
            (
                &evaluations,
                (complete, vec![Proposition::BuildValidationResults], 3, 4),
            ),
            (
                &policy,
                (complete, vec![Proposition::BranchConfiguration], 1, 1),
            ),
            (
                &reviewed,
                (
                    EnumerationStatus::Truncated,
                    vec![Proposition::PullRequestReviews],
                    7,
                    6,
                ),
            ),
            (
                &pulled,
                (
                    EnumerationStatus::Truncated,
                    vec![Proposition::RepositoryMutations],
                    3,
                    5,
                ),
            ),
            (
                &evaluated,
                (
                    EnumerationStatus::Truncated,
                    vec![Proposition::BuildValidationResults],
                    4,
                    105,
                ),
            ),
        ] {
            let assessment = assess(transcript, &ContractRegistry::default());
            let actual = (
                assessment.enumeration,
                assessment.authority,
                assessment.pages,
                assessment.items,
            );
            assert_eq!(
                actual, expected,
                "{}",
                transcript.contents.collector_contract
            );
        }

        let url = |transcript: &AcquisitionTranscript, part: &str| {
            transcript
                .contents
                .exchanges
                .iter()
                .position(|exchange| exchange.request.url.contains(part))
                .unwrap()
        };
        let pulls = format!("/commits/{DIRECT}/pulls");
        for (gap, transcript) in [
            (
                "azure $skip page dropped",
                reseal(&pushes, &|c| {
                    c.exchanges.remove(url(&pushes, "%24skip=100"));
                }),
            ),
            (
                "truncation onto another resource",
                reseal(&truncated, &|c| {
                    c.termination = AcquisitionTermination::Truncated {
                        next_url: "https://api.github.com/repos/someone/else/pulls?page=9".into(),
                    };
                }),
            ),
            (
                "denied run relabelled truncated",
                reseal(&denied, &|c| {
                    let denied = c.exchanges.last_mut().unwrap();
                    let next_url = format!("{}&page=2", denied.request.url);
                    let link = format!("<{next_url}>; rel=\"next\"");
                    denied.response.headers.insert("link".into(), link);
                    c.termination = AcquisitionTermination::Truncated { next_url };
                }),
            ),
            (
                "first activity page dropped",
                reseal(&mutations, &|c| {
                    c.exchanges.retain(|e| {
                        !e.request.url.ends_with("per_page=100")
                            || !e.request.url.contains("/activity?")
                    });
                    c.exchanges.retain(|e| !e.request.url.contains(&pulls));
                }),
            ),
            (
                "activity filtered",
                reseal(&mutations, &|c| {
                    let filtered = format!("{}&activity_type=pr_merge", c.exchanges[1].request.url);
                    let merge = c.exchanges[2].response.body.clone();
                    c.exchanges.retain(|e| {
                        !e.request.url.contains("/activity?") && !e.request.url.contains(&pulls)
                    });
                    c.exchanges
                        .insert(1, exchange(&filtered, 200, &merge, BTreeMap::new()));
                }),
            ),
            (
                "first commit page dropped",
                reseal(&commits, &|c| {
                    c.exchanges.remove(1);
                }),
            ),
            (
                "commits from another branch and window",
                reseal(&commits, &|c| {
                    let other = c.exchanges[1]
                        .request
                        .url
                        .replace("sha=main", "sha=release")
                        .replace("since=2026-09-11T00", "since=2026-09-11T23");
                    c.exchanges.truncate(1);
                    c.exchanges
                        .push(exchange(&other, 200, "[]", BTreeMap::new()));
                }),
            ),
            (
                "check runs filtered by name",
                reseal(&runs, &|c| {
                    let lint = c.exchanges[1]
                        .request
                        .url
                        .replace("check-runs?", "check-runs?check_name=lint&");
                    c.exchanges[1] = exchange(
                        &lint,
                        200,
                        r#"{"total_count":1,"check_runs":[{"name":"lint"}]}"#,
                        BTreeMap::new(),
                    );
                }),
            ),
            (
                "pull requests narrowed",
                reseal(&votes, &|c| {
                    let index = url(&votes, "/pullrequests?");
                    let narrowed = c.exchanges[index]
                        .request
                        .url
                        .replace("minTime=2026-09-11T00", "minTime=2026-09-11T23")
                        + "&searchCriteria.creatorId=33333333-4444-5555-6666-777777777777";
                    c.exchanges[index] =
                        exchange(&narrowed, 200, r#"{"value":[]}"#, BTreeMap::new());
                    c.exchanges.retain(|e| !e.request.url.contains("/threads?"));
                }),
            ),
            (
                "vote history of an unlisted pull request",
                reseal(&votes, &|c| {
                    let threads = &c.exchanges.last().unwrap().request.url;
                    let other = threads.replace("/pullRequests/2/", "/pullRequests/999/");
                    c.exchanges
                        .push(exchange(&other, 200, r#"{"value":[]}"#, BTreeMap::new()));
                }),
            ),
            (
                "pushes filtered by pusher",
                reseal(&pushes, &|c| {
                    let filtered = c.exchanges[1].request.url.replace(
                        "includeRefUpdates=true",
                        "pusherId=33333333-4444-5555-6666-777777777777",
                    );
                    c.exchanges.retain(|e| !e.request.url.contains("/pushes?"));
                    c.exchanges.insert(
                        1,
                        exchange(&filtered, 200, r#"{"value":[]}"#, BTreeMap::new()),
                    );
                }),
            ),
            (
                "filtered pushes cut at a full page",
                reseal(&skipped, &|c| {
                    let filtered = c.exchanges[1].request.url.replace(
                        "includeRefUpdates=true",
                        "pusherId=33333333-4444-5555-6666-777777777777",
                    );
                    let next_url = filtered.replace("%24skip=0", "%24skip=100");
                    c.exchanges[1].request.url = filtered;
                    c.termination = AcquisitionTermination::Truncated { next_url };
                }),
            ),
            (
                "evaluation from another project",
                reseal(&evaluations, &|c| {
                    let index = url(&evaluations, "%2F2&");
                    let other = c.exchanges[index]
                        .request
                        .url
                        .replace("22222222-3333", "99999999-3333");
                    c.exchanges[index].request.url = other;
                }),
            ),
            (
                "evaluation of another pull request",
                reseal(&evaluations, &|c| {
                    let index = url(&evaluations, "%2F2&");
                    let other = c.exchanges[index].request.url.replace("%2F2&", "%2F999&");
                    c.exchanges[index].request.url = other;
                }),
            ),
            (
                "protection detail dropped",
                reseal(&protection, &|c| c.exchanges.truncate(1)),
            ),
            (
                "policy configurations dropped",
                reseal(&policy, &|c| c.exchanges.truncate(1)),
            ),
            (
                "earlier pull request's reviews dropped before the cut",
                reseal(&reviewed, &|c| {
                    c.exchanges.remove(url(&reviewed, "/pulls/8/reviews?"));
                }),
            ),
            (
                "earlier pull request's evaluation dropped before the cut",
                reseal(&evaluated, &|c| {
                    c.exchanges.remove(url(&evaluated, "%2F2&"));
                }),
            ),
            (
                "earlier head's pulls dropped before the cut",
                reseal(&pulled, &|c| {
                    c.exchanges.remove(url(&pulled, &pulls));
                }),
            ),
            (
                "repository lookup alone relabelled truncated",
                reseal(&skipped, &|c| {
                    let next_url = format!("{}&continuationToken=t", c.initial_request.url);
                    c.exchanges.truncate(1);
                    let token = ("x-ms-continuationtoken".into(), "t".into());
                    c.exchanges[0].response.headers.extend([token]);
                    c.termination = AcquisitionTermination::Truncated { next_url };
                }),
            ),
            (
                "denied run relabelled exhausted",
                reseal(&denied, &|c| {
                    c.termination = AcquisitionTermination::Exhausted;
                }),
            ),
            (
                "denied protection detail relabelled exhausted",
                reseal(&protection, &|c| {
                    let detail = c.exchanges[1].request.url.clone();
                    c.exchanges[1] =
                        exchange(&detail, 403, r#"{"message":"Forbidden"}"#, BTreeMap::new());
                }),
            ),
            (
                "last commit page dropped",
                reseal(&commits, &|c| {
                    c.exchanges.pop();
                }),
            ),
            (
                "protected branch moved to another branch",
                reseal(&protection, &|c| {
                    let moved = |url: &str| url.replace("/branches/main", "/branches/release");
                    c.initial_request.url = moved(&c.initial_request.url);
                    for exchange in &mut c.exchanges {
                        exchange.request.url = moved(&exchange.request.url);
                    }
                }),
            ),
        ] {
            let assessment = assess(&transcript, &ContractRegistry::default());
            assert!(
                assessment.enumeration != EnumerationStatus::Complete
                    && assessment.authority.is_empty(),
                "{gap}: {:?} {:?}",
                assessment.enumeration,
                assessment.reasons
            );
        }
    }
}
