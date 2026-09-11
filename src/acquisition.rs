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
    Truncated { next_url: String },
    PermissionDenied { diagnostic: String },
    Failed { diagnostic: String },
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
    PermissionDenied,
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
    AcquisitionAssessment {
        transcript_id: transcript.id.clone(),
        integrity,
        contract,
        enumeration,
        authority,
        pages: u64::try_from(transcript.contents.exchanges.len()).unwrap_or(u64::MAX),
        items: transcript
            .contents
            .exchanges
            .iter()
            .map(|exchange| exchange.response.item_count)
            .sum(),
        reasons,
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
    if let Some(first) = transcript.contents.exchanges.first() {
        if first.request != transcript.contents.initial_request {
            reasons.push("first exchange does not match the initial request".into());
            return EnumerationStatus::Failed;
        }
    }
    for pair in transcript.contents.exchanges.windows(2) {
        if next_link(&pair[0].response.headers).as_deref() != Some(pair[1].request.url.as_str()) {
            reasons.push("response pagination link does not match the following request".into());
            return EnumerationStatus::Failed;
        }
    }
    match &transcript.contents.termination {
        AcquisitionTermination::Exhausted => {
            let terminal = transcript
                .contents
                .exchanges
                .last()
                .is_some_and(|exchange| {
                    exchange.response.status == 200
                        && next_link(&exchange.response.headers).is_none()
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
                .and_then(|exchange| next_link(&exchange.response.headers))
                .as_deref()
                != Some(next_url.as_str())
            {
                reasons.push("truncation next url does not match the last response".into());
                return EnumerationStatus::Failed;
            }
            reasons.push("collection stopped while a next page was available".into());
            EnumerationStatus::Truncated
        }
        AcquisitionTermination::PermissionDenied { diagnostic } => {
            reasons.push(format!("source access denied: {diagnostic}"));
            EnumerationStatus::PermissionDenied
        }
        AcquisitionTermination::Failed { diagnostic } => {
            reasons.push(format!("collector failed: {diagnostic}"));
            EnumerationStatus::Failed
        }
    }
}

fn contract_authority(contract: &str) -> Vec<Proposition> {
    match contract {
        GITHUB_COMMITS_CONTRACT => vec![Proposition::CommitAncestry],
        GITHUB_BRANCH_PROTECTION_CONTRACT => vec![Proposition::BranchConfiguration],
        _ => vec![],
    }
}

fn json_item_count(value: &serde_json::Value) -> u64 {
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
}
