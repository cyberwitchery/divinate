use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
/// branch activity and pull-request association for one github branch interval.
pub const GITHUB_REPOSITORY_MUTATIONS_CONTRACT: &str = "github-repository-mutations/v1";
/// merged pull requests and their reviews for one github branch interval.
pub const GITHUB_PULL_REQUEST_REVIEWS_CONTRACT: &str = "github-pull-request-reviews/v1";
/// check runs and commit statuses for integrations in one github branch interval.
pub const GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT: &str = "github-build-validation-history/v1";
/// current azure devops policies that apply to one repository branch.
pub const AZURE_DEVOPS_BRANCH_POLICY_CONTRACT: &str = "azure-devops-branch-policy/v1";
/// branch pushes and completed pull-request association for one azure branch interval.
pub const AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT: &str = "azure-devops-repository-mutations/v1";
/// completed pull requests and vote history for one azure branch interval.
pub const AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT: &str = "azure-devops-pull-request-reviews/v1";
/// policy evaluations for integrations in one azure branch interval.
pub const AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT: &str =
    "azure-devops-build-validation-history/v1";

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
