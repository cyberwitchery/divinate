//! http and api acquisition transcripts.
//!
//! [`AcquisitionTranscript`] stores request urls, exact response bodies,
//! pagination metadata, and termination. [`assess`] verifies the transcript and
//! applies its versioned source contract. [`ContractRegistry`] can withdraw
//! current authority without changing retained evidence.
//!
//! authorization headers and cookies are invalid transcript data.

mod assessment;
mod azure_devops;
mod github;
mod http;
#[cfg(test)]
mod test_support;
mod transcript;

pub use assessment::{
    assess, exchanges_after_github_lookup, AcquisitionAssessment, ContractInvalidation,
    ContractRegistry, ContractStatus, EnumerationStatus, IntegrityStatus,
};
pub use azure_devops::{
    capture_azure_devops_remote, AzureDevopsRemoteCapture, AzureDevopsRemoteResource,
};
pub use github::{capture_github_remote, GithubRemoteCapture, GithubRemoteResource};
pub use transcript::{
    seal_transcript, AcquisitionTermination, AcquisitionTranscript, HttpExchange, HttpRequest,
    HttpResponse, TranscriptContents, AZURE_DEVOPS_BRANCH_POLICY_CONTRACT,
    AZURE_DEVOPS_BUILD_VALIDATION_HISTORY_CONTRACT, AZURE_DEVOPS_PULL_REQUEST_REVIEWS_CONTRACT,
    AZURE_DEVOPS_REPOSITORY_MUTATIONS_CONTRACT, GITHUB_BRANCH_PROTECTION_CONTRACT,
    GITHUB_BUILD_VALIDATION_HISTORY_CONTRACT, GITHUB_CHECK_RUNS_CONTRACT, GITHUB_COMMITS_CONTRACT,
    GITHUB_COMMIT_STATUSES_CONTRACT, GITHUB_PULL_REQUEST_REVIEWS_CONTRACT,
    GITHUB_REPOSITORY_MUTATIONS_CONTRACT, TRANSCRIPT_SCHEMA_VERSION,
};
