//! retained source responses.
//!
//! a [`Transcript`] is one reading of one resource: the requests made, the
//! exact response bodies, and how the reading ended. request headers are never
//! retained, so a transcript cannot hold the credential that produced it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::{content_id, hex_digest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one reading of one resource, addressed by the digest of its contents.
pub struct Transcript {
    pub id: String,
    pub contents: TranscriptContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// what was asked, what came back, and how the reading ended.
pub struct TranscriptContents {
    /// the versioned name of the resource, such as `github/branch-rules/v1`.
    pub resource: String,
    /// what the resource is about, such as `github:owner/repository`.
    pub subject: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    /// what narrows the resource within its subject, such as the branch.
    pub parameters: BTreeMap<String, String>,
    pub captured_at: String,
    pub exchanges: Vec<HttpExchange>,
    pub termination: Termination,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the method and url of one request, with no headers retained.
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// what was sent with the request, where a source is asked with a body.
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// one request and the response it produced.
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// a response with its exact body. retained headers are an allow-list.
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// digest of the retained body, recomputed on every verification.
    pub body_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// how a reading ended. everything but `exhausted` is a gap.
pub enum Termination {
    /// the source said there was nothing further to read.
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
    /// the reading was skipped, and no request was made.
    NotAttempted {
        reason: String,
    },
}

impl Termination {
    /// why the reading is incomplete, or `None` when it is complete.
    #[must_use]
    pub fn gap(&self) -> Option<String> {
        match self {
            Self::Exhausted => None,
            Self::Truncated { next_url } => {
                Some(format!("reading stopped before the last page ({next_url})"))
            }
            Self::Unauthenticated { diagnostic } => {
                Some(format!("not authenticated: {diagnostic}"))
            }
            Self::PermissionDenied { diagnostic } => {
                Some(format!("permission denied: {diagnostic}"))
            }
            Self::NotFound { diagnostic } => Some(format!(
                "not found, or not visible to this credential: {diagnostic}"
            )),
            Self::RateLimited { diagnostic, .. } => Some(format!("rate limited: {diagnostic}")),
            Self::UnsafeRedirect { location } => Some(format!("refused a redirect to {location}")),
            Self::Failed { diagnostic } => Some(format!("failed: {diagnostic}")),
            Self::NotAttempted { reason } => Some(format!("not attempted: {reason}")),
        }
    }
}

impl Transcript {
    /// the bodies of the successful responses, in the order they were read.
    pub fn bodies(&self) -> impl Iterator<Item = &str> {
        self.contents
            .exchanges
            .iter()
            .filter(|exchange| (200..300).contains(&exchange.response.status))
            .map(|exchange| exchange.response.body.as_str())
    }

    /// one parameter of the reading, if it was recorded.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.contents.parameters.get(name).map(String::as_str)
    }
}

/// build one exchange from a response, recording the digest of its body.
#[must_use]
pub fn exchange(
    url: &str,
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
) -> HttpExchange {
    HttpExchange {
        request: HttpRequest {
            method: "GET".into(),
            url: url.into(),
            body: None,
        },
        response: HttpResponse {
            status,
            headers,
            body_sha256: hex_digest(body.as_bytes()),
            body,
        },
    }
}

/// create a content-addressed transcript.
///
/// # Errors
///
/// returns an error when the contents cannot be serialized.
pub fn seal(contents: TranscriptContents) -> Result<Transcript> {
    Ok(Transcript {
        id: content_id("acq", &contents)?,
        contents,
    })
}

/// check a transcript's id and every retained body against their digests.
///
/// # Errors
///
/// returns an error naming the first mismatch.
pub fn verify(transcript: &Transcript) -> Result<()> {
    let expected = content_id("acq", &transcript.contents)?;
    if expected != transcript.id {
        return Err(Error::Verification(format!(
            "transcript {} does not match its contents ({expected})",
            transcript.id
        )));
    }
    for exchange in &transcript.contents.exchanges {
        if hex_digest(exchange.response.body.as_bytes()) != exchange.response.body_sha256 {
            return Err(Error::Verification(format!(
                "transcript {}: the body of {} does not match its digest",
                transcript.id, exchange.request.url
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Transcript {
        seal(TranscriptContents {
            resource: "github/branch-rules/v1".into(),
            subject: "github:example/service".into(),
            parameters: BTreeMap::from([("branch".into(), "main".into())]),
            captured_at: "2026-11-24T10:00:00Z".into(),
            exchanges: vec![exchange(
                "https://api.github.com/repos/example/service/rules/branches/main",
                200,
                BTreeMap::new(),
                "[]".into(),
            )],
            termination: Termination::Exhausted,
        })
        .unwrap()
    }

    #[test]
    fn a_sealed_transcript_verifies() {
        verify(&sample()).unwrap();
    }

    #[test]
    fn a_changed_body_is_rejected() {
        let mut transcript = sample();
        transcript.contents.exchanges[0].response.body = "[{}]".into();
        assert!(verify(&transcript).is_err());
    }

    #[test]
    fn only_an_exhausted_reading_is_complete() {
        assert_eq!(Termination::Exhausted.gap(), None);
        let denied = Termination::PermissionDenied {
            diagnostic: "HTTP 403: Resource not accessible".into(),
        };
        assert!(denied.gap().unwrap().starts_with("permission denied"));
    }
}
