use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::azure_devops::{AzureDevopsRemoteCapture, AzureDevopsRemoteResource};
use super::github::{GithubRemoteCapture, GithubRemoteResource};
use super::http::build_exchange;
use super::transcript::HttpExchange;
use crate::model::{Subject, TimeRange};

pub(super) const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

pub(super) fn remote(resource: GithubRemoteResource) -> GithubRemoteCapture {
    GithubRemoteCapture {
        repository: "cyberwitchery/divinate".into(),
        branch: "main".into(),
        revision: REVISION.into(),
        subject: Subject {
            kind: "repository".into(),
            id: "github:cyberwitchery/divinate".into(),
            qualifiers: BTreeMap::from([
                ("branch".into(), serde_json::json!("main")),
                ("revision".into(), serde_json::json!(REVISION)),
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

pub(super) fn azure_remote() -> AzureDevopsRemoteCapture {
    AzureDevopsRemoteCapture {
        organization: "example-org".into(),
        project: "example-project".into(),
        repository: "example-repository".into(),
        branch: "develop".into(),
        resource: AzureDevopsRemoteResource::BranchPolicy,
        subject: Subject {
            kind: "repository".into(),
            id: "azure-devops:example-org/example-project/example-repository".into(),
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

pub(super) fn exchange(
    url: &str,
    status: u16,
    body: &str,
    headers: BTreeMap<String, String>,
) -> HttpExchange {
    build_exchange(url, status, headers, body.into(), "test").unwrap()
}

pub(super) fn github_lookup(url: &str) -> Option<HttpExchange> {
    (url == "https://api.github.com/repos/cyberwitchery/divinate").then(|| {
        exchange(
            url,
            200,
            r#"{"id":123,"full_name":"cyberwitchery/divinate"}"#,
            BTreeMap::new(),
        )
    })
}
