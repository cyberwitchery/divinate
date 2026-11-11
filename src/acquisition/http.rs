use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::transcript::{HttpExchange, HttpRequest, HttpResponse};
use crate::error::{Error, Result};
use crate::hex_digest;

pub(super) fn percent_encode(value: &str) -> String {
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

pub(super) fn build_exchange(
    url: &str,
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
    provider: &str,
) -> Result<HttpExchange> {
    let item_count = response_item_count(status, &body).map_err(|error| {
        Error::Invalid(format!("{provider} response body is not JSON: {error}"))
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
            item_count,
            body,
        },
    })
}

/// a success body must be JSON; an error body that is not JSON counts no items.
pub(super) fn response_item_count(status: u16, body: &str) -> serde_json::Result<u64> {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(value) => Ok(json_item_count(&value)),
        Err(_) if !(200..300).contains(&status) => Ok(0),
        Err(error) => Err(error),
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

pub(super) fn next_link(headers: &BTreeMap<String, String>) -> Option<String> {
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

pub(super) fn sanitize_diagnostic(value: &str) -> String {
    value.trim().chars().take(500).collect()
}

pub(super) fn format_time(value: OffsetDateTime) -> Result<String> {
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
}
