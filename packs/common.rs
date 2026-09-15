use std::io::{self, Read};

use serde_json::{json, Value};

pub fn request() -> Value {
    let mut bytes = Vec::new();
    if io::stdin().read_to_end(&mut bytes).is_err() {
        fail("cannot read pack request");
    }
    let value: Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| fail("request is not valid json"));
    if value.get("protocol_version").and_then(Value::as_u64) != Some(1) {
        fail("unsupported protocol version");
    }
    value
}

pub fn input(request: &Value) -> &Value {
    request.get("input").unwrap_or(&Value::Null)
}

pub fn operation(request: &Value) -> &str {
    request
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("request has no operation"))
}

pub fn reply(result: Value) -> ! {
    let mut response = serde_json::Map::new();
    response.insert("ok".into(), Value::Bool(true));
    response.insert("result".into(), result);
    println!("{}", Value::Object(response));
    std::process::exit(0)
}

pub fn fail(message: &str) -> ! {
    println!("{}", json!({"ok": false, "error": message}));
    std::process::exit(0)
}

pub fn context_subject(context: &Value) -> Value {
    json!({
        "kind": "repository",
        "id": required_str(context, "repository"),
        "repository": required_str(context, "repository"),
        "branch": required_str(context, "branch"),
        "revision": required_str(context, "revision"),
    })
}

pub fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail(&format!("request is missing {field}")))
}

pub fn normalized(claim_key: &str, data: Value, evidence_class: &str, kind: &str) -> Value {
    let mut result = json!({
        "claim_key": claim_key,
        "evidence_class": evidence_class,
        "kind": kind,
        "severity": null,
        "status": null,
    });
    result
        .as_object_mut()
        .expect("normalized result is an object")
        .insert("data".into(), data);
    result
}

pub fn source_payload(input: &Value) -> Value {
    let content = input
        .get("source")
        .and_then(|source| source.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("normalize request has no source content"));
    serde_json::from_str(content).unwrap_or_else(|_| fail("source is not valid json"))
}

pub fn source_subject(input: &Value) -> &Value {
    input.get("subject").unwrap_or(&Value::Null)
}

pub fn adapter(input: &Value) -> &str {
    input
        .get("adapter")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("normalize request has no adapter"))
}

pub fn transcript(payload: &Value) -> divinate::acquisition::AcquisitionTranscript {
    serde_json::from_value(payload.clone())
        .unwrap_or_else(|_| fail("historical acquisition transcript is invalid"))
}

pub fn json_body(exchange: &divinate::acquisition::HttpExchange) -> Value {
    serde_json::from_str(&exchange.response.body)
        .unwrap_or_else(|_| fail("acquisition transcript contains invalid response json"))
}

#[cfg(test)]
pub fn historical_payload(repository: &str, branch: &str, exchanges: Vec<(&str, Value)>) -> Value {
    let exchanges = exchanges.into_iter().map(|(url, body)| {
        let body = body.to_string();
        json!({
            "request":{"method":"GET","url":url},
            "response":{"status":200,"headers":{},"body":body,"body_sha256":divinate::hex_digest(body.as_bytes()),"item_count":0}
        })
    }).collect::<Vec<_>>();
    json!({
        "id":"test-transcript","schema_version":"0.1.0",
        "contents":{
            "collector_contract":"test/v1","collector_version":"1",
            "subject":{"kind":"repository","id":repository,"branch":branch},
            "proposition":"pull_request_reviews",
            "requested_scope":{"from":"2026-09-11T00:00:00Z","until":"2026-09-12T00:00:00Z"},
            "captured_at":"2026-09-12T00:00:00Z",
            "initial_request":exchanges[0]["request"],"exchanges":exchanges,
            "termination":{"kind":"exhausted"}
        }
    })
}
