//! the osv pack says what its transcripts mean. nothing here asks the network.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::Path;

use divinate::pack::{source, Configured};
use divinate::process::{self, Outcome};
use divinate::record;
use divinate::transcript::{
    seal, HttpExchange, HttpRequest, HttpResponse, Termination, Transcript, TranscriptContents,
};

const SUBJECT: &str = "osv:example/service";

fn read(resource: &str, parameters: &[(&str, &str)], body: &str, status: u16) -> Transcript {
    seal(TranscriptContents {
        resource: resource.into(),
        subject: SUBJECT.into(),
        parameters: parameters
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        captured_at: "2026-03-27T00:00:00Z".into(),
        exchanges: vec![HttpExchange {
            request: HttpRequest {
                method: "GET".into(),
                url: "https://example.test/".into(),
                body: None,
            },
            response: HttpResponse {
                status,
                headers: BTreeMap::new(),
                body_sha256: divinate::hex_digest(body.as_bytes()),
                body: body.into(),
            },
        }],
        termination: if status == 200 {
            Termination::Exhausted
        } else {
            Termination::Failed {
                diagnostic: format!("HTTP {status}"),
            }
        },
    })
    .unwrap()
}

/// three releases: the first has a vulnerable component, the second no
/// longer has it, and the third has no bill of materials attached.
fn transcripts(details: u16) -> Vec<Transcript> {
    read_with(details, r#""database_specific":{"severity":"HIGH"}"#)
}

/// the same, with what the record of the vulnerability says of its severity.
fn read_with(details: u16, severity: &str) -> Vec<Transcript> {
    let release = |tag: &str, at: &str, asset: &str| {
        format!(
            r#"{{"tag_name":"{tag}","name":"{tag}","draft":false,"prerelease":false,"published_at":"{at}","assets":[{asset}]}}"#
        )
    };
    let sbom = r#"{"id":1,"name":"service.cdx.json","size":10,"digest":null}"#;
    let listing = format!(
        "[{},{},{}]",
        release("v3", "2026-03-20T10:00:00Z", ""),
        release("v2", "2026-03-01T10:00:00Z", sbom),
        release("v1", "2026-02-01T10:00:00Z", sbom),
    );
    let period = [
        ("from", "2026-01-01T00:00:00Z"),
        ("until", "2026-03-27T00:00:00Z"),
    ];
    let bom = |version: &str| {
        format!(
            r#"{{"components":[{{"purl":"pkg:cargo/parser@{version}?download=x"}},{{"name":"unversioned"}}]}}"#
        )
    };
    let of = |tag: &'static str| [("release", tag), ("asset", "service.cdx.json")];
    let asked = |tag: &'static str| {
        [
            ("release", tag),
            ("asset", "service.cdx.json"),
            ("part", "0"),
        ]
    };
    vec![
        read("osv/github-releases/v1", &period, &listing, 200),
        read("osv/release-sbom/v1", &of("v1"), &bom("1.0.0"), 200),
        read(
            "osv/query/v1",
            &asked("v1"),
            r#"{"results":[{"vulns":[{"id":"GHSA-aaaa","modified":"2026-01-16T00:00:00Z"}]}]}"#,
            200,
        ),
        read("osv/release-sbom/v1", &of("v2"), &bom("1.0.1"), 200),
        read("osv/query/v1", &asked("v2"), r#"{"results":[{}]}"#, 200),
        read(
            "osv/vulnerability/v1",
            &[("id", "GHSA-aaaa")],
            &format!(
                r#"{{"id":"GHSA-aaaa","summary":"parser reads past the end","published":"2026-01-15T00:00:00Z","aliases":["CVE-2026-0001"],{severity}}}"#
            ),
            details,
        ),
    ]
}

fn packs() -> Option<Configured> {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .ok()?;
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("packs/divinate.yaml");
    Some(Configured::load(Some(&config)).unwrap())
}

#[test]
fn a_vulnerability_is_a_finding_from_the_release_that_has_it_to_the_one_that_does_not() {
    let Some(packs) = packs() else {
        return;
    };
    let transcripts = transcripts(200);
    let derived = source::derive(&packs, "osv", &transcripts).unwrap();
    // the same transcripts say the same again.
    assert_eq!(
        derived,
        source::derive(&packs, "osv", &transcripts).unwrap()
    );
    let finding = derived.named("osv:example/service GHSA-aaaa").unwrap();
    let state = derived
        .statement(&finding.uid, "finding")
        .unwrap()
        .reading
        .value()
        .unwrap();
    assert_eq!(state["title"], "parser reads past the end");
    assert_eq!(state["labels"], serde_json::json!(["high"]));
    // the report is older than the release, so it is known of the release
    // from the day the release was published.
    assert_eq!(state["opened_at"], "2026-02-01T10:00:00Z");
    assert_eq!(state["closed_at"], "2026-03-01T10:00:00Z");
    assert_eq!(state["releases"], serde_json::json!(["v1"]));
    let scope = derived.named(SUBJECT).unwrap();
    let findings = derived.statement(&scope.uid, "findings").unwrap();
    assert!(findings.note.as_ref().unwrap().starts_with(
        "1 of 3 releases have no bill of materials attached, and nothing is known of them: v3"
    ));

    // the record a pack derived is checked like any other.
    let collection = record::seal_derived(
        SUBJECT,
        "2026-03-27T00:00:00Z".into(),
        "2026-03-27T00:00:00Z".into(),
        &transcripts,
        derived,
        None,
    )
    .unwrap();
    let definition = "process: known vulnerabilities\nitems:\n  kind: finding\n  label: high\nsteps:\n  - name: fixed\n    event: closed\n    within: 30d\n";
    let definition = process::parse(definition, Path::new("inline")).unwrap();
    let report = process::check(&definition, &collection, &[]).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].outcomes[0], Outcome::Kept);
    let releases = "process: releases\nitems:\n  kind: release\nsteps:\n  - name: sbom attached\n    asset: '*.cdx.json'\n";
    let report = process::check(
        &process::parse(releases, Path::new("inline")).unwrap(),
        &collection,
        &[],
    )
    .unwrap();
    let found = report
        .rows
        .iter()
        .map(|row| row.outcomes[0].label())
        .collect::<Vec<_>>();
    assert_eq!(found, ["kept", "kept", "broken"]);
}

#[test]
fn nothing_is_said_of_the_findings_when_a_reading_is_missing() {
    let Some(packs) = packs() else {
        return;
    };
    let derived = source::derive(&packs, "osv", &transcripts(500)).unwrap();
    let scope = derived.named(SUBJECT).unwrap();
    let findings = derived.statement(&scope.uid, "findings").unwrap();
    assert_eq!(findings.reading.gap_reason(), Some("failed: HTTP 500"));
    // the releases were read, and stand.
    assert!(derived
        .statement(&scope.uid, "releases")
        .unwrap()
        .reading
        .value()
        .is_some());
}

#[test]
fn the_severity_is_the_word_given_a_cvss_band_or_the_kind_of_notice() {
    let Some(packs) = packs() else {
        return;
    };
    let label = |severity: &str| {
        let derived = source::derive(&packs, "osv", &read_with(200, severity)).unwrap();
        let finding = derived.named("osv:example/service GHSA-aaaa").unwrap();
        let state = derived.statement(&finding.uid, "finding").unwrap();
        state.reading.value().unwrap()["labels"].clone()
    };
    assert_eq!(
        label(r#""database_specific":{"severity":"MODERATE"}"#),
        serde_json::json!(["medium"])
    );
    // 9.8 and 5.4, as the cvss calculator scores these vectors.
    assert_eq!(
        label(
            r#""severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]"#
        ),
        serde_json::json!(["critical"])
    );
    assert_eq!(
        label(
            r#""affected":[{"database_specific":{"cvss":"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"}}]"#
        ),
        serde_json::json!(["medium"])
    );
    assert_eq!(
        label(r#""affected":[{"database_specific":{"cvss":null,"informational":"unmaintained"}}]"#),
        serde_json::json!(["unmaintained"])
    );
    assert_eq!(label(r#""severity":null"#), serde_json::json!([]));
}
