//! reading a scope from canned responses, for every source the same way.

use std::collections::BTreeMap;

use divinate::record::{self, Collection};
use divinate::source::{self, Period};
use divinate::transcript::{exchange, Transcript};

/// what a canned source answers: a status, headers, and a body.
pub type Answer = (u16, BTreeMap<String, String>, String);

/// an answer with no headers.
// each test binary compiles this module, and not every one answers without headers.
#[allow(dead_code)]
pub fn answer(found: Option<&(u16, String)>, url: &str) -> Answer {
    let (status, body) = found.unwrap_or_else(|| panic!("unexpected request: {url}"));
    (*status, BTreeMap::new(), body.clone())
}

/// read `scope` for the period from `from` to `at`, at the time `at`, and
/// seal one collection.
pub fn collect(
    scope: &str,
    from: &str,
    at: &str,
    answer: impl Fn(&str) -> Answer,
) -> (Collection, Vec<Transcript>) {
    collect_with(scope, from, at, true, answer)
}

/// the same, with or without the files each change touches.
// each test binary compiles this module, and not every one leaves the files out.
#[allow(dead_code)]
pub fn collect_with(
    scope: &str,
    from: &str,
    at: &str,
    files: bool,
    answer: impl Fn(&str) -> Answer,
) -> (Collection, Vec<Transcript>) {
    let (source, path) = source::for_scope(scope).unwrap();
    let period = Period {
        from: from.into(),
        until: at.into(),
        files,
    };
    let transcripts = source
        .capture(path, &period, &|| Ok(at.to_owned()), &mut |url: &str| {
            let (status, headers, body) = answer(url);
            Ok(exchange(url, status, headers, body))
        })
        .unwrap();
    let collection = record::seal(scope, at.into(), at.into(), &transcripts).unwrap();
    (collection, transcripts)
}
