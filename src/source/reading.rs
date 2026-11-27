//! reading a source over http.
//!
//! a [`Reader`] turns one resource into one transcript: it follows pagination,
//! repeats a request after a server error or a short rate limit, and records
//! how the reading ended. it never returns a failed reading as an error.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ureq::tls::{parse_pem, PemItem, RootCerts, TlsConfig};

use super::{Clock, Fetch};
use crate::error::{Error, Result};
use crate::transcript::{
    exchange, seal, HttpExchange, Termination, Transcript, TranscriptContents,
};

const MAX_PAGES: usize = 500;
/// how often a request is repeated after a server error.
const RETRIES: usize = 2;
/// how often one reading waits for a rate limit to lift.
const WAITS: usize = 10;
/// the variable that names a file of certificates to trust, as openssl reads it.
const CERT_FILE: &str = "SSL_CERT_FILE";

/// how one source's api is read.
pub(crate) struct Api {
    /// the only origin requests may go to, such as `https://api.github.com`.
    pub origin: &'static str,
    /// how a failed response ends a reading.
    pub classify: fn(u16, &str, &BTreeMap<String, String>) -> Termination,
    /// where the next page of a reading is, if the source says there is one.
    pub next: fn(&HttpExchange) -> Option<String>,
}

pub(crate) struct Reader<'a> {
    api: &'static Api,
    clock: &'a Clock<'a>,
    fetch: &'a mut Fetch<'a>,
    /// why the remaining readings are skipped, once the source refuses more.
    halted: Option<String>,
    /// how long to wait before repeating a request after a server error.
    pub pause: Duration,
    /// the longest rate limit worth waiting for.
    pub patience: Duration,
    pub notify: fn(&str),
}

impl<'a> Reader<'a> {
    pub fn new(api: &'static Api, clock: &'a Clock<'a>, fetch: &'a mut Fetch<'a>) -> Self {
        Self {
            api,
            clock,
            fetch,
            halted: None,
            pause: Duration::from_secs(1),
            patience: Duration::from_secs(120),
            notify: |message| eprintln!("{message}"),
        }
    }

    /// the time, as the readings are stamped.
    pub fn now(&self) -> Result<String> {
        (self.clock)()
    }

    /// read one resource about one subject, following its pages, into a
    /// sealed transcript. `parameters` say what narrows the resource within
    /// its subject, such as the branch.
    pub fn read(
        &mut self,
        resource: &str,
        subject: &str,
        parameters: &[(&str, &str)],
        url: String,
    ) -> Result<Transcript> {
        let captured_at = (self.clock)()?;
        let (exchanges, termination) = match &self.halted {
            Some(reason) => (
                Vec::new(),
                Termination::NotAttempted {
                    reason: reason.clone(),
                },
            ),
            None => self.pages(url),
        };
        if matches!(termination, Termination::RateLimited { .. }) {
            self.halted = Some("the source rate limited an earlier request".into());
        }
        seal(TranscriptContents {
            resource: resource.into(),
            subject: subject.into(),
            parameters: parameters
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            captured_at,
            exchanges,
            termination,
        })
    }

    pub fn pages(&mut self, first: String) -> (Vec<HttpExchange>, Termination) {
        let mut exchanges = Vec::new();
        let mut url = first;
        let (mut pages, mut retries, mut waits) = (0, 0, 0);
        loop {
            if !on_origin(self.api.origin, &url) {
                return (exchanges, Termination::UnsafeRedirect { location: url });
            }
            let exchange = match (self.fetch)(&url) {
                Ok(exchange) => exchange,
                Err(error) => {
                    let diagnostic = sanitize(&error.to_string());
                    return (exchanges, Termination::Failed { diagnostic });
                }
            };
            // a server error or a short rate limit is retained and the request
            // repeated. the transcript then shows what failed and what answered.
            let response = &exchange.response;
            if response.status >= 500 && retries < RETRIES {
                retries += 1;
                exchanges.push(exchange);
                std::thread::sleep(self.pause);
                continue;
            }
            if let Some(wait) = self.rate_limit_wait(&exchange).filter(|_| waits < WAITS) {
                waits += 1;
                exchanges.push(exchange);
                (self.notify)(&format!("rate limited; waiting {} seconds", wait.as_secs()));
                std::thread::sleep(wait);
                continue;
            }
            retries = 0;
            pages += 1;
            let end = self.page_end(&exchange, pages);
            exchanges.push(exchange);
            match end {
                PageEnd::Next(next) => url = next,
                PageEnd::Done(termination) => return (exchanges, termination),
            }
        }
    }

    /// how long to wait when the source rate limits and says when to return.
    fn rate_limit_wait(&self, exchange: &HttpExchange) -> Option<Duration> {
        let response = &exchange.response;
        if response.status == 200 {
            return None;
        }
        let limited = (self.api.classify)(response.status, &response.body, &response.headers);
        if !matches!(limited, Termination::RateLimited { .. }) {
            return None;
        }
        let seconds = response.headers.get("retry-after")?.parse::<u64>().ok()?;
        let wait = Duration::from_secs(seconds);
        (wait <= self.patience).then_some(wait)
    }

    fn page_end(&self, exchange: &HttpExchange, pages: usize) -> PageEnd {
        let response = &exchange.response;
        // only a plain success is an answer. some sources send a sign-in page
        // with another 2xx status.
        if response.status != 200 {
            return PageEnd::Done((self.api.classify)(
                response.status,
                &response.body,
                &response.headers,
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&response.body).is_err() {
            return PageEnd::Done(Termination::Failed {
                diagnostic: format!("HTTP {}: the response body is not JSON", response.status),
            });
        }
        match (self.api.next)(exchange) {
            None => PageEnd::Done(Termination::Exhausted),
            Some(next_url) if pages >= MAX_PAGES => {
                PageEnd::Done(Termination::Truncated { next_url })
            }
            Some(next) => PageEnd::Next(next),
        }
    }
}

enum PageEnd {
    Next(String),
    Done(Termination),
}

/// how a failed response ends a reading, by its status alone. `reset` names
/// the header that says when a rate limit lifts.
pub(crate) fn failure(
    status: u16,
    body: &str,
    headers: &BTreeMap<String, String>,
    reset: &str,
) -> Termination {
    let diagnostic = diagnostic(status, body);
    match status {
        301 | 302 | 303 | 307 | 308 => Termination::UnsafeRedirect {
            location: headers.get("location").cloned().unwrap_or_default(),
        },
        401 => Termination::Unauthenticated { diagnostic },
        403 => Termination::PermissionDenied { diagnostic },
        404 => Termination::NotFound { diagnostic },
        429 => Termination::RateLimited {
            diagnostic,
            reset_at: headers.get(reset).cloned(),
        },
        _ => Termination::Failed { diagnostic },
    }
}

/// the next page, from a `link` header.
pub(crate) fn linked_page(exchange: &HttpExchange) -> Option<String> {
    next_link(&exchange.response.headers)
}

/// the credential a command prints, if the command is there and succeeds.
///
/// # Errors
///
/// returns an error when the command prints something that is not text.
pub(crate) fn command_credential(command: &[&str]) -> Result<Option<String>> {
    let Some((program, arguments)) = command.split_first() else {
        return Ok(None);
    };
    let Ok(output) = Command::new(program).args(arguments).output() else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let token = String::from_utf8(output.stdout)
        .map_err(|_| Error::Invalid(format!("{program} returned a credential that is not text")))?;
    let token = token.trim();
    Ok((!token.is_empty()).then(|| token.to_owned()))
}

/// the credential in an environment variable, if it is set.
pub(crate) fn variable_credential(name: &str) -> Option<String> {
    let token = std::env::var(name).ok()?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// find a source's local credential: what a command prints, then an
/// environment variable.
///
/// # Errors
///
/// returns an error that says how to sign in when neither yields a credential.
pub(crate) fn credential(command: &[&str], variable: &str, sign_in: &str) -> Result<String> {
    match command_credential(command)?.or_else(|| variable_credential(variable)) {
        Some(token) => Ok(token),
        None => Err(Error::Collection(format!(
            "no credential found; run `{sign_in}` or set {variable}"
        ))),
    }
}

/// the certificate authorities a server's certificate has to chain to.
#[derive(Clone, Debug)]
pub struct Roots(RootCerts);

impl Default for Roots {
    /// the public certificate authorities divinate ships with.
    fn default() -> Self {
        Self(RootCerts::WebPki)
    }
}

impl Roots {
    /// the certificates in the file `SSL_CERT_FILE` names, in place of the
    /// ones divinate ships with. unset or empty, the variable leaves the
    /// [default](Roots::default).
    ///
    /// # Errors
    ///
    /// returns an error that names the variable and the file when the file
    /// cannot be read, is not valid pem, or holds no certificate.
    pub fn from_environment() -> Result<Self> {
        Self::from_variable(std::env::var_os(CERT_FILE).as_deref())
    }

    fn from_variable(value: Option<&OsStr>) -> Result<Self> {
        match value {
            Some(path) if !path.is_empty() => Self::from_file(Path::new(path)),
            _ => Ok(Self::default()),
        }
    }

    fn from_file(path: &Path) -> Result<Self> {
        let unusable = |problem: String| {
            Error::Collection(format!(
                "{CERT_FILE} is {}, which {problem}",
                path.display()
            ))
        };
        let pem =
            std::fs::read(path).map_err(|error| unusable(format!("cannot be read: {error}")))?;
        let certificates = parse_pem(&pem)
            .filter_map(|item| match item {
                Ok(PemItem::Certificate(certificate)) => Some(Ok(certificate)),
                Ok(_) => None,
                Err(_) => Some(Err(unusable("is not valid pem".into()))),
            })
            .collect::<Result<Vec<_>>>()?;
        if certificates.is_empty() {
            return Err(unusable("holds no pem certificate".into()));
        }
        Ok(Self(certificates.into()))
    }
}

/// a fetch function that reads one origin.
///
/// `authorization` is the value of the header that carries the credential, or
/// `None` to read without one. the server's certificate has to chain to one of
/// `roots`. redirects are not followed, only allow-listed response headers are
/// kept, and a response that repeats one of `secrets` is refused instead of
/// retained.
pub(crate) fn client(
    origin: &'static str,
    authorization: Option<String>,
    secrets: Vec<String>,
    request_headers: &'static [(&'static str, &'static str)],
    retained_headers: &'static [&'static str],
    roots: &Roots,
) -> Box<Fetch<'static>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .tls_config(TlsConfig::builder().root_certs(roots.0.clone()).build())
        .build()
        .into();
    Box::new(move |url| {
        if !on_origin(origin, url) {
            return Err(Error::Invalid(format!("refused a URL outside {origin}")));
        }
        let mut request = agent.get(url).header(
            "user-agent",
            concat!("divinate/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(authorization) = &authorization {
            request = request.header("authorization", authorization);
        }
        for (name, value) in request_headers {
            request = request.header(*name, *value);
        }
        let mut response = request.call().map_err(|error| {
            Error::Collection(format!(
                "no response from {origin}: {}",
                sanitize(&error.to_string())
            ))
        })?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                let name = name.as_str().to_ascii_lowercase();
                retained_headers
                    .contains(&name.as_str())
                    .then(|| value.to_str().ok().map(|value| (name, value.to_owned())))?
            })
            .collect::<BTreeMap<_, _>>();
        let body = response.body_mut().read_to_string().map_err(|_| {
            Error::Collection(format!("a response body from {origin} could not be read"))
        })?;
        let repeated = |secret: &String| {
            body.contains(secret) || headers.values().any(|value| value.contains(secret))
        };
        if secrets.iter().any(repeated) {
            return Err(Error::Collection(format!(
                "a response from {origin} repeated the credential and was not retained"
            )));
        }
        Ok(exchange(url, status, headers, body))
    })
}

pub(crate) fn on_origin(origin: &str, url: &str) -> bool {
    url.strip_prefix(origin)
        .is_some_and(|path| path.starts_with('/'))
        && !url.contains('@')
        && !url.contains('#')
}

/// `HTTP <status>: <message>`, with the message the source put in its error body.
pub(crate) fn diagnostic(status: u16, body: &str) -> String {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            ["message", "error_description", "error"]
                .iter()
                .find_map(|field| value.get(field).and_then(serde_json::Value::as_str))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "request failed".into());
    sanitize(&format!("HTTP {status}: {message}"))
}

pub(crate) fn sanitize(value: &str) -> String {
    value.trim().chars().take(500).collect()
}

pub(crate) fn next_link(headers: &BTreeMap<String, String>) -> Option<String> {
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

pub(crate) fn percent_encode(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://api.example.org";

    fn classify(status: u16, body: &str, headers: &BTreeMap<String, String>) -> Termination {
        failure(status, body, headers, "ratelimit-reset")
    }

    static API: Api = Api {
        origin: ORIGIN,
        classify,
        next: linked_page,
    };

    type Answer = (u16, &'static [(&'static str, &'static str)], &'static str);

    /// read one url, answering from the end of `answers`.
    fn read(answers: &mut Vec<Answer>, patience: u64) -> (Vec<u16>, Termination) {
        let clock = || Ok("2026-11-24T10:00:00Z".to_owned());
        let mut fetch = |url: &str| {
            let (status, headers, body) = answers.pop().unwrap();
            let headers = headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            Ok(exchange(url, status, headers, body.into()))
        };
        let mut reader = Reader::new(&API, &clock, &mut fetch);
        reader.pause = Duration::ZERO;
        reader.patience = Duration::from_secs(patience);
        reader.notify = |_| {};
        let (exchanges, termination) = reader.pages(format!("{ORIGIN}/things"));
        let statuses = exchanges
            .iter()
            .map(|exchange| exchange.response.status)
            .collect();
        (statuses, termination)
    }

    #[test]
    fn a_server_error_is_retained_and_the_request_repeated() {
        let mut answers: Vec<Answer> = vec![(200, &[], "[]"), (500, &[], ""), (500, &[], "")];
        assert_eq!(
            read(&mut answers, 0),
            (vec![500, 500, 200], Termination::Exhausted)
        );
        let mut answers: Vec<Answer> = vec![(500, &[], ""), (500, &[], ""), (500, &[], "")];
        let (statuses, termination) = read(&mut answers, 0);
        assert_eq!(statuses, [500, 500, 500]);
        assert!(matches!(termination, Termination::Failed { .. }));
    }

    #[test]
    fn a_short_rate_limit_is_waited_out_and_a_long_one_ends_the_reading() {
        let limited: Answer = (429, &[("retry-after", "0")], "{}");
        let mut answers = vec![(200, &[][..], "[]"), limited];
        assert_eq!(
            read(&mut answers, 0),
            (vec![429, 200], Termination::Exhausted)
        );

        let mut answers: Vec<Answer> = vec![(429, &[("retry-after", "3600")], "{}")];
        let (statuses, termination) = read(&mut answers, 120);
        assert_eq!(statuses, [429]);
        assert!(matches!(termination, Termination::RateLimited { .. }));
    }

    #[test]
    fn pages_are_followed_only_on_the_origin() {
        let next: Answer = (
            200,
            &[(
                "link",
                "<https://api.example.org/things?page=2>; rel=\"next\"",
            )],
            "[1]",
        );
        let mut answers = vec![(200, &[][..], "[2]"), next];
        assert_eq!(
            read(&mut answers, 0),
            (vec![200, 200], Termination::Exhausted)
        );

        let elsewhere: Answer = (
            200,
            &[(
                "link",
                "<https://elsewhere.example.org/things?page=2>; rel=\"next\"",
            )],
            "[1]",
        );
        let mut answers = vec![elsewhere];
        let (_, termination) = read(&mut answers, 0);
        assert!(matches!(termination, Termination::UnsafeRedirect { .. }));
    }

    #[test]
    fn urls_outside_the_origin_are_refused() {
        assert!(on_origin(ORIGIN, "https://api.example.org/things"));
        assert!(!on_origin(
            ORIGIN,
            "https://api.example.org.evil.test/things"
        ));
        assert!(!on_origin(ORIGIN, "https://user@api.example.org/things"));
    }

    #[test]
    fn a_branch_name_is_encoded_as_one_path_segment() {
        assert_eq!(percent_encode("release/1.x"), "release%2F1.x");
    }

    #[test]
    fn next_link_is_extracted() {
        let headers = BTreeMap::from([(
            "link".into(),
            "<https://api.example.org/things?page=2>; rel=\"next\", <https://api.example.org/things?page=4>; rel=\"last\"".into(),
        )]);
        assert_eq!(
            next_link(&headers).as_deref(),
            Some("https://api.example.org/things?page=2")
        );
    }

    /// a file in `tests/tls`: a test certificate authority, and a certificate
    /// it signed for 127.0.0.1 with its key. the readme there says how they
    /// were made.
    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/tls")
            .join(name)
    }

    #[test]
    fn unset_or_empty_keeps_the_bundled_roots() {
        for value in [None, Some(OsStr::new(""))] {
            let roots = Roots::from_variable(value).unwrap();
            assert!(matches!(roots.0, RootCerts::WebPki));
        }
    }

    #[test]
    fn the_file_replaces_the_bundled_roots_with_every_certificate_in_it() {
        let read = |name| std::fs::read_to_string(fixture(name)).unwrap();
        let bundle = format!(
            "test ca\n{}\nserver\n{}{}",
            read("ca.pem"),
            read("server.pem"),
            read("server.key")
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bundle.pem");
        std::fs::write(&path, bundle).unwrap();
        let roots = Roots::from_variable(Some(path.as_os_str())).unwrap();
        assert!(matches!(&roots.0, RootCerts::Specific(certificates) if certificates.len() == 2));
    }

    #[test]
    fn a_file_that_cannot_be_used_is_an_error_naming_the_variable_and_the_file() {
        let ca = std::fs::read_to_string(fixture("ca.pem")).unwrap();
        let cut = ca.lines().take(3).collect::<Vec<_>>().join("\n");
        let garbled = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let key = std::fs::read_to_string(fixture("server.key")).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let cases = [
            ("missing.pem", None, "cannot be read: "),
            ("cut.pem", Some(cut.as_str()), "is not valid pem"),
            ("garbled.pem", Some(garbled), "is not valid pem"),
            ("empty.pem", Some(""), "holds no pem certificate"),
            ("key.pem", Some(key.as_str()), "holds no pem certificate"),
        ];
        for (name, contents, problem) in cases {
            let path = directory.path().join(name);
            if let Some(contents) = contents {
                std::fs::write(&path, contents).unwrap();
            }
            let error = Roots::from_variable(Some(path.as_os_str()))
                .unwrap_err()
                .to_string();
            let expected = format!("SSL_CERT_FILE is {}, which {problem}", path.display());
            assert!(error.contains(&expected), "{error}");
        }
    }

    /// serve https on 127.0.0.1 with the test certificate, and answer the
    /// first request on each of `connections` connections with an empty list.
    fn serve(connections: usize) -> (&'static str, std::thread::JoinHandle<()>) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{Read, Write};

        let certificates = CertificateDer::pem_file_iter(fixture("server.pem"))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certificates, key)
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(connections) {
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::Stream::new(&mut connection, &mut stream);
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                // a client that refuses the certificate ends the handshake,
                // and with it this connection.
                while !request.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut buffer) {
                        Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
                        _ => break,
                    }
                }
                if request.ends_with(b"\r\n\r\n") {
                    tls.write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n[]",
                    )
                    .unwrap();
                    tls.flush().unwrap();
                }
            }
        });
        (Box::leak(origin.into_boxed_str()), server)
    }

    #[test]
    fn a_server_signed_by_another_authority_is_read_only_with_it_in_the_file() {
        let (origin, server) = serve(2);
        let url = format!("{origin}/things");
        let fetch = |roots: &Roots| client(origin, None, Vec::new(), &[], &[], roots)(&url);

        let unset = Roots::from_variable(None).unwrap();
        let refused = fetch(&unset).unwrap_err().to_string();
        assert!(refused.contains("UnknownIssuer"), "{refused}");

        let set = Roots::from_variable(Some(fixture("ca.pem").as_os_str())).unwrap();
        let exchange = fetch(&set).unwrap();
        assert_eq!(exchange.response.status, 200);
        assert_eq!(exchange.response.body, "[]");
        server.join().unwrap();
    }
}
