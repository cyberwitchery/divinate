//! packs: checks and process definitions that live outside this crate.
//!
//! a pack is a program that `divinate.yaml` declares. it is given one json
//! request on its standard input and answers with one json document on its
//! standard output. a pack can judge the items of a process check, ship
//! process definitions, and be a source: it reads a system itself and hands
//! back the responses, which are kept as transcripts like any other.
//!
//! a pack is run with an almost empty environment. it gets the variables its
//! configuration names, and nothing else of the environment of divinate.

pub mod source;

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{Error, Result};

/// the version of the requests and answers in this module.
pub const PROTOCOL: u64 = 1;

/// what runs a pack: the executables on this machine, or a stand-in.
pub trait Packs {
    /// send one request to a pack and return its answer.
    ///
    /// # Errors
    ///
    /// returns an error when the pack cannot be found or run, or does not
    /// answer with json.
    fn call(&self, pack: &str, request: &Value) -> Result<Value>;

    /// the values a pack was handed that must not end up in the record,
    /// such as a token it was given to read its source.
    fn secrets(&self, _pack: &str) -> Vec<String> {
        Vec::new()
    }
}

/// no packs at all. a definition that uses one cannot be checked.
pub struct NoPacks;

impl Packs for NoPacks {
    fn call(&self, pack: &str, _: &Value) -> Result<Value> {
        Err(Error::Pack(format!(
            "the pack {pack:?} is needed, and no packs are available here"
        )))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
/// the configuration file, `divinate.yaml`.
pub struct Config {
    #[serde(default)]
    /// the packs that can be used, by name.
    pub packs: BTreeMap<String, Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
/// how one pack is run.
pub struct Entry {
    /// the program. a path with a `/` in it is taken from the directory of
    /// the configuration file, and a bare name is looked up on `PATH`.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    /// the directory the pack runs in. the directory of the configuration
    /// file when not given.
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    /// the names of the environment variables the pack is given from the
    /// environment of divinate, such as a token it needs to read its source.
    pub inherit: Vec<String>,
    #[serde(default)]
    /// environment variables set for the pack, as written here.
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_timeout")]
    /// how long one request to the pack may take.
    pub timeout_seconds: u64,
    #[serde(default)]
    /// what the pack is told with every request, as the pack defines it.
    pub setup: Option<Value>,
}

fn default_timeout() -> u64 {
    300
}

/// the packs a configuration file declares.
pub struct Configured {
    config: Config,
    /// the directory of the configuration file.
    home: PathBuf,
    /// where the configuration was looked for, for a message.
    origin: PathBuf,
}

impl Configured {
    /// read the configuration: the file given, or `divinate.yaml` in the
    /// current directory. without a file there are no packs.
    ///
    /// # Errors
    ///
    /// returns an error when a file was given and cannot be read, or the
    /// file is not a configuration.
    pub fn load(given: Option<&Path>) -> Result<Self> {
        let origin = given.map_or_else(|| PathBuf::from("divinate.yaml"), Path::to_path_buf);
        let home = origin
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let text = match std::fs::read_to_string(&origin) {
            Ok(text) => text,
            Err(error) if given.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(source) => {
                return Err(Error::Io {
                    path: origin,
                    source,
                })
            }
        };
        let config = if text.trim().is_empty() {
            Config::default()
        } else {
            serde_saphyr::from_str(&text).map_err(|source| Error::Yaml {
                path: origin.clone(),
                source: Box::new(source),
            })?
        };
        // a pack is started in a directory of its own, so where it lives
        // must not depend on where divinate was started.
        let home = std::path::absolute(&home).map_err(|source| Error::Io {
            path: home.clone(),
            source,
        })?;
        Ok(Self {
            config,
            home,
            origin,
        })
    }

    /// whether a pack of this name is configured.
    #[must_use]
    pub fn has(&self, pack: &str) -> bool {
        self.config.packs.contains_key(pack)
    }

    fn entry(&self, pack: &str) -> Result<&Entry> {
        self.config.packs.get(pack).ok_or_else(|| {
            Error::Pack(format!(
                "the pack {pack:?} is not configured: {} has no `packs.{pack}`",
                self.origin.display()
            ))
        })
    }
}

impl Packs for Configured {
    fn call(&self, pack: &str, request: &Value) -> Result<Value> {
        let entry = self.entry(pack)?;
        let failed = |what: &str| Error::Pack(format!("the pack {pack:?} {what}"));
        let program = if entry.command.contains('/') {
            self.home.join(&entry.command)
        } else {
            PathBuf::from(&entry.command)
        };
        let mut command = Command::new(&program);
        command
            .args(&entry.args)
            .current_dir(
                entry
                    .working_dir
                    .as_ref()
                    .map_or_else(|| self.home.clone(), |directory| self.home.join(directory)),
            )
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // a pack is given what it needs to run, what the configuration names,
        // and nothing else of the environment.
        let kept = ["PATH", "HOME", "LANG", "TMPDIR"].map(str::to_owned);
        for name in kept.iter().chain(&entry.inherit) {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.envs(&entry.env);
        // a pack is told its setup with everything but a derivation, which
        // must follow from the transcripts alone.
        let mut request = request.clone();
        if request["request"] != "derive" {
            request["setup"] = entry.setup.clone().unwrap_or(Value::Null);
        }
        let body = serde_json::to_vec(&request).map_err(Error::Serialize)?;
        let mut child = command.spawn().map_err(|error| {
            failed(&format!(
                "could not be started ({}): {error}",
                program.display()
            ))
        })?;
        // the request is written and the answer read on threads of their
        // own, so a pack that neither reads nor answers can be stopped.
        let input = child.stdin.take();
        let writer = std::thread::spawn(move || {
            if let Some(mut input) = input {
                let _ = input.write_all(&body);
            }
        });
        let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
        let reader = std::thread::spawn(move || {
            let mut answer = Vec::new();
            if let Some(out) = &mut out {
                let _ = out.read_to_end(&mut answer);
            }
            answer
        });
        let complaints = std::thread::spawn(move || {
            let mut said = String::new();
            if let Some(err) = &mut err {
                let _ = err.read_to_string(&mut said);
            }
            said
        });
        let deadline = Instant::now() + Duration::from_secs(entry.timeout_seconds);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(failed(&format!(
                        "did not answer within {} seconds",
                        entry.timeout_seconds
                    )));
                }
                Err(error) => return Err(failed(&format!("could not be waited for: {error}"))),
            }
        };
        let _ = writer.join();
        let answer = reader.join().unwrap_or_default();
        let said = complaints.join().unwrap_or_default();
        if !status.success() {
            let said = said.lines().last().unwrap_or("it said nothing");
            return Err(failed(&format!("failed: {said}")));
        }
        serde_json::from_slice(&answer).map_err(|_| failed("did not answer with json"))
    }

    fn secrets(&self, pack: &str) -> Vec<String> {
        self.config
            .packs
            .get(pack)
            .into_iter()
            .flat_map(|entry| &entry.inherit)
            .filter_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// what a pack says it offers.
pub struct Description {
    pub protocol: u64,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub processes: Vec<Shipped>,
    #[serde(default)]
    /// what the pack reads as a source, when it is one.
    pub collects: Option<Collects>,
    #[serde(default)]
    /// the frameworks the process definitions it ships can map to.
    pub frameworks: crate::process::Frameworks,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// what a pack reads as a source.
pub struct Collects {
    /// the scopes it reads, for a message, such as `osv:<owner>/<repository>`.
    pub scopes: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// one check a pack offers.
pub struct Check {
    pub name: String,
    pub answers: Shape,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// what a check answers with, which decides where a definition can use it.
pub enum Shape {
    /// an outcome for each item: used in a step.
    EachItem,
    /// one outcome for all items together: used under `overall`.
    AllItems,
    /// a number over all items: used in a measure.
    Number,
}

impl Shape {
    /// where in a definition a check of this shape goes.
    #[must_use]
    pub fn place(self) -> &'static str {
        match self {
            Self::EachItem => "a step",
            Self::AllItems => "`overall`",
            Self::Number => "a measure",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// a process definition a pack ships.
pub struct Shipped {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// the definition, as the yaml text a file would hold.
    pub definition: String,
}

/// ask a pack what it offers.
///
/// # Errors
///
/// returns an error when the pack cannot be run, speaks another protocol, or
/// answers under another name.
pub fn describe(packs: &dyn Packs, pack: &str) -> Result<Description> {
    let answer = packs.call(
        pack,
        &json!({ "protocol": PROTOCOL, "request": "describe" }),
    )?;
    let description: Description = serde_json::from_value(answer).map_err(|error| {
        Error::Pack(format!(
            "the pack {pack:?} does not describe itself as expected: {error}"
        ))
    })?;
    if description.protocol != PROTOCOL {
        return Err(Error::Pack(format!(
            "the pack {pack:?} speaks protocol {}, and this divinate speaks {PROTOCOL}",
            description.protocol
        )));
    }
    if description.name != pack {
        return Err(Error::Pack(format!(
            "the pack installed as {pack:?} calls itself {:?}",
            description.name
        )));
    }
    Ok(description)
}

/// the pack and the name within it that `<pack>/<name>` names.
///
/// # Errors
///
/// returns an error when there is no `/`.
pub fn named(uses: &str) -> Result<(&str, &str)> {
    uses.split_once('/')
        .filter(|(pack, name)| !pack.is_empty() && !name.is_empty())
        .ok_or_else(|| Error::Pack(format!("{uses:?} is not `<pack>/<check>`")))
}

/// the descriptions of the packs a check has asked so far, each asked once.
pub struct Asked<'a> {
    packs: &'a dyn Packs,
    described: BTreeMap<String, Description>,
}

impl<'a> Asked<'a> {
    #[must_use]
    pub fn new(packs: &'a dyn Packs) -> Self {
        Self {
            packs,
            described: BTreeMap::new(),
        }
    }

    /// run one check of a pack on some items, after making sure the pack has
    /// a check of that name that answers in the wanted shape.
    ///
    /// # Errors
    ///
    /// returns an error when the pack cannot be run or has no such check.
    pub fn check(
        &mut self,
        uses: &str,
        shape: Shape,
        with: Option<&Value>,
        about: &Value,
        items: &[Value],
    ) -> Result<Value> {
        let (pack, name) = named(uses)?;
        if !self.described.contains_key(pack) {
            self.described
                .insert(pack.to_owned(), describe(self.packs, pack)?);
        }
        let found = self.described[pack]
            .checks
            .iter()
            .find(|check| check.name == name)
            .ok_or_else(|| Error::Pack(format!("the pack {pack:?} has no check {name:?}")))?;
        if found.answers != shape {
            return Err(Error::Pack(format!(
                "{uses} belongs in {}, not in {}",
                found.answers.place(),
                shape.place()
            )));
        }
        self.packs.call(
            pack,
            &json!({
                "protocol": PROTOCOL,
                "request": "check",
                "check": name,
                "with": with.cloned().unwrap_or_else(|| json!({})),
                "collection": about,
                "items": items,
            }),
        )
    }

    /// the packs that were asked, as `<name> <version>`.
    #[must_use]
    pub fn used(&self) -> Vec<String> {
        self.described
            .values()
            .map(|description| format!("{} {}", description.name, description.version))
            .collect()
    }
}
