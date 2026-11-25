//! packs: checks and process definitions that live outside this crate.
//!
//! a pack is an executable named `divinate-pack-<name>`. it is given one json
//! request on its standard input and answers with one json document on its
//! standard output. a pack never makes a statement of the record: it is
//! handed what a collection holds about some items and says what it finds,
//! the same way a step of a process definition does.
//!
//! a pack is run with an almost empty environment, so the credentials the
//! sources use are not passed on to it.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

/// the packs installed on this machine: executables named
/// `divinate-pack-<name>` in the directories `DIVINATE_PACKS` lists, then in
/// those of `PATH`.
pub struct Installed {
    directories: Vec<PathBuf>,
}

impl Installed {
    /// the packs the environment of this process points to.
    #[must_use]
    pub fn from_environment() -> Self {
        let listed = |name| {
            std::env::var_os(name)
                .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let mut directories = listed("DIVINATE_PACKS");
        directories.extend(listed("PATH"));
        Self { directories }
    }

    /// the packs in these directories alone.
    #[must_use]
    pub fn at(directories: Vec<PathBuf>) -> Self {
        Self { directories }
    }

    fn executable(&self, pack: &str) -> Result<PathBuf> {
        let allowed = !pack.is_empty()
            && pack
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !allowed {
            return Err(Error::Pack(format!(
                "{pack:?} is not the name of a pack: use lowercase letters, digits, and `-`"
            )));
        }
        let file = format!("divinate-pack-{pack}");
        self.directories
            .iter()
            .map(|directory| directory.join(&file))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                Error::Pack(format!(
                    "the pack {pack:?} is not installed: no {file} in DIVINATE_PACKS or PATH"
                ))
            })
    }
}

impl Packs for Installed {
    fn call(&self, pack: &str, request: &Value) -> Result<Value> {
        let executable = self.executable(pack)?;
        let failed = |what: &str| Error::Pack(format!("the pack {pack:?} {what}"));
        let mut command = Command::new(&executable);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for kept in ["PATH", "HOME", "LANG", "TMPDIR"] {
            if let Some(value) = std::env::var_os(kept) {
                command.env(kept, value);
            }
        }
        let mut child = command
            .spawn()
            .map_err(|error| failed(&format!("could not be started: {error}")))?;
        let body = serde_json::to_vec(request).map_err(Error::Serialize)?;
        // a pack that answers without reading its input closes the pipe early.
        // what it answered is still read below.
        if let Some(mut input) = child.stdin.take() {
            let _ = input.write_all(&body);
        }
        let output = child
            .wait_with_output()
            .map_err(|error| failed(&format!("could not be read: {error}")))?;
        if !output.status.success() {
            let said = String::from_utf8_lossy(&output.stderr);
            let said = said.lines().last().unwrap_or("it said nothing");
            return Err(failed(&format!("failed: {said}")));
        }
        serde_json::from_slice(&output.stdout).map_err(|_| failed("did not answer with json"))
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
