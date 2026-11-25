//! the divinate command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use divinate::error::{Error, Result};
use divinate::pack::{self, Installed};
use divinate::record::Collection;
use divinate::source::{self, Period};
use divinate::{format_time, ledger, parse_time, process, record, timestamp, verify};

#[derive(Parser)]
#[command(
    version,
    about = "keep a dated record of how software is developed and released"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// read a scope and add one collection to the record
    Collect {
        /// what to read: an organisation or group, or one repository or project,
        /// such as github:<organisation>/<repository>, gitlab:<group>/<project>,
        /// or azure:<organisation>/<project>. a single repository or project is
        /// read with its tickets and changes
        scope: String,
        /// read tickets and changes opened from this time; defaults to 90 days ago
        #[arg(long)]
        from: Option<String>,
        /// read tickets and changes opened before this time; defaults to now
        #[arg(long)]
        until: Option<String>,
        /// where the record is kept
        #[arg(long, default_value = "evidence")]
        state: PathBuf,
    },
    /// show one collection in full; the latest by default
    Show {
        /// the collection to show, by id
        collection: Option<String>,
        /// where the record is kept
        #[arg(long, default_value = "evidence")]
        state: PathBuf,
    },
    /// show every kind of evidence across collections
    Ledger {
        /// the scope to show; defaults to the scope of the latest collection
        #[arg(long)]
        scope: Option<String>,
        /// how many collections to show, counted from the latest
        #[arg(long, default_value_t = 8)]
        last: usize,
        /// where the record is kept
        #[arg(long, default_value = "evidence")]
        state: PathBuf,
    },
    /// check a process definition against one collection; the latest by default
    Check {
        /// the process definition: a yaml file, or `<pack>:<name>` for one a
        /// pack ships
        definition: String,
        /// the collection to check, by id
        #[arg(long, conflicts_with_all = ["last", "all"])]
        collection: Option<String>,
        /// summarise the last collections of one scope instead, oldest first
        #[arg(long, conflicts_with = "all")]
        last: Option<usize>,
        /// the scope `--last` looks at; defaults to the scope of the latest collection
        #[arg(long, requires = "last")]
        scope: Option<String>,
        /// summarise the latest collection of every scope in the record instead
        #[arg(long)]
        all: bool,
        /// print the outcomes as json: one report, or a list of them with
        /// `--last` or `--all`
        #[arg(long)]
        json: bool,
        /// where the record is kept
        #[arg(long, default_value = "evidence")]
        state: PathBuf,
    },
    /// show what an installed pack offers: its checks and process definitions
    Pack {
        /// the name of the pack, as in `divinate-pack-<name>`
        name: String,
    },
    /// check the stored record offline
    Verify {
        /// where the record is kept
        #[arg(long, default_value = "evidence")]
        state: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Collect {
            scope,
            from,
            until,
            state,
        } => collect(&scope, from.as_deref(), until.as_deref(), &state),
        Command::Check {
            definition,
            collection,
            last,
            scope,
            all,
            json,
            state,
        } => {
            let packs = Installed::from_environment();
            let definition = definition_from(&definition, &packs)?;
            let collections = record::load(&state)?;
            // each collection is checked with those before it at hand.
            let checked = |position: usize| {
                process::check_with(
                    &definition,
                    &collections[position],
                    &collections[..position],
                    &packs,
                )
            };
            let positions = if all {
                latest_of_each_scope(&collections)
            } else if let Some(last) = last {
                let mut positions = in_scope(&collections, scope.as_deref())?;
                positions.drain(..positions.len().saturating_sub(last));
                positions
            } else {
                let report = checked(position(&collections, collection.as_deref())?)?;
                if json {
                    println!("{}", to_json(&report)?);
                } else {
                    print!("{}", process::render(&report));
                }
                return Ok(());
            };
            let reports = positions
                .into_iter()
                .map(checked)
                .collect::<Result<Vec<_>>>()?;
            if json {
                println!("{}", to_json(&reports)?);
            } else {
                print!("{}", process::summary(&reports));
            }
            Ok(())
        }
        Command::Show { collection, state } => show(collection.as_deref(), &state),
        Command::Pack { name } => offered(&name),
        Command::Ledger { scope, last, state } => {
            let all = record::load(&state)?;
            let collections = in_scope(&all, scope.as_deref())?
                .into_iter()
                .map(|position| all[position].clone())
                .collect::<Vec<_>>();
            print!("{}", ledger::ledger(&collections, last));
            Ok(())
        }
        Command::Verify { state } => {
            let report = verify::verify(&state)?;
            println!(
                "verified {} collections and {} transcripts",
                report.collections, report.transcripts
            );
            for id in &report.not_recomputed {
                println!("{id}: derived by other rules; bytes checked, statements not recomputed");
            }
            Ok(())
        }
    }
}

/// print what an installed pack offers.
fn offered(name: &str) -> Result<()> {
    let found = pack::describe(&Installed::from_environment(), name)?;
    println!("{} {}", found.name, found.version);
    if !found.description.is_empty() {
        println!("{}", found.description);
    }
    if !found.checks.is_empty() {
        println!("\nchecks");
    }
    for check in &found.checks {
        println!(
            "  {}/{}  for {}. {}",
            found.name,
            check.name,
            check.answers.place(),
            check.description
        );
    }
    if !found.processes.is_empty() {
        println!("\nprocess definitions");
    }
    for process in &found.processes {
        println!("  {}:{}  {}", found.name, process.name, process.description);
    }
    Ok(())
}

/// the process definition an argument names: a file, or one a pack ships as
/// `<pack>:<name>`.
fn definition_from(argument: &str, packs: &Installed) -> Result<process::Process> {
    let path = Path::new(argument);
    let shipped = argument.split_once(':').filter(|_| !path.exists());
    let Some((pack, name)) = shipped else {
        return process::load(path);
    };
    let found = pack::describe(packs, pack)?;
    let process = found
        .processes
        .iter()
        .find(|process| process.name == name)
        .ok_or_else(|| {
            let known = found
                .processes
                .iter()
                .map(|process| process.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Error::Pack(format!(
                "the pack {pack:?} ships no process definition {name:?}; it has: {known}"
            ))
        })?;
    process::parse(&process.definition, path)
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(Error::Serialize)
}

fn collect(scope: &str, from: Option<&str>, until: Option<&str>, state: &Path) -> Result<()> {
    let (source, path) = source::for_scope(scope)?;
    let started_at = timestamp()?;
    let until = match until {
        Some(until) => format_time(parse_time(until)?)?,
        None => started_at.clone(),
    };
    let from = match from {
        Some(from) => format_time(parse_time(from)?)?,
        None => format_time(parse_time(&until)? - time::Duration::days(90))?,
    };
    let mut fetch = source.client(&source.token()?);
    let transcripts = source.capture(path, &Period { from, until }, &timestamp, &mut *fetch)?;
    let collection = record::seal(scope, started_at, timestamp()?, &transcripts)?;
    record::store(state, &collection, &transcripts)?;
    println!(
        "collected {scope}: {} records, {} gaps\n{}",
        collection.recorded(),
        collection.gaps(),
        collection.id
    );
    Ok(())
}

fn show(id: Option<&str>, state: &Path) -> Result<()> {
    let collections = record::load(state)?;
    let position = position(&collections, id)?;
    let collection = &collections[position];
    let previous = collections[..position]
        .iter()
        .rev()
        .find(|earlier| earlier.contents.scope == collection.contents.scope);
    print!("{}", ledger::show(collection, previous));
    Ok(())
}

/// where a collection is in the record: the one with an id, or the latest.
fn position(collections: &[Collection], id: Option<&str>) -> Result<usize> {
    match id {
        Some(id) => collections
            .iter()
            .position(|collection| collection.id == id)
            .ok_or_else(|| Error::Invalid(format!("no collection {id}"))),
        None => collections
            .len()
            .checked_sub(1)
            .ok_or_else(|| Error::Invalid("the record holds no collections".into())),
    }
}

/// where the latest collection of every scope is, in the order of the scopes' names.
fn latest_of_each_scope(collections: &[Collection]) -> Vec<usize> {
    let mut latest = std::collections::BTreeMap::new();
    for (position, collection) in collections.iter().enumerate() {
        latest.insert(&collection.contents.scope, position);
    }
    latest.into_values().collect()
}

/// where the collections of one scope are: the named scope, or that of the
/// latest collection.
fn in_scope(collections: &[Collection], scope: Option<&str>) -> Result<Vec<usize>> {
    let scope = match scope {
        Some(scope) => scope,
        None => {
            &collections
                .last()
                .ok_or_else(|| Error::Invalid("the record holds no collections".into()))?
                .contents
                .scope
        }
    };
    Ok(collections
        .iter()
        .enumerate()
        .filter(|(_, collection)| collection.contents.scope == scope)
        .map(|(position, _)| position)
        .collect())
}
