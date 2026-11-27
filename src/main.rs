//! the divinate command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use divinate::error::{Error, Result};
use divinate::pack::{self, Configured};
use divinate::record::Collection;
use divinate::source::{self, Period, Roots};
use divinate::{format_time, ledger, parse_time, process, record, timestamp, verify};

#[derive(Parser)]
#[command(
    version,
    about = "keep a dated record of how software is developed and released"
)]
struct Cli {
    /// the configuration file, which declares the packs; `divinate.yaml` in
    /// the current directory by default
    #[arg(long, global = true)]
    config: Option<PathBuf>,
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
        /// leave out the files each change touches: a faster collection, with
        /// no diffs kept
        #[arg(long)]
        no_files: bool,
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
        /// the process definitions: yaml files, `<pack>:<name>` for one a pack
        /// ships, or `<pack>:` for all of them
        #[arg(required = true)]
        definitions: Vec<String>,
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
    /// show what a configured pack offers: what it collects, its checks, and its process definitions
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
    let cli = Cli::parse();
    match Configured::load(cli.config.as_deref()).and_then(|packs| run(cli.command, &packs)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command, packs: &Configured) -> Result<()> {
    match command {
        Command::Collect {
            scope,
            from,
            until,
            no_files,
            state,
        } => collect(
            &scope,
            from.as_deref(),
            until.as_deref(),
            !no_files,
            &state,
            packs,
        ),
        Command::Check {
            definitions,
            collection,
            last,
            scope,
            all,
            json,
            state,
        } => {
            let mut loaded = Vec::new();
            for definition in &definitions {
                loaded.extend(definitions_from(definition, packs)?);
            }
            let collections = record::load(&state)?;
            let positions = if all {
                Some(latest_of_each_scope(&collections))
            } else if let Some(last) = last {
                let mut positions = in_scope(&collections, scope.as_deref())?;
                positions.drain(..positions.len().saturating_sub(last));
                Some(positions)
            } else {
                None
            };
            check(
                &loaded,
                &collections,
                positions,
                collection.as_deref(),
                json,
                packs,
            )
        }
        Command::Show { collection, state } => show(collection.as_deref(), &state),
        Command::Pack { name } => offered(&name, packs),
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
            let report = verify::verify_with(&state, packs)?;
            println!(
                "verified {} collections and {} transcripts",
                report.collections, report.transcripts
            );
            for (id, why) in &report.not_recomputed {
                println!("{id}: {why}; bytes checked, statements not recomputed");
            }
            Ok(())
        }
    }
}

/// print what a configured pack offers.
fn offered(name: &str, packs: &Configured) -> Result<()> {
    let found = pack::describe(packs, name)?;
    println!("{} {}", found.name, found.version);
    if !found.description.is_empty() {
        println!("{}", found.description);
    }
    if let Some(collects) = &found.collects {
        println!(
            "\ncollects\n  {}  {}",
            collects.scopes, collects.description
        );
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

/// check process definitions against one collection in full, or against
/// the collections at `positions` as a summary each.
fn check(
    definitions: &[process::Process],
    collections: &[Collection],
    positions: Option<Vec<usize>>,
    collection: Option<&str>,
    json: bool,
    packs: &Configured,
) -> Result<()> {
    // each collection is checked with those before it at hand.
    let checked = |definition: &process::Process, position: usize| {
        process::check_with(
            definition,
            &collections[position],
            &collections[..position],
            packs,
        )
    };
    let Some(positions) = positions else {
        let position = position(collections, collection)?;
        let reports = definitions
            .iter()
            .map(|definition| checked(definition, position))
            .collect::<Result<Vec<_>>>()?;
        if json {
            // one definition prints one report, as it always has.
            match reports.as_slice() {
                [report] => println!("{}", to_json(report)?),
                reports => println!("{}", to_json(&reports)?),
            }
        } else {
            for (number, report) in reports.iter().enumerate() {
                if number > 0 {
                    println!();
                }
                print!("{}", process::render(report));
            }
            print!("{}", process::coverage(&reports));
        }
        return Ok(());
    };
    let mut summaries = Vec::new();
    for definition in definitions {
        summaries.push(
            positions
                .iter()
                .map(|position| checked(definition, *position))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    if json {
        match summaries.as_slice() {
            [reports] => println!("{}", to_json(reports)?),
            summaries => println!("{}", to_json(&summaries)?),
        }
    } else {
        for (number, reports) in summaries.iter().enumerate() {
            if number > 0 {
                println!();
            }
            print!("{}", process::summary(reports));
        }
    }
    Ok(())
}

/// the process definitions an argument names: a file, one a pack ships as
/// `<pack>:<name>`, or all a pack ships as `<pack>:`.
fn definitions_from(argument: &str, packs: &Configured) -> Result<Vec<process::Process>> {
    let path = Path::new(argument);
    let shipped = argument.split_once(':').filter(|_| !path.exists());
    let Some((pack, name)) = shipped else {
        return Ok(vec![process::load(path)?]);
    };
    let found = pack::describe(packs, pack)?;
    // a definition a pack ships can map to the frameworks the pack declares.
    let parsed = |process: &pack::Shipped| {
        let mut parsed = process::parse_with(&process.definition, path, &found.frameworks)?;
        parsed.shipped_by = Some(format!("{} {}", found.name, found.version));
        Ok(parsed)
    };
    if name.is_empty() {
        return found.processes.iter().map(parsed).collect();
    }
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
    Ok(vec![parsed(process)?])
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(Error::Serialize)
}

fn collect(
    scope: &str,
    from: Option<&str>,
    until: Option<&str>,
    files: bool,
    state: &Path,
    packs: &Configured,
) -> Result<()> {
    let started_at = timestamp()?;
    let until = match until {
        Some(until) => format_time(parse_time(until)?)?,
        None => started_at.clone(),
    };
    let from = match from {
        Some(from) => format_time(parse_time(from)?)?,
        None => format_time(parse_time(&until)? - time::Duration::days(90))?,
    };
    let period = Period { from, until, files };
    // a scope names a source of this build, or a pack that is one.
    let by_pack = scope.split_once(':').filter(|(name, _)| packs.has(name));
    let (collection, transcripts) = if let Some((pack, path)) = by_pack {
        let (transcripts, stamp) = pack::source::collect(packs, pack, path, &period)?;
        let derived = pack::source::derive(packs, pack, &transcripts)?;
        let collection = record::seal_derived(
            scope,
            started_at,
            timestamp()?,
            &transcripts,
            derived,
            Some(stamp),
        )?;
        (collection, transcripts)
    } else {
        let (source, path) = source::for_scope(scope)?;
        let roots = Roots::from_environment()?;
        let mut fetch = source.client(&source.token()?, &roots);
        let transcripts = source.capture(path, &period, &timestamp, &mut *fetch)?;
        let collection = record::seal(scope, started_at, timestamp()?, &transcripts)?;
        (collection, transcripts)
    };
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
