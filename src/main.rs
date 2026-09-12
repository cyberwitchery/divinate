use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use divinate::acquisition::{
    self, AcquisitionTranscript, ContractInvalidation, ContractRegistry,
    GithubBranchProtectionCapture, GithubCapture, GITHUB_COMMITS_CONTRACT,
};
use divinate::assertions::{self, DerivedAssertion, EvaluationTarget};
use divinate::dossier;
use divinate::error::{Error, Result};
use divinate::execution::{self, ExecutionRequest, NamedPath};
use divinate::model::{CollectionOutcome, Corpus, Observation, ObservationKind};
use divinate::{collect, load_corpus, parse_timestamp, read_json, source_bytes, write_json};

#[derive(Parser)]
#[command(about = "preserve technical security evidence and derive traceable claims")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// configure this repository
    Init {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// bring configured evidence and the current evaluation up to date
    Collect {
        #[command(subcommand)]
        command: Option<CollectCommand>,
        #[command(flatten)]
        args: ProductCollectArgs,
    },
    /// summarize the latest saved state
    Status {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// compare the current evaluation with the previous one
    Review {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value = "current")]
        current: String,
        #[arg(long, default_value = "review")]
        output: String,
        #[arg(long)]
        json: bool,
    },
    /// render a view from saved assertions
    Export {
        #[command(subcommand)]
        kind: ExportCommand,
    },
    /// advanced: list configured packs
    Packs {
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
    },
    /// advanced: inspect one configured external pack
    Pack {
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
        id: String,
    },
    /// advanced: run a local tool and retain its provenance
    Run {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long)]
        tool: String,
        #[arg(long)]
        tool_version: Option<String>,
        #[arg(long = "input", value_parser = parse_named_path)]
        inputs: Vec<NamedPathArg>,
        #[arg(long = "output", value_parser = parse_named_path)]
        outputs: Vec<NamedPathArg>,
        #[arg(long = "environment", value_parser = parse_metadata)]
        environment: Vec<(String, String)>,
        #[arg(long)]
        working_directory: Option<PathBuf>,
        #[arg(long)]
        stdout: Option<PathBuf>,
        executable: PathBuf,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// advanced: derive and save assertions
    Evaluate {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
        #[arg(long, default_value = "current")]
        label: String,
        #[arg(long)]
        contracts: Option<PathBuf>,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// inspect: verify all retained provenance offline
    Verify {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
    },
    /// inspect: show an assertion's provenance
    Provenance {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = "current")]
        evaluation: String,
        assertion_id: String,
    },
    /// inspect: extract a retained command stream
    Extract {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        execution_id: String,
        #[arg(long, value_enum, default_value_t = Stream::Stdout)]
        stream: Stream,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// query observations
    #[command(hide = true)]
    Query {
        corpus: PathBuf,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        kind: Option<Kind>,
    },
    /// list evidence producers
    #[command(hide = true)]
    Tools { corpus: PathBuf },
    /// extract an observation's verified source
    #[command(name = "source-bytes", hide = true)]
    SourceBytes {
        corpus: PathBuf,
        evidence_id: String,
    },
    /// derive assertions from a corpus
    #[command(hide = true)]
    Assertions {
        corpus: PathBuf,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// explain an assertion from a standalone corpus
    #[command(hide = true)]
    Explain {
        corpus: PathBuf,
        assertion_id: String,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long)]
        json: bool,
    },
    /// inspect collection runs
    #[command(hide = true)]
    Collections {
        corpus: PathBuf,
        #[arg(long)]
        incomplete: bool,
    },
    /// inspect an assertion's coverage
    #[command(hide = true)]
    Coverage {
        corpus: PathBuf,
        assertion_id: String,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// capture a github commit transcript
    #[command(hide = true)]
    CaptureGithub(CaptureArgs),
    /// capture a github branch-protection transcript
    #[command(hide = true)]
    CaptureBranchProtection(CaptureBranchArgs),
    /// extract an acquisition response body
    #[command(hide = true)]
    AcquisitionSource {
        transcript: PathBuf,
        #[arg(default_value_t = 0)]
        exchange: usize,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// verify an acquisition transcript offline
    #[command(hide = true)]
    ReplayAcquisition {
        transcript: PathBuf,
        #[arg(long)]
        invalidate_at: Option<String>,
        #[arg(long)]
        invalidate_reason: Option<String>,
    },
    /// compare equal-scope acquisitions
    #[command(hide = true)]
    CompareAcquisitions { left: PathBuf, right: PathBuf },
    /// build a technical-controls dossier
    #[command(hide = true)]
    Dossier {
        corpus: PathBuf,
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long = "acquisition")]
        acquisitions: Vec<PathBuf>,
        #[arg(long)]
        markdown: PathBuf,
        #[arg(long)]
        json_output: PathBuf,
    },
    /// append a corpus increment and acquisitions
    #[command(hide = true)]
    StateRecord {
        state: PathBuf,
        increment: PathBuf,
        #[arg(long = "acquisition")]
        acquisitions: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ExportCommand {
    /// render a due-diligence evidence response
    Dd {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = "current")]
        evaluation: String,
        #[arg(long, default_value = "dd-response")]
        output: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CollectCommand {
    /// compatibility: collect one explicit release sbom comparison
    Release(Box<ReleaseArgs>),
    /// collect with a configured pack
    Pack {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = ".")]
        repository_path: PathBuf,
        id: String,
        collector: String,
        #[arg(long)]
        context: Option<PathBuf>,
    },
    /// import a source manifest
    Manifest {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        manifest: PathBuf,
        #[arg(long = "acquisition")]
        acquisitions: Vec<PathBuf>,
    },
}

#[derive(Args)]
struct ReleaseArgs {
    #[arg(long, default_value = ".evidence")]
    state: PathBuf,
    #[arg(long)]
    repository_path: PathBuf,
    #[arg(long)]
    base_release: String,
    #[arg(long)]
    release: String,
    #[arg(long)]
    base_revision: Option<String>,
    #[arg(long)]
    revision: Option<String>,
    #[arg(long)]
    base_sbom: PathBuf,
    #[arg(long)]
    target_sbom: PathBuf,
    #[arg(long)]
    sbom_diff: PathBuf,
    #[arg(long)]
    tool_version: Option<String>,
    #[arg(long, default_value = "supply-chain/default")]
    policy: String,
    #[arg(long, default_value = "added-components")]
    fail_on: String,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ProductCollectArgs {
    #[arg(long, default_value = ".evidence")]
    state: PathBuf,
    #[arg(long, default_value = ".")]
    repository_path: PathBuf,
    #[arg(long)]
    release: Option<String>,
    #[arg(long)]
    base_release: Option<String>,
    #[arg(long)]
    from: Option<String>,
    #[arg(long)]
    until: Option<String>,
    #[arg(long)]
    at: Option<String>,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Clone)]
struct NamedPathArg {
    name: String,
    path: PathBuf,
}

struct PreparedPackCollection {
    pack: String,
    collector: String,
    observation: String,
    corpus: Corpus,
    invocations: Vec<divinate::pack::PackCapture>,
    execution: divinate::execution::ExecutionCapture,
}

struct PreparedSource {
    corpus: Corpus,
    executions: Vec<divinate::execution::ExecutionCapture>,
    invocations: Vec<divinate::pack::PackCapture>,
    detail: String,
}

#[derive(Clone)]
struct ReleaseContext {
    release: String,
    revision: String,
    previous_release: String,
    previous_revision: String,
}

#[derive(serde::Serialize)]
struct SourceReport {
    source: String,
    status: String,
    detail: String,
}

#[derive(serde::Serialize)]
struct ProductCollectionReport {
    repository: String,
    branch: String,
    release: String,
    sources: Vec<SourceReport>,
    new_observations: usize,
    outcomes: BTreeMap<String, usize>,
    dossier: String,
}

#[derive(serde::Serialize)]
struct StatusReport {
    repository: String,
    branch: String,
    last_collected: Option<String>,
    last_evaluated: Option<String>,
    outcomes: BTreeMap<String, usize>,
    evidence_sources: BTreeMap<String, usize>,
    configured_sources: Vec<ConfiguredSourceStatus>,
    degraded_collections: Vec<DegradedCollection>,
    unresolved_gaps: usize,
    since_previous: Option<StatusChanges>,
}

#[derive(serde::Serialize)]
struct ConfiguredSourceStatus {
    source: String,
    required: Option<bool>,
    state: String,
    detail: Option<String>,
}

#[derive(serde::Serialize)]
struct DegradedCollection {
    collector: String,
    outcome: String,
    limitations: Vec<String>,
}

#[derive(serde::Serialize)]
struct StatusChanges {
    claims_changed: usize,
    new_gaps: usize,
    coverage_regressions: usize,
}

#[derive(Args)]
struct CaptureArgs {
    #[arg(long)]
    repository: String,
    #[arg(long, default_value = "main")]
    branch: String,
    #[arg(long)]
    from: String,
    #[arg(long)]
    until: String,
    #[arg(long, default_value_t = 100)]
    per_page: u16,
    #[arg(long, default_value_t = 100)]
    max_pages: u16,
    #[arg(long)]
    at: Option<String>,
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Args)]
struct CaptureBranchArgs {
    #[arg(long)]
    repository: String,
    #[arg(long, default_value = "main")]
    branch: String,
    #[arg(long)]
    from: String,
    #[arg(long)]
    until: String,
    #[arg(long)]
    at: Option<String>,
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Args)]
struct TargetArgs {
    #[arg(long)]
    repository: Option<String>,
    #[arg(long)]
    branch: Option<String>,
    #[arg(long)]
    release: Option<String>,
    #[arg(long)]
    from: String,
    #[arg(long)]
    until: String,
    #[arg(long)]
    at: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    ChangeSet,
    ConfigurationHistory,
    ConfigurationSnapshot,
    MutationHistory,
    PolicyCheck,
    ReleaseMembership,
    ReviewRecord,
}

#[derive(Clone, Copy, ValueEnum)]
enum Stream {
    Stdout,
    Stderr,
}

impl From<Kind> for ObservationKind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::ChangeSet => Self::ChangeSet,
            Kind::ConfigurationHistory => Self::ConfigurationHistory,
            Kind::ConfigurationSnapshot => Self::ConfigurationSnapshot,
            Kind::MutationHistory => Self::MutationHistory,
            Kind::PolicyCheck => Self::PolicyCheck,
            Kind::ReleaseMembership => Self::ReleaseMembership,
            Kind::ReviewRecord => Self::ReviewRecord,
        }
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init {
            state,
            branch,
            repository_path,
            json,
        } => init_repository(&state, &repository_path, branch, json),
        Command::Collect { command, args } => match command {
            Some(CollectCommand::Release(args)) => collect_release(*args),
            Some(CollectCommand::Pack {
                state,
                repository_path,
                id,
                collector,
                context,
            }) => collect_pack(
                &state,
                &repository_path,
                &id,
                &collector,
                context.as_deref(),
            ),
            Some(CollectCommand::Manifest {
                state,
                manifest,
                acquisitions,
            }) => {
                let increment = collect(&manifest).map_err(collection_error)?;
                record_increment(&state, &increment, &acquisitions).map_err(collection_error)
            }
            None => collect_configured(&args),
        },
        Command::Status {
            state,
            repository_path,
            json,
        } => state_status(&state, &repository_path, json),
        Command::Packs { repository_path } => list_packs(&repository_path),
        Command::Pack {
            repository_path,
            id,
        } => inspect_pack(&repository_path, &id),
        Command::Run {
            state,
            tool,
            tool_version,
            inputs,
            outputs,
            environment,
            working_directory,
            stdout,
            executable,
            argv,
        } => run_tool(
            &state,
            tool,
            tool_version,
            &inputs,
            &outputs,
            environment,
            working_directory,
            stdout.as_deref(),
            executable,
            argv,
        ),
        Command::Evaluate {
            state,
            repository_path,
            label,
            contracts,
            target,
        } => evaluate_state(
            &state,
            &repository_path,
            &label,
            contracts.as_deref(),
            target,
        ),
        Command::Review {
            state,
            since,
            current,
            output,
            json,
        } => state_review(&state, since.as_deref(), &current, &output, json),
        Command::Export { kind } => match kind {
            ExportCommand::Dd {
                state,
                evaluation,
                output,
                json,
            } => state_dd(&state, &evaluation, &output, json),
        },
        Command::Verify { state } => verify_state(&state),
        Command::Provenance {
            state,
            evaluation,
            assertion_id,
        } => show_provenance(&state, &evaluation, &assertion_id),
        Command::Extract {
            state,
            execution_id,
            stream,
            output,
        } => extract_stream(&state, &execution_id, stream, &output),
        Command::Query {
            corpus,
            revision,
            tool,
            kind,
        } => query(&corpus, revision.as_deref(), tool.as_deref(), kind),
        Command::Tools { corpus } => list_tools(&corpus),
        Command::SourceBytes {
            corpus,
            evidence_id,
        } => recover_source(&corpus, &evidence_id),
        Command::Assertions {
            corpus,
            target,
            output,
        } => derive_assertions(&corpus, target, output.as_deref()),
        Command::Explain {
            corpus,
            assertion_id,
            target,
            json,
        } => {
            let corpus = load_corpus(&corpus)?;
            let (target, at) = evaluation(target)?;
            let derived = assertions::evaluate_all(&corpus, &target, at)?;
            let assertion = derived
                .iter()
                .find(|item| item.id == assertion_id)
                .ok_or_else(|| Error::Invalid(format!("unknown assertion id: {assertion_id}")))?;
            if json {
                print_json(assertion)
            } else {
                explain(assertion)
            }
        }
        Command::Collections { corpus, incomplete } => list_collections(&corpus, incomplete),
        Command::Coverage {
            corpus,
            assertion_id,
            target,
        } => {
            let corpus = load_corpus(&corpus)?;
            let (target, at) = evaluation(target)?;
            let derived = assertions::evaluate_all(&corpus, &target, at)?;
            let assertion = derived
                .iter()
                .find(|item| item.id == assertion_id)
                .ok_or_else(|| Error::Invalid(format!("unknown assertion id: {assertion_id}")))?;
            print_json(&assertion.coverage)
        }
        Command::CaptureGithub(args) => capture_github(args),
        Command::CaptureBranchProtection(args) => capture_branch_protection(args),
        Command::AcquisitionSource {
            transcript,
            exchange,
            output,
        } => acquisition_source(&transcript, exchange, &output),
        Command::ReplayAcquisition {
            transcript,
            invalidate_at,
            invalidate_reason,
        } => replay_acquisition(&transcript, invalidate_at, invalidate_reason),
        Command::CompareAcquisitions { left, right } => compare_acquisitions(&left, &right),
        Command::Dossier {
            corpus,
            target,
            acquisitions,
            markdown,
            json_output,
        } => generate_dossier(&corpus, target, &acquisitions, &markdown, &json_output),
        Command::StateRecord {
            state,
            increment,
            acquisitions,
        } => record_state(&state, &increment, &acquisitions),
    }
}

fn list_tools(corpus_path: &std::path::Path) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    let tools = corpus
        .observations
        .iter()
        .map(|item| (&item.producer.name, &item.producer.version))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(name, version)| serde_json::json!({"name": name, "version": version}))
        .collect::<Vec<_>>();
    print_json(&tools)
}

fn init_repository(
    state: &std::path::Path,
    repository_path: &std::path::Path,
    branch: Option<String>,
    json: bool,
) -> Result<()> {
    let repository = divinate::release::repository_identity(repository_path)?;
    let branch = branch.map_or_else(|| divinate::release::current_branch(repository_path), Ok)?;
    divinate::workflow::init(state)?;
    divinate::workflow::ensure_repository_identity(state, &repository)?;
    let project_path = repository_path.join(divinate::project::PROJECT_FILE);
    let created = if project_path.exists() {
        divinate::project::load(repository_path)?;
        false
    } else if state.join(divinate::workflow::CONFIG_FILE).exists() {
        let legacy = divinate::workflow::load_legacy_config(state)?;
        if legacy.repository != repository {
            return Err(Error::Provenance(format!(
                "legacy configuration identifies repository {}, not {repository}",
                legacy.repository
            )));
        }
        divinate::project::store(repository_path, &divinate::project::from_legacy(&legacy))?;
        true
    } else {
        divinate::project::initialize(repository_path, &repository, &branch)?
    };
    let branch = divinate::project::load(repository_path)?.config.branch;
    if json {
        print_json(&serde_json::json!({
            "repository": repository,
            "branch": branch,
            "state": state,
            "configuration_created": created,
        }))
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Initialized").map_err(stdout_error)?;
        writeln!(out, "  Repository  {repository}").map_err(stdout_error)?;
        writeln!(out, "  Branch      {branch}").map_err(stdout_error)?;
        writeln!(out, "  Config      {}", project_path.display()).map_err(stdout_error)?;
        writeln!(out, "  State       {}", state.display()).map_err(stdout_error)
    }
}

#[allow(clippy::too_many_lines)]
fn collect_configured(args: &ProductCollectArgs) -> Result<()> {
    let project = divinate::project::load(&args.repository_path)?;
    let config = project.config;
    divinate::workflow::ensure_repository_identity(&args.state, &config.repository)?;
    let corpus_path = divinate::workflow::corpus_path(&args.state);
    let base = if corpus_path.exists() {
        load_corpus(&corpus_path)?
    } else {
        empty_corpus()
    };
    let before = base.observations.len();
    let at = args.at.as_ref().map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(value),
    )?;
    let evaluated_at = format_timestamp(at)?;
    let until = args.until.clone().unwrap_or_else(|| evaluated_at.clone());
    let enabled = config
        .sources
        .iter()
        .filter(|(_, source)| source.enabled)
        .collect::<Vec<_>>();
    if enabled.is_empty() {
        return Err(Error::Invalid(
            "divinate.yaml defines no evidence sources; add one under sources".into(),
        ));
    }
    let needs_release = enabled
        .iter()
        .any(|(_, source)| source.context == divinate::workflow::SourceContext::Release);
    let release_context = needs_release
        .then(|| resolve_release_context(&config, &base, args))
        .transpose()?;
    let from = infer_evaluation_start(
        args,
        release_context.as_ref(),
        current_evaluated_at(&args.state)?,
    )?;
    if parse_timestamp(&from)? >= parse_timestamp(&until)? {
        return Err(Error::Invalid(format!(
            "automatic evaluation interval is empty ({from} to {until}); choose --from and --until"
        )));
    }
    let mut increment = empty_corpus();
    let mut executions = Vec::new();
    let mut invocations = Vec::new();
    let mut reports = Vec::new();
    let mut unavailable_optional_packs = BTreeSet::new();

    for (id, source) in enabled {
        let context = source_context(
            &config,
            source,
            release_context.as_ref(),
            &args.repository_path,
            &from,
            &until,
            &evaluated_at,
        );
        match prepare_source(args, &config, source, release_context.as_ref(), &context) {
            Ok(prepared) => {
                let incomplete = prepared
                    .corpus
                    .collections
                    .iter()
                    .any(|run| run.outcome != CollectionOutcome::Complete);
                increment = divinate::workflow::merge(&increment, &prepared.corpus)?;
                executions.extend(prepared.executions);
                invocations.extend(prepared.invocations);
                reports.push(SourceReport {
                    source: id.clone(),
                    status: if incomplete { "incomplete" } else { "complete" }.into(),
                    detail: prepared.detail,
                });
            }
            Err(error) if !source.required => {
                if let divinate::workflow::SourceProvider::Pack { pack, .. } = &source.provider {
                    unavailable_optional_packs.insert(pack.clone());
                }
                reports.push(SourceReport {
                    source: id.clone(),
                    status: "failed (optional)".into(),
                    detail: error.to_string(),
                });
            }
            Err(error) => {
                return Err(Error::Collection(format!(
                    "required source {id} failed: {error}"
                )));
            }
        }
    }

    let preview = divinate::workflow::merge(&base, &increment)?;
    let release = release_context.map_or_else(
        || divinate::workflow::latest_release(&preview, at),
        |context| Ok(context.release),
    )?;
    divinate::workflow::store_project_configuration(&args.state, &project.sha256, &project.bytes)?;
    let merged = commit_collections(&args.state, &increment, &executions, &invocations)?;
    divinate::workflow::store_collection_cycle(
        &args.state,
        divinate::workflow::CollectionCycleContents {
            repository: config.repository.clone(),
            branch: config.branch.clone(),
            project_config_sha256: project.sha256.clone(),
            sources: reports
                .iter()
                .map(|report| {
                    (
                        report.source.clone(),
                        divinate::workflow::SourceCollectionRecord {
                            status: report.status.clone(),
                            detail: report.detail.clone(),
                        },
                    )
                })
                .collect(),
            observation_ids: increment
                .observations
                .iter()
                .map(|item| item.id.clone())
                .collect(),
            execution_transcript_ids: executions
                .iter()
                .map(|item| item.transcript.id.clone())
                .collect(),
            pack_invocation_ids: invocations
                .iter()
                .map(|item| item.invocation.id.clone())
                .collect(),
            completed_at: evaluated_at.clone(),
        },
    )?;
    evaluate_state_with_skips(
        &args.state,
        &config,
        Some(&project.sha256),
        "next",
        None,
        TargetArgs {
            repository: Some(config.repository.clone()),
            branch: Some(config.branch.clone()),
            release: Some(release.clone()),
            from,
            until,
            at: Some(evaluated_at),
        },
        &unavailable_optional_packs,
    )
    .map_err(|error| {
        Error::Collection(format!(
            "evidence was recorded, but current evaluation failed: {error}"
        ))
    })?;
    promote_current_evaluation(&args.state, "next")?;
    let assertions = load_evaluation(&args.state, "current")?;
    let report = ProductCollectionReport {
        repository: config.repository,
        branch: config.branch,
        release,
        sources: reports,
        new_observations: merged.observations.len().saturating_sub(before),
        outcomes: outcome_counts(&assertions),
        dossier: args
            .state
            .join("dossiers/current.md")
            .to_string_lossy()
            .into_owned(),
    };
    if args.json {
        print_json(&report)
    } else {
        render_collection_report(&report)
    }
}

fn resolve_release_context(
    config: &divinate::workflow::ProjectConfig,
    corpus: &Corpus,
    args: &ProductCollectArgs,
) -> Result<ReleaseContext> {
    let actual = divinate::release::repository_identity(&args.repository_path)?;
    if actual != config.repository {
        return Err(Error::Provenance(format!(
            "repository path resolves to {actual}, not configured repository {}",
            config.repository
        )));
    }
    let release = args.release.clone().map_or_else(
        || divinate::release::release_at_head(&args.repository_path),
        Ok,
    )?;
    let known_releases = corpus
        .observations
        .iter()
        .filter_map(|item| item.subject.qualifier("release").map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let base_release = args.base_release.clone().map_or_else(
        || divinate::release::previous_release(&args.repository_path, &release, &known_releases),
        Ok,
    )?;
    let previous_revision =
        divinate::release::resolve_release(&args.repository_path, &base_release)?;
    let revision = divinate::release::resolve_release(&args.repository_path, &release)?;
    validate_recorded_revision(corpus, &base_release, &previous_revision)?;
    validate_recorded_revision(corpus, &release, &revision)?;
    if previous_revision == revision {
        return Err(Error::Provenance(
            "base and target releases resolve to the same revision".into(),
        ));
    }
    Ok(ReleaseContext {
        release,
        revision,
        previous_release: base_release,
        previous_revision,
    })
}

fn validate_recorded_revision(corpus: &Corpus, release: &str, revision: &str) -> Result<()> {
    if let Some(expected) = recorded_revision(corpus, release)? {
        if expected != revision {
            return Err(Error::Provenance(format!(
                "release {release} resolves to {revision}, not expected revision {expected}"
            )));
        }
    }
    Ok(())
}

fn infer_evaluation_start(
    args: &ProductCollectArgs,
    release: Option<&ReleaseContext>,
    current: Option<String>,
) -> Result<String> {
    if let Some(from) = &args.from {
        return Ok(from.clone());
    }
    if let Some(current) = current {
        return Ok(current);
    }
    release.map_or_else(
        || {
            Err(Error::Invalid(
                "cannot determine evaluation start; choose one with --from".into(),
            ))
        },
        |context| divinate::release::release_time(&args.repository_path, &context.previous_release),
    )
}

fn source_context(
    project: &divinate::workflow::ProjectConfig,
    source: &divinate::workflow::SourceConfig,
    release: Option<&ReleaseContext>,
    repository_path: &std::path::Path,
    from: &str,
    until: &str,
    observed_at: &str,
) -> serde_json::Value {
    let release = (source.context == divinate::workflow::SourceContext::Release)
        .then_some(release)
        .flatten()
        .map(|release| {
            serde_json::json!({
                "release": release.release,
                "revision": release.revision,
                "previous_release": release.previous_release,
                "previous_revision": release.previous_revision,
            })
        });
    serde_json::json!({
        "repository": project.repository,
        "branch": project.branch,
        "repository_path": repository_path,
        "interval": {"from": from, "until": until},
        "observed_at": observed_at,
        "release": release,
        "configuration": source.configuration,
    })
}

fn prepare_source(
    args: &ProductCollectArgs,
    project: &divinate::workflow::ProjectConfig,
    configured: &divinate::workflow::SourceConfig,
    release: Option<&ReleaseContext>,
    context: &serde_json::Value,
) -> Result<PreparedSource> {
    match &configured.provider {
        divinate::workflow::SourceProvider::Builtin { source } if source == "release-sbom" => {
            prepare_release_sbom_source(args, project, configured, release)
        }
        divinate::workflow::SourceProvider::Builtin { source } => Err(Error::Invalid(format!(
            "unknown built-in source {source:?}"
        ))),
        divinate::workflow::SourceProvider::Pack { pack, collector } => {
            let config = project
                .packs
                .get(pack)
                .ok_or_else(|| Error::Invalid(format!("pack {pack:?} is not configured")))?;
            let prepared = prepare_pack_collection(config, pack, collector, context)?;
            Ok(PreparedSource {
                corpus: prepared.corpus,
                executions: vec![prepared.execution],
                invocations: prepared.invocations,
                detail: "evidence recorded".into(),
            })
        }
    }
}

fn prepare_release_sbom_source(
    args: &ProductCollectArgs,
    project: &divinate::workflow::ProjectConfig,
    source: &divinate::workflow::SourceConfig,
    release: Option<&ReleaseContext>,
) -> Result<PreparedSource> {
    let release = release
        .ok_or_else(|| Error::Invalid("release-sbom requires release collection context".into()))?;
    let existing = divinate::workflow::load_executions(&args.state)?;
    let blobs = divinate::workflow::load_blobs(&args.state)?;
    let capture = divinate::release::collect_configured(
        &divinate::release::ConfiguredReleaseRequest {
            repository: project.repository.clone(),
            repository_path: args.repository_path.clone(),
            base_release: release.previous_release.clone(),
            release: release.release.clone(),
            base_revision: release.previous_revision.clone(),
            revision: release.revision.clone(),
            configuration: source.configuration.clone(),
            force: args.force,
        },
        &existing,
        &blobs,
    )?;
    let detail = if capture.result.reused_executions.is_empty() {
        "release dependency evidence recorded".into()
    } else {
        "verified release dependency evidence reused".into()
    };
    Ok(PreparedSource {
        corpus: capture.corpus,
        executions: capture.executions,
        invocations: vec![],
        detail,
    })
}

fn recorded_revision(corpus: &Corpus, release: &str) -> Result<Option<String>> {
    let revisions = corpus
        .observations
        .iter()
        .filter(|item| item.subject.qualifier("release") == Some(release))
        .filter_map(|item| item.subject.qualifier("revision"))
        .collect::<BTreeSet<_>>();
    match revisions.len() {
        0 => Ok(None),
        1 => Ok(revisions.into_iter().next().map(str::to_owned)),
        _ => Err(Error::Invalid(format!(
            "recorded state identifies multiple revisions for release {release}"
        ))),
    }
}

fn empty_corpus() -> Corpus {
    Corpus {
        collections: vec![],
        observations: vec![],
        schema_version: divinate::SCHEMA_VERSION.into(),
        sources: vec![],
    }
}

fn format_timestamp(value: time::OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format timestamp: {error}")))
}

fn current_evaluated_at(state: &std::path::Path) -> Result<Option<String>> {
    let path = state.join("assertions/current.json");
    if !path.exists() {
        return Ok(None);
    }
    let assertions: Vec<DerivedAssertion> = read_json(&path)?;
    Ok(assertions.first().map(|item| item.evaluated_at.clone()))
}

fn load_evaluation(state: &std::path::Path, label: &str) -> Result<Vec<DerivedAssertion>> {
    read_json(&state.join("assertions").join(format!("{label}.json")))
}

fn promote_current_evaluation(state: &std::path::Path, next: &str) -> Result<()> {
    let paths = [
        ("assertions", ".json"),
        ("assertions", ".contracts.json"),
        ("assertions", ".configuration.json"),
        ("dossiers", ".json"),
        ("dossiers", ".md"),
    ];
    for (directory, suffix) in paths {
        let next_path = state.join(directory).join(format!("{next}{suffix}"));
        if !next_path.is_file() {
            return Err(Error::Invalid(format!(
                "automatic evaluation did not produce {}",
                next_path.display()
            )));
        }
    }
    for (directory, suffix) in paths {
        let current = state.join(directory).join(format!("current{suffix}"));
        if current.is_file() {
            let previous = state.join(directory).join(format!("previous{suffix}"));
            std::fs::copy(&current, &previous).map_err(|source| Error::Io {
                path: previous,
                source,
            })?;
        }
    }
    for (directory, suffix) in paths {
        let next_path = state.join(directory).join(format!("{next}{suffix}"));
        let current = state.join(directory).join(format!("current{suffix}"));
        std::fs::copy(&next_path, &current).map_err(|source| Error::Io {
            path: current,
            source,
        })?;
        std::fs::remove_file(&next_path).map_err(|source| Error::Io {
            path: next_path,
            source,
        })?;
    }
    Ok(())
}

fn outcome_counts(assertions: &[DerivedAssertion]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::from([
        ("contradicted".into(), 0),
        ("insufficient evidence".into(), 0),
        ("not automatable".into(), 0),
        ("stale".into(), 0),
        ("supported".into(), 0),
    ]);
    for assertion in assertions {
        *counts
            .entry(outcome_label(assertion.outcome).into())
            .or_default() += 1;
    }
    counts
}

const fn outcome_label(outcome: assertions::Outcome) -> &'static str {
    match outcome {
        assertions::Outcome::Supported => "supported",
        assertions::Outcome::Contradicted => "contradicted",
        assertions::Outcome::InsufficientEvidence => "insufficient evidence",
        assertions::Outcome::Stale => "stale",
        assertions::Outcome::NotAutomatable => "not automatable",
    }
}

fn render_collection_report(report: &ProductCollectionReport) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Collected").map_err(stdout_error)?;
    for source in &report.sources {
        writeln!(
            out,
            "  {:<36} {} ({})",
            source.source, source.status, source.detail
        )
        .map_err(stdout_error)?;
    }
    writeln!(out, "\nEvaluation").map_err(stdout_error)?;
    for name in [
        "supported",
        "insufficient evidence",
        "contradicted",
        "stale",
        "not automatable",
    ] {
        writeln!(
            out,
            "  {name:<24} {}",
            report.outcomes.get(name).copied().unwrap_or_default()
        )
        .map_err(stdout_error)?;
    }
    writeln!(out, "\ndossier: {}", report.dossier).map_err(stdout_error)
}

fn list_collections(corpus_path: &std::path::Path, incomplete: bool) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    let runs = corpus
        .collections
        .iter()
        .filter(|run| !incomplete || run.outcome != CollectionOutcome::Complete)
        .collect::<Vec<_>>();
    print_json(&runs)
}

fn recover_source(corpus_path: &std::path::Path, evidence_id: &str) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    io::stdout()
        .write_all(source_bytes(&corpus, evidence_id)?)
        .map_err(stdout_error)
}

fn derive_assertions(
    corpus_path: &std::path::Path,
    target: TargetArgs,
    output: Option<&std::path::Path>,
) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    let (target, at) = evaluation(target)?;
    let derived = assertions::evaluate_all(&corpus, &target, at)?;
    output.map_or_else(|| print_json(&derived), |path| write_json(&derived, path))
}

fn query(
    corpus_path: &std::path::Path,
    revision: Option<&str>,
    tool: Option<&str>,
    kind: Option<Kind>,
) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    let observations = corpus
        .observations
        .iter()
        .filter(|item| matches_query(item, revision, tool, kind))
        .collect::<Vec<_>>();
    print_json(&observations)
}

fn generate_dossier(
    corpus_path: &std::path::Path,
    target: TargetArgs,
    acquisition_paths: &[PathBuf],
    markdown: &std::path::Path,
    json_output: &std::path::Path,
) -> Result<()> {
    let corpus = load_corpus(corpus_path)?;
    let (target, at) = evaluation(target)?;
    let assertions = assertions::evaluate_all(&corpus, &target, at)?;
    let acquisitions = acquisition_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<AcquisitionTranscript>>>()?;
    let dossier = dossier::build(&corpus, &assertions, &acquisitions, &target, at)?;
    write_json(&dossier, json_output)?;
    std::fs::write(markdown, dossier::render_markdown(&dossier)).map_err(|source| Error::Io {
        path: markdown.into(),
        source,
    })
}

fn record_state(
    state: &std::path::Path,
    increment_path: &std::path::Path,
    acquisition_paths: &[PathBuf],
) -> Result<()> {
    let increment = load_corpus(increment_path)?;
    let acquisitions = acquisition_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<AcquisitionTranscript>>>()?;
    let corpus = divinate::workflow::accumulate(state, &increment, &acquisitions)?;
    print_json(&serde_json::json!({
        "collections": corpus.collections.len(),
        "observations": corpus.observations.len(),
        "sources": corpus.sources.len(),
        "transcripts": divinate::workflow::load_transcripts(state)?.len(),
    }))
}

fn record_increment(
    state: &std::path::Path,
    increment: &divinate::model::Corpus,
    acquisition_paths: &[PathBuf],
) -> Result<()> {
    let acquisitions = acquisition_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<AcquisitionTranscript>>>()?;
    let corpus = divinate::workflow::accumulate(state, increment, &acquisitions)?;
    print_json(&serde_json::json!({
        "collections": corpus.collections.len(),
        "observations": corpus.observations.len(),
        "sources": corpus.sources.len(),
        "acquisitions": divinate::workflow::load_transcripts(state)?.len(),
        "executions": divinate::workflow::load_executions(state)?.len(),
    }))
}

fn commit_collections(
    state: &std::path::Path,
    increment: &Corpus,
    executions: &[divinate::execution::ExecutionCapture],
    invocations: &[divinate::pack::PackCapture],
) -> Result<Corpus> {
    preflight_collections(state, increment, executions, invocations)?;
    divinate::workflow::store_pack_invocations(state, invocations)?;
    divinate::workflow::accumulate_with_executions(state, increment, &[], executions)
}

fn preflight_collections(
    state: &std::path::Path,
    increment: &Corpus,
    captures: &[divinate::execution::ExecutionCapture],
    pack_captures: &[divinate::pack::PackCapture],
) -> Result<()> {
    let corpus_path = divinate::workflow::corpus_path(state);
    let base = if corpus_path.exists() {
        load_corpus(&corpus_path)?
    } else {
        Corpus {
            collections: vec![],
            observations: vec![],
            schema_version: divinate::SCHEMA_VERSION.into(),
            sources: vec![],
        }
    };
    let merged = divinate::workflow::merge(&base, increment)?;
    let acquisitions = divinate::workflow::load_transcripts(state)?;
    let registry = divinate::workflow::load_registry(state)?;
    divinate::provenance::verify_collection_links(&merged, &acquisitions, &registry)?;

    let mut blobs = divinate::workflow::load_blobs(state)?;
    let mut executions = divinate::workflow::load_executions(state)?;
    for capture in captures {
        execution::verify(&capture.transcript, &capture.blobs)?;
        merge_blob_bytes(&mut blobs, &capture.blobs)?;
        merge_execution(&mut executions, &capture.transcript)?;
    }
    for capture in pack_captures {
        let digest = divinate::hex_digest(&capture.executable_bytes);
        if let Some(existing) = blobs.get(&digest) {
            if existing != &capture.executable_bytes {
                return Err(Error::Invalid(format!("blob collision: {digest}")));
            }
        } else {
            blobs.insert(digest, capture.executable_bytes.clone());
        }
    }
    divinate::provenance::verify_execution_links(&merged, &executions, &blobs)?;

    let mut invocations = divinate::workflow::load_pack_invocations(state)?;
    for capture in pack_captures {
        divinate::pack::verify(&capture.invocation, &blobs)?;
        if let Some(existing) = invocations
            .iter()
            .find(|item| item.id == capture.invocation.id)
        {
            if existing != &capture.invocation {
                return Err(Error::Invalid(format!(
                    "pack invocation id collision: {}",
                    capture.invocation.id
                )));
            }
        } else {
            invocations.push(capture.invocation.clone());
        }
    }
    divinate::pack::verify_observation_links(&merged, &invocations, &executions, &blobs)
}

fn merge_blob_bytes(
    target: &mut BTreeMap<String, Vec<u8>>,
    additions: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for (digest, bytes) in additions {
        if let Some(existing) = target.get(digest) {
            if existing != bytes {
                return Err(Error::Invalid(format!("blob collision: {digest}")));
            }
        } else {
            target.insert(digest.clone(), bytes.clone());
        }
    }
    Ok(())
}

fn merge_execution(
    executions: &mut Vec<divinate::execution::ExecutionTranscript>,
    addition: &divinate::execution::ExecutionTranscript,
) -> Result<()> {
    if let Some(existing) = executions.iter().find(|item| item.id == addition.id) {
        if existing != addition {
            return Err(Error::Invalid(format!(
                "execution id collision: {}",
                addition.id
            )));
        }
    } else {
        executions.push(addition.clone());
    }
    Ok(())
}

fn collect_release(args: ReleaseArgs) -> Result<()> {
    let repository = divinate::release::repository_identity(&args.repository_path)?;
    divinate::workflow::ensure_repository_identity(&args.state, &repository)?;
    let existing = divinate::workflow::load_executions(&args.state).map_err(provenance_error)?;
    let blobs = divinate::workflow::load_blobs(&args.state).map_err(provenance_error)?;
    let capture = divinate::release::collect(
        &divinate::release::ReleaseRequest {
            repository,
            repository_path: args.repository_path,
            base_release: args.base_release,
            release: args.release,
            expected_base_revision: args.base_revision,
            expected_revision: args.revision,
            base_sbom: args.base_sbom,
            target_sbom: args.target_sbom,
            executable: args.sbom_diff,
            reported_version: args.tool_version,
            policy_id: args.policy,
            fail_on: args.fail_on,
            force: args.force,
        },
        &existing,
        &blobs,
    )?;
    divinate::workflow::accumulate_with_executions(
        &args.state,
        &capture.corpus,
        &[],
        &capture.executions,
    )
    .map_err(provenance_error)?;
    print_json(&capture.result)
}

fn inspect_pack(repository_path: &std::path::Path, id: &str) -> Result<()> {
    let config = divinate::project::load(repository_path)?
        .config
        .packs
        .remove(id)
        .ok_or_else(|| Error::Invalid(format!("pack {id:?} is not configured")))?;
    let (metadata, capture) = divinate::pack::describe(&config)?;
    if metadata.id != id {
        return Err(Error::Invalid(format!(
            "configured pack {id:?} identifies itself as {:?}",
            metadata.id
        )));
    }
    print_json(&serde_json::json!({
        "metadata": metadata,
        "executable_sha256": capture.invocation.contents.executable.sha256,
    }))
}

fn list_packs(repository_path: &std::path::Path) -> Result<()> {
    let project = divinate::project::load(repository_path)?;
    let config = project.config;
    let mut packs = Vec::new();
    for (id, pack_config) in config.packs {
        let (metadata, capture) = divinate::pack::describe(&pack_config)?;
        if metadata.id != id {
            return Err(Error::Invalid(format!(
                "configured pack {id:?} identifies itself as {:?}",
                metadata.id
            )));
        }
        packs.push(serde_json::json!({
            "metadata": metadata,
            "executable_sha256": capture.invocation.contents.executable.sha256,
        }));
    }
    print_json(&packs)
}

fn collect_pack(
    state: &std::path::Path,
    repository_path: &std::path::Path,
    id: &str,
    collector: &str,
    context: Option<&std::path::Path>,
) -> Result<()> {
    let context = context.map_or_else(|| Ok(serde_json::Value::Null), read_json)?;
    let project = divinate::project::load(repository_path)?;
    divinate::workflow::ensure_repository_identity(state, &project.config.repository)?;
    let config = project
        .config
        .packs
        .get(id)
        .ok_or_else(|| Error::Invalid(format!("pack {id:?} is not configured")))?;
    let prepared = prepare_pack_collection(config, id, collector, &context)?;
    commit_collections(
        state,
        &prepared.corpus,
        std::slice::from_ref(&prepared.execution),
        &prepared.invocations,
    )?;
    print_json(&serde_json::json!({
        "pack": prepared.pack,
        "collector": prepared.collector,
        "observation": prepared.observation,
    }))
}

fn prepare_pack_collection(
    config: &divinate::pack::PackConfig,
    id: &str,
    collector: &str,
    context: &serde_json::Value,
) -> Result<PreparedPackCollection> {
    let (metadata, described) = divinate::pack::describe(config)?;
    if metadata.id != id {
        return Err(Error::Invalid(format!(
            "configured pack {id:?} identifies itself as {:?}",
            metadata.id
        )));
    }
    let (plan, planned) = divinate::pack::plan(config, &metadata, collector, context)?;
    let execution =
        execution::capture(&plan.command.execution_request()).map_err(collection_error)?;
    let planned =
        divinate::pack::bind_execution(planned, &execution.transcript).map_err(provenance_error)?;
    let source_bytes = execution::stdout_bytes(&execution.transcript)?;
    let source_content = String::from_utf8(source_bytes.clone())
        .map_err(|_| Error::Invalid("pack collector output is not utf-8".into()))?;
    let source_digest = divinate::hex_digest(&source_bytes);
    let source = divinate::model::SourceDocument {
        content: source_content,
        format: plan.adapter.clone(),
        id: format!("src_{}", &source_digest[..20]),
        media_type: "application/json".into(),
        path: format!("execution:{}:stdout", execution.transcript.id),
        sha256: source_digest.clone(),
    };
    let (normalized, normalization) = divinate::pack::normalize(
        config,
        &metadata,
        &plan.adapter,
        &source_bytes,
        &source_digest,
        &plan.subject,
    )?;
    let mut observation = divinate::pack::observation(
        normalized,
        &metadata,
        &normalization.invocation,
        &source,
        plan.subject,
        plan.observed_at,
        execution.transcript.id.clone(),
    )?;
    observation.pack_invocation_ids = vec![
        described.invocation.id.clone(),
        planned.invocation.id.clone(),
        normalization.invocation.id.clone(),
    ];
    let observation_id = observation.id.clone();
    let corpus = Corpus {
        collections: vec![],
        observations: vec![observation],
        schema_version: divinate::SCHEMA_VERSION.into(),
        sources: vec![source],
    };
    Ok(PreparedPackCollection {
        pack: metadata.id,
        collector: collector.into(),
        observation: observation_id,
        corpus,
        invocations: vec![described, planned, normalization],
        execution,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_tool(
    state: &std::path::Path,
    tool: String,
    tool_version: Option<String>,
    inputs: &[NamedPathArg],
    outputs: &[NamedPathArg],
    environment: Vec<(String, String)>,
    working_directory: Option<PathBuf>,
    stdout_path: Option<&std::path::Path>,
    executable: PathBuf,
    argv: Vec<String>,
) -> Result<()> {
    let capture = execution::capture(&ExecutionRequest {
        tool_name: tool,
        reported_version: tool_version,
        executable,
        argv,
        working_directory,
        environment: environment.into_iter().collect(),
        inputs: inputs
            .iter()
            .map(|item| NamedPath {
                name: item.name.clone(),
                path: item.path.clone(),
            })
            .collect(),
        outputs: outputs
            .iter()
            .map(|item| NamedPath {
                name: item.name.clone(),
                path: item.path.clone(),
            })
            .collect(),
    })
    .map_err(collection_error)?;
    divinate::workflow::store_execution(state, &capture).map_err(provenance_error)?;
    if let Some(path) = stdout_path {
        let bytes = execution::stdout_bytes(&capture.transcript)?;
        std::fs::write(path, bytes).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    print_json(&serde_json::json!({
        "execution": capture.transcript.id,
        "exit_code": capture.transcript.contents.exit.code,
        "success": capture.transcript.contents.exit.success,
        "stdout_sha256": capture.transcript.contents.stdout.sha256,
    }))
}

#[allow(clippy::too_many_lines)]
fn evaluate_state(
    state: &std::path::Path,
    repository_path: &std::path::Path,
    label: &str,
    contracts: Option<&std::path::Path>,
    target: TargetArgs,
) -> Result<()> {
    let project = divinate::project::load(repository_path)?;
    divinate::workflow::ensure_repository_identity(state, &project.config.repository)?;
    divinate::workflow::store_project_configuration(state, &project.sha256, &project.bytes)?;
    evaluate_state_with_skips(
        state,
        &project.config,
        Some(&project.sha256),
        label,
        contracts,
        target,
        &BTreeSet::new(),
    )
}

#[allow(clippy::too_many_lines)]
fn evaluate_state_with_skips(
    state: &std::path::Path,
    project: &divinate::workflow::ProjectConfig,
    project_config_sha256: Option<&str>,
    label: &str,
    contracts: Option<&std::path::Path>,
    target: TargetArgs,
    unavailable_optional_packs: &BTreeSet<String>,
) -> Result<()> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Invalid(
            "evaluation label must contain only letters, numbers, '-' or '_'".into(),
        ));
    }
    let corpus = load_corpus(&divinate::workflow::corpus_path(state))?;
    let at = target.at.as_ref().map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(value),
    )?;
    let transcripts = divinate::workflow::load_transcripts(state)?;
    let executions = divinate::workflow::load_executions(state)?;
    let blobs = divinate::workflow::load_blobs(state).map_err(provenance_error)?;
    divinate::provenance::verify_execution_links(&corpus, &executions, &blobs)
        .map_err(provenance_error)?;
    let registry = contracts.map_or_else(|| divinate::workflow::load_registry(state), read_json)?;
    divinate::provenance::verify_collection_links(&corpus, &transcripts, &registry)
        .map_err(provenance_error)?;
    let pack_invocations = divinate::workflow::load_pack_invocations(state)?;
    divinate::pack::verify_observation_links(&corpus, &pack_invocations, &executions, &blobs)
        .map_err(provenance_error)?;
    let historical =
        divinate::workflow::as_of_with_provenance(&corpus, &transcripts, &executions, at)?;
    let target = evaluation_in_project(project, &historical.corpus, target, at)?;
    divinate::provenance::verify_execution_links(
        &historical.corpus,
        &historical.executions,
        &blobs,
    )
    .map_err(provenance_error)?;
    let current = divinate::provenance::with_current_authority(
        &historical.corpus,
        &historical.acquisitions,
        &registry,
    )
    .map_err(provenance_error)?;
    let mut assertions = assertions::evaluate_all(&current, &target, at)?;
    let evaluated_at = assertions
        .first()
        .map(|assertion| assertion.evaluated_at.clone())
        .ok_or_else(|| Error::Invalid("core evaluation returned no assertions".into()))?;
    let mut pack_captures = Vec::new();
    for (configured_id, config) in &project.packs {
        if unavailable_optional_packs.contains(configured_id) {
            continue;
        }
        let (metadata, described) = divinate::pack::describe(config)?;
        if metadata.id != *configured_id {
            return Err(Error::Invalid(format!(
                "configured pack {configured_id:?} identifies itself as {:?}",
                metadata.id
            )));
        }
        if !metadata.evaluators.is_empty() {
            pack_captures.push(described);
        }
        for evaluator in &metadata.evaluators {
            let (mut derived, capture) = divinate::pack::evaluate(
                config,
                &metadata,
                evaluator,
                &current,
                &target,
                &evaluated_at,
            )?;
            pack_captures.push(capture);
            assertions.append(&mut derived);
        }
    }
    let mut assertion_ids = BTreeSet::new();
    if let Some(duplicate) = assertions
        .iter()
        .find(|assertion| !assertion_ids.insert(assertion.id.as_str()))
    {
        return Err(Error::Invalid(format!(
            "duplicate assertion id: {}",
            duplicate.id
        )));
    }
    divinate::workflow::store_pack_invocations(state, &pack_captures)?;
    let pack_invocations = divinate::workflow::load_pack_invocations(state)?;
    let pack_blobs = divinate::workflow::load_blobs(state)?;
    divinate::pack::verify_assertion_links(&assertions, &pack_invocations, &pack_blobs)?;
    let dossier = dossier::build_with_registry(
        &current,
        &assertions,
        &historical.acquisitions,
        &registry,
        &target,
        at,
    )?;
    write_json(
        &assertions,
        &state.join("assertions").join(format!("{label}.json")),
    )?;
    write_json(
        &registry,
        &state
            .join("assertions")
            .join(format!("{label}.contracts.json")),
    )?;
    if let Some(sha256) = project_config_sha256 {
        write_json(
            &divinate::workflow::EvaluationConfiguration {
                project_config_sha256: sha256.into(),
            },
            &state
                .join("assertions")
                .join(format!("{label}.configuration.json")),
        )?;
    }
    write_json(
        &dossier,
        &state.join("dossiers").join(format!("{label}.json")),
    )?;
    let markdown = state.join("dossiers").join(format!("{label}.md"));
    std::fs::write(&markdown, dossier::render_markdown(&dossier)).map_err(|source| Error::Io {
        path: markdown,
        source,
    })
}

#[allow(clippy::too_many_lines)]
fn state_status(
    state: &std::path::Path,
    repository_path: &std::path::Path,
    json: bool,
) -> Result<()> {
    let project = divinate::project::load(repository_path)?;
    let current_config_sha256 = project.sha256;
    let config = project.config;
    let corpus_path = divinate::workflow::corpus_path(state);
    let corpus = if corpus_path.is_file() {
        load_corpus(&corpus_path)?
    } else {
        empty_corpus()
    };
    let current_path = state.join("assertions/current.json");
    let current = if current_path.is_file() {
        load_evaluation(state, "current")?
    } else {
        vec![]
    };
    let previous_path = state.join("assertions/previous.json");
    let previous = if previous_path.is_file() {
        Some(load_evaluation(state, "previous")?)
    } else {
        None
    };
    let mut evidence_sources = BTreeMap::new();
    for observation in &corpus.observations {
        *evidence_sources
            .entry(format!(
                "{} / {}",
                observation.producer.name, observation.producer.collector
            ))
            .or_default() += 1;
    }
    let cycles = divinate::workflow::load_collection_cycles(state)?;
    let latest_cycle = cycles.iter().max_by(|left, right| {
        left.contents
            .completed_at
            .cmp(&right.contents.completed_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    let historical_source_ids = cycles
        .iter()
        .flat_map(|cycle| cycle.contents.sources.keys())
        .collect::<BTreeSet<_>>();
    let mut configured_sources = config
        .sources
        .iter()
        .map(|(id, source)| {
            let latest = latest_cycle
                .filter(|cycle| cycle.contents.project_config_sha256 == current_config_sha256)
                .and_then(|cycle| cycle.contents.sources.get(id));
            let (state, detail) = if let Some(result) = latest {
                let state = match result.status.as_str() {
                    "complete" => "current",
                    value => value,
                };
                (state.into(), Some(result.detail.clone()))
            } else if historical_source_ids.contains(id) {
                ("stale".into(), None)
            } else {
                ("never collected".into(), None)
            };
            ConfiguredSourceStatus {
                source: id.clone(),
                required: Some(source.required),
                state,
                detail,
            }
        })
        .collect::<Vec<_>>();
    for id in historical_source_ids {
        if !config.sources.contains_key(id) {
            configured_sources.push(ConfiguredSourceStatus {
                source: id.clone(),
                required: None,
                state: "removed".into(),
                detail: None,
            });
        }
    }
    configured_sources.sort_by(|left, right| left.source.cmp(&right.source));
    let degraded_collections = corpus
        .collections
        .iter()
        .filter(|run| run.outcome != CollectionOutcome::Complete)
        .map(|run| DegradedCollection {
            collector: format!("{} / {}", run.collector.name, run.collector.collector),
            outcome: collection_outcome_label(run.outcome).into(),
            limitations: run
                .limitations
                .iter()
                .map(|limitation| limitation.detail.clone())
                .collect(),
        })
        .collect();
    let unresolved_gaps = current
        .iter()
        .flat_map(|assertion| assertion.missing.iter())
        .map(|missing| missing.requirement.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let since_previous = previous.as_ref().map(|previous| {
        let update = divinate::views::isms_update(previous, &current);
        StatusChanges {
            claims_changed: update.changes.len(),
            new_gaps: update.new_gaps.len(),
            coverage_regressions: update.coverage_regressions.len(),
        }
    });
    let collected_times = corpus
        .observations
        .iter()
        .map(|observation| observation.observed_at.as_str())
        .chain(
            corpus
                .collections
                .iter()
                .map(|collection| collection.completed_at.as_str()),
        )
        .chain(
            cycles
                .iter()
                .map(|cycle| cycle.contents.completed_at.as_str()),
        )
        .collect::<Vec<_>>();
    let report = StatusReport {
        repository: config.repository,
        branch: config.branch,
        last_collected: latest_timestamp(&collected_times)?,
        last_evaluated: current.first().map(|item| item.evaluated_at.clone()),
        outcomes: outcome_counts(&current),
        evidence_sources,
        configured_sources,
        degraded_collections,
        unresolved_gaps,
        since_previous,
    };
    if json {
        print_json(&report)
    } else {
        render_status(&report)
    }
}

fn latest_timestamp(values: &[&str]) -> Result<Option<String>> {
    let mut latest = None;
    for value in values {
        let parsed = parse_timestamp(value)?;
        if latest
            .as_ref()
            .is_none_or(|(current, _): &(time::OffsetDateTime, String)| parsed > *current)
        {
            latest = Some((parsed, (*value).to_owned()));
        }
    }
    Ok(latest.map(|(_, value)| value))
}

const fn collection_outcome_label(outcome: CollectionOutcome) -> &'static str {
    match outcome {
        CollectionOutcome::Complete => "complete",
        CollectionOutcome::Partial => "partial",
        CollectionOutcome::PermissionDenied => "permission denied",
        CollectionOutcome::RetentionLimited => "retention limited",
        CollectionOutcome::Interrupted => "interrupted",
        CollectionOutcome::Failed => "failed",
        CollectionOutcome::NotAttempted => "not attempted",
    }
}

fn render_status(report: &StatusReport) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Repository      {}", report.repository).map_err(stdout_error)?;
    writeln!(out, "Branch          {}", report.branch).map_err(stdout_error)?;
    writeln!(
        out,
        "Last collected  {}",
        report.last_collected.as_deref().unwrap_or("not collected")
    )
    .map_err(stdout_error)?;
    writeln!(
        out,
        "Last evaluated  {}",
        report.last_evaluated.as_deref().unwrap_or("not evaluated")
    )
    .map_err(stdout_error)?;
    writeln!(out, "\nSources").map_err(stdout_error)?;
    if report.configured_sources.is_empty() {
        writeln!(out, "  none configured").map_err(stdout_error)?;
    } else {
        for source in &report.configured_sources {
            let requirement =
                source.required.map_or(
                    "",
                    |required| {
                        if required {
                            "required"
                        } else {
                            "optional"
                        }
                    },
                );
            writeln!(
                out,
                "  {:<28} {:<18} {}",
                source.source, source.state, requirement
            )
            .map_err(stdout_error)?;
            if source.state != "current" {
                if let Some(detail) = &source.detail {
                    writeln!(out, "    {detail}").map_err(stdout_error)?;
                }
            }
        }
    }
    writeln!(out, "\nClaims").map_err(stdout_error)?;
    for name in [
        "supported",
        "insufficient evidence",
        "contradicted",
        "stale",
        "not automatable",
    ] {
        writeln!(
            out,
            "  {name:<24} {}",
            report.outcomes.get(name).copied().unwrap_or_default()
        )
        .map_err(stdout_error)?;
    }
    writeln!(out, "\nEvidence").map_err(stdout_error)?;
    if report.evidence_sources.is_empty() {
        writeln!(out, "  not collected").map_err(stdout_error)?;
    } else {
        for (source, count) in &report.evidence_sources {
            writeln!(out, "  {source:<36} {count}").map_err(stdout_error)?;
        }
    }
    writeln!(
        out,
        "  unresolved evidence gaps             {}",
        report.unresolved_gaps
    )
    .map_err(stdout_error)?;
    if report.degraded_collections.is_empty() {
        writeln!(out, "  degraded collections                 0").map_err(stdout_error)?;
    } else {
        writeln!(out, "  degraded collections").map_err(stdout_error)?;
        for collection in &report.degraded_collections {
            writeln!(out, "    {}  {}", collection.collector, collection.outcome)
                .map_err(stdout_error)?;
            for limitation in &collection.limitations {
                writeln!(out, "      {limitation}").map_err(stdout_error)?;
            }
        }
    }
    if let Some(changes) = &report.since_previous {
        writeln!(out, "\nSince previous evaluation").map_err(stdout_error)?;
        writeln!(out, "  claims changed          {}", changes.claims_changed)
            .map_err(stdout_error)?;
        writeln!(out, "  new evidence gaps       {}", changes.new_gaps).map_err(stdout_error)?;
        writeln!(
            out,
            "  coverage regressions    {}",
            changes.coverage_regressions
        )
        .map_err(stdout_error)?;
    }
    Ok(())
}

fn state_review(
    state: &std::path::Path,
    previous: Option<&str>,
    current: &str,
    label: &str,
    json: bool,
) -> Result<()> {
    let previous = match previous {
        Some(previous) => previous,
        None if current == "current" && state.join("assertions/previous.json").is_file() => {
            "previous"
        }
        None => {
            return Err(Error::Invalid(format!(
                "cannot determine previous evaluation for {current}; choose one with --since"
            )));
        }
    };
    require_evaluation(state, previous)?;
    require_evaluation(state, current)?;
    let previous: Vec<DerivedAssertion> =
        read_json(&state.join("assertions").join(format!("{previous}.json")))?;
    let current: Vec<DerivedAssertion> =
        read_json(&state.join("assertions").join(format!("{current}.json")))?;
    let update = divinate::views::isms_update(&previous, &current);
    write_view(
        state,
        label,
        &update,
        &divinate::views::render_isms(&update),
    )?;
    if json {
        print_json(&update)
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Review").map_err(stdout_error)?;
        writeln!(out, "  claims changed          {}", update.changes.len())
            .map_err(stdout_error)?;
        writeln!(out, "  new evidence gaps       {}", update.new_gaps.len())
            .map_err(stdout_error)?;
        writeln!(
            out,
            "  coverage regressions    {}",
            update.coverage_regressions.len()
        )
        .map_err(stdout_error)?;
        writeln!(
            out,
            "\nreview: {}",
            state.join("views").join(format!("{label}.md")).display()
        )
        .map_err(stdout_error)
    }
}

fn state_dd(state: &std::path::Path, evaluation: &str, label: &str, json: bool) -> Result<()> {
    require_evaluation(state, evaluation)?;
    let assertions: Vec<DerivedAssertion> =
        read_json(&state.join("assertions").join(format!("{evaluation}.json")))?;
    let response = divinate::views::dd_response(&assertions);
    write_view(
        state,
        label,
        &response,
        &divinate::views::render_dd(&response),
    )?;
    if json {
        print_json(&response)
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Exported").map_err(stdout_error)?;
        writeln!(out, "  claims  {}", response.claims.len()).map_err(stdout_error)?;
        writeln!(
            out,
            "\nresponse: {}",
            state.join("views").join(format!("{label}.md")).display()
        )
        .map_err(stdout_error)
    }
}

fn write_view<T: serde::Serialize>(
    state: &std::path::Path,
    label: &str,
    value: &T,
    markdown: &str,
) -> Result<()> {
    write_json(value, &state.join("views").join(format!("{label}.json")))?;
    let path = state.join("views").join(format!("{label}.md"));
    std::fs::write(&path, markdown).map_err(|source| Error::Io { path, source })
}

fn compare_acquisitions(left: &std::path::Path, right: &std::path::Path) -> Result<()> {
    let left: AcquisitionTranscript = read_json(left)?;
    let right: AcquisitionTranscript = read_json(right)?;
    print_json(&acquisition::compare(&left, &right))
}

fn capture_github(args: CaptureArgs) -> Result<()> {
    parse_timestamp(&args.from)?;
    parse_timestamp(&args.until)?;
    let captured_at = args.at.map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(&value),
    )?;
    let transcript = acquisition::capture_github_commits(&GithubCapture {
        repository: args.repository,
        branch: args.branch,
        interval: divinate::model::TimeRange {
            from: args.from,
            until: args.until,
        },
        per_page: args.per_page,
        max_pages: args.max_pages,
        captured_at,
    })?;
    write_json(&transcript, &args.output)
}

fn capture_branch_protection(args: CaptureBranchArgs) -> Result<()> {
    parse_timestamp(&args.from)?;
    parse_timestamp(&args.until)?;
    let captured_at = args.at.map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(&value),
    )?;
    let transcript =
        acquisition::capture_github_branch_protection(&GithubBranchProtectionCapture {
            repository: args.repository,
            branch: args.branch,
            interval: divinate::model::TimeRange {
                from: args.from,
                until: args.until,
            },
            captured_at,
        })?;
    write_json(&transcript, &args.output)
}

fn acquisition_source(
    path: &std::path::Path,
    exchange: usize,
    output: &std::path::Path,
) -> Result<()> {
    let transcript: AcquisitionTranscript = read_json(path)?;
    let body = transcript
        .contents
        .exchanges
        .get(exchange)
        .ok_or_else(|| Error::Invalid(format!("acquisition has no exchange {exchange}")))?
        .response
        .body
        .as_bytes();
    std::fs::write(output, body).map_err(|source| Error::Io {
        path: output.into(),
        source,
    })
}

fn replay_acquisition(
    path: &std::path::Path,
    invalidate_at: Option<String>,
    invalidate_reason: Option<String>,
) -> Result<()> {
    let transcript: AcquisitionTranscript = read_json(path)?;
    let mut registry = ContractRegistry::default();
    if let Some(discovered_at) = invalidate_at {
        parse_timestamp(&discovered_at)?;
        registry.invalidations.push(ContractInvalidation {
            contract: GITHUB_COMMITS_CONTRACT.into(),
            discovered_at,
            reason: invalidate_reason.unwrap_or_else(|| {
                "collector contract no longer establishes exhaustive enumeration".into()
            }),
        });
    }
    print_json(&acquisition::assess(&transcript, &registry))
}

fn evaluation(args: TargetArgs) -> Result<(EvaluationTarget, time::OffsetDateTime)> {
    let at = args.at.map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(&value),
    )?;
    Ok((
        EvaluationTarget {
            repository: args.repository.ok_or_else(|| {
                Error::Invalid("--repository is required outside repository-local state".into())
            })?,
            branch: args.branch.unwrap_or_else(|| "main".into()),
            release: args.release.ok_or_else(|| {
                Error::Invalid("--release is required outside repository-local state".into())
            })?,
            from: args.from,
            until: args.until,
        },
        at,
    ))
}

fn evaluation_in_project(
    config: &divinate::workflow::ProjectConfig,
    corpus: &divinate::model::Corpus,
    args: TargetArgs,
    at: time::OffsetDateTime,
) -> Result<EvaluationTarget> {
    Ok(EvaluationTarget {
        repository: args.repository.unwrap_or_else(|| config.repository.clone()),
        branch: args.branch.unwrap_or_else(|| config.branch.clone()),
        release: args
            .release
            .map_or_else(|| divinate::workflow::latest_release(corpus, at), Ok)?,
        from: args.from,
        until: args.until,
    })
}

fn verify_state(state: &std::path::Path) -> Result<()> {
    let corpus = load_corpus(&divinate::workflow::corpus_path(state))?;
    let acquisitions = divinate::workflow::load_transcripts(state).map_err(provenance_error)?;
    let executions = divinate::workflow::load_executions(state).map_err(provenance_error)?;
    let blobs = divinate::workflow::load_blobs(state).map_err(provenance_error)?;
    let registry = divinate::workflow::load_registry(state)?;
    let acquisition_links =
        divinate::provenance::verify_collection_links(&corpus, &acquisitions, &registry)
            .map_err(provenance_error)?;
    let execution_links =
        divinate::provenance::verify_execution_links(&corpus, &executions, &blobs)
            .map_err(provenance_error)?;
    for transcript in &executions {
        execution::verify(transcript, &blobs).map_err(provenance_error)?;
    }
    let pack_invocations = divinate::workflow::load_pack_invocations(state)?;
    divinate::pack::verify_observation_links(&corpus, &pack_invocations, &executions, &blobs)
        .map_err(provenance_error)?;
    for invocation in &pack_invocations {
        divinate::pack::verify(invocation, &blobs).map_err(provenance_error)?;
    }
    let configured_cycles = divinate::workflow::verify_configuration_provenance(
        state,
        &corpus,
        &executions,
        &pack_invocations,
    )
    .map_err(provenance_error)?;
    print_json(&serde_json::json!({
        "status": "verified",
        "acquisition_transcripts": acquisitions.len(),
        "collection_acquisition_links": acquisition_links.len(),
        "execution_transcripts": executions.len(),
        "observation_execution_links": execution_links.len(),
        "pack_invocations": pack_invocations.len(),
        "configured_collection_cycles": configured_cycles,
        "content_blobs": blobs.len(),
    }))
}

#[allow(clippy::too_many_lines)]
fn show_provenance(state: &std::path::Path, evaluation: &str, assertion_id: &str) -> Result<()> {
    let corpus = load_corpus(&divinate::workflow::corpus_path(state))?;
    let assertions: Vec<DerivedAssertion> =
        read_json(&state.join("assertions").join(format!("{evaluation}.json")))?;
    let assertion = assertions
        .iter()
        .find(|assertion| assertion.id == assertion_id)
        .ok_or_else(|| Error::Invalid(format!("unknown assertion id: {assertion_id}")))?;
    let configuration_path = state
        .join("assertions")
        .join(format!("{evaluation}.configuration.json"));
    let evaluation_configuration = if configuration_path.is_file() {
        Some(read_json::<divinate::workflow::EvaluationConfiguration>(
            &configuration_path,
        )?)
    } else {
        None
    };
    let cycles = divinate::workflow::load_collection_cycles(state)?;
    let evidence_ids = assertion
        .support
        .iter()
        .chain(&assertion.contradictions)
        .chain(&assertion.considered)
        .map(|evidence| evidence.observation_id.as_str())
        .collect::<BTreeSet<_>>();
    let acquisitions = divinate::workflow::load_transcripts(state)?;
    let executions = divinate::workflow::load_executions(state)?;
    let blobs = divinate::workflow::load_blobs(state)?;
    let pack_invocations = divinate::workflow::load_pack_invocations(state)?;
    divinate::pack::verify_assertion_links(&assertions, &pack_invocations, &blobs)?;
    let execution_links =
        divinate::provenance::verify_execution_links(&corpus, &executions, &blobs)?;
    let observations = corpus
        .observations
        .iter()
        .filter(|observation| evidence_ids.contains(observation.id.as_str()))
        .map(|observation| {
            let uses = assertion
                .support
                .iter()
                .filter(|item| item.observation_id == observation.id)
                .map(|item| serde_json::json!({"role": "support", "reason": item.reason}))
                .chain(
                    assertion
                        .contradictions
                        .iter()
                        .filter(|item| item.observation_id == observation.id)
                        .map(|item| {
                            serde_json::json!({"role": "contradiction", "reason": item.reason})
                        }),
                )
                .chain(
                    assertion
                        .considered
                        .iter()
                        .filter(|item| item.observation_id == observation.id)
                        .map(|item| serde_json::json!({"role": "considered", "reason": item.reason})),
                )
                .collect::<Vec<_>>();
            let source = corpus
                .sources
                .iter()
                .find(|source| source.id == observation.provenance.source_id)
                .expect("validated corpus source");
            let collection = observation.collection_run_id.as_ref().and_then(|run_id| {
                corpus
                    .collections
                    .iter()
                    .find(|run| &run.id == run_id)
                    .map(|run| serde_json::json!({
                        "id": run.id,
                        "outcome": run.outcome,
                        "acquisition_transcripts": run.acquisition_transcript_ids.iter().filter_map(|id| acquisitions.iter().find(|item| &item.id == id)).map(|item| serde_json::json!({
                            "id": item.id,
                            "contract": item.contents.collector_contract,
                            "responses": item.contents.exchanges.iter().map(|exchange| &exchange.response.body_sha256).collect::<Vec<_>>()
                        })).collect::<Vec<_>>()
                    }))
            });
            let local = execution_links
                .iter()
                .filter(|link| link.observation_id == observation.id)
                .filter_map(|link| executions.iter().find(|item| item.id == link.execution_transcript_id).map(|item| serde_json::json!({
                    "id": item.id,
                    "tool": item.contents.tool,
                    "argv": item.contents.argv,
                    "inputs": item.contents.inputs,
                    "exit": item.contents.exit,
                    "output": link.output,
                    "stdout_sha256": item.contents.stdout.sha256,
                    "stderr_sha256": item.contents.stderr.sha256
                })))
                .collect::<Vec<_>>();
            let packs = observation
                .pack_invocation_ids
                .iter()
                .filter_map(|id| pack_invocations.iter().find(|item| &item.id == id))
                .map(|item| serde_json::json!({
                    "id": item.id,
                    "pack": item.contents.pack_id,
                    "version": item.contents.pack_version,
                    "executable_sha256": item.contents.executable.sha256,
                    "operation": item.contents.operation,
                    "request_sha256": item.contents.request_sha256,
                    "response_sha256": item.contents.response_sha256,
                }))
                .collect::<Vec<_>>();
            let project_configurations = cycles
                .iter()
                .filter(|cycle| {
                    cycle
                        .contents
                        .observation_ids
                        .iter()
                        .any(|id| id == &observation.id)
                })
                .map(|cycle| &cycle.contents.project_config_sha256)
                .collect::<BTreeSet<_>>();
            serde_json::json!({
                "observation": observation.id,
                "uses": uses,
                "source": {"id": source.id, "sha256": source.sha256},
                "collection": collection,
                "executions": local,
                "pack_invocations": packs,
                "project_configurations": project_configurations,
            })
        })
        .collect::<Vec<_>>();
    print_json(&serde_json::json!({
        "assertion": {
            "id": assertion.id,
            "claim": assertion.claim,
            "outcome": assertion.outcome,
            "derivation": assertion.derivation,
            "project_config_sha256": evaluation_configuration.map(|item| item.project_config_sha256),
        },
        "observations": observations,
    }))
}

fn extract_stream(
    state: &std::path::Path,
    execution_id: &str,
    stream: Stream,
    output: &std::path::Path,
) -> Result<()> {
    let executions = divinate::workflow::load_executions(state).map_err(provenance_error)?;
    let blobs = divinate::workflow::load_blobs(state).map_err(provenance_error)?;
    let transcript = executions
        .iter()
        .find(|transcript| transcript.id == execution_id)
        .ok_or_else(|| Error::Provenance(format!("missing execution transcript {execution_id}")))?;
    execution::verify(transcript, &blobs).map_err(provenance_error)?;
    let bytes = match stream {
        Stream::Stdout => execution::stdout_bytes(transcript),
        Stream::Stderr => execution::stderr_bytes(transcript),
    }
    .map_err(provenance_error)?;
    std::fs::write(output, bytes).map_err(|source| Error::Io {
        path: output.to_path_buf(),
        source,
    })
}

fn parse_named_path(value: &str) -> std::result::Result<NamedPathArg, String> {
    let (name, path) = value
        .split_once('=')
        .ok_or_else(|| "expected NAME=PATH".to_owned())?;
    if name.is_empty() || path.is_empty() {
        return Err("expected non-empty NAME=PATH".into());
    }
    Ok(NamedPathArg {
        name: name.into(),
        path: path.into(),
    })
}

fn parse_metadata(value: &str) -> std::result::Result<(String, String), String> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| "expected NAME=VALUE".to_owned())?;
    if name.is_empty() {
        return Err("metadata name must not be empty".into());
    }
    Ok((name.into(), value.into()))
}

fn matches_query(
    observation: &Observation,
    revision: Option<&str>,
    tool: Option<&str>,
    kind: Option<Kind>,
) -> bool {
    revision.is_none_or(|revision| observation.subject.qualifier("revision") == Some(revision))
        && tool.is_none_or(|tool| observation.producer.name == tool)
        && kind.is_none_or(|kind| observation.kind == kind.into())
}

fn explain(assertion: &DerivedAssertion) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "assertion: {}", assertion.claim).map_err(stdout_error)?;
    writeln!(out, "id: {}", assertion.id).map_err(stdout_error)?;
    writeln!(out, "result: {:?}", assertion.outcome).map_err(stdout_error)?;
    writeln!(out, "evaluator: {}", assertion.derivation.version).map_err(stdout_error)?;
    explain_evidence(&mut out, "support", &assertion.support)?;
    explain_evidence(&mut out, "contradictions", &assertion.contradictions)?;
    explain_evidence(&mut out, "considered", &assertion.considered)?;
    if !assertion.coverage.is_empty() {
        writeln!(out, "coverage:").map_err(stdout_error)?;
        for decision in &assertion.coverage {
            writeln!(
                out,
                "  {:?}: {:?} for {} .. {}",
                decision.requirement.proposition,
                decision.outcome,
                decision.requirement.interval.from,
                decision.requirement.interval.until
            )
            .map_err(stdout_error)?;
            for run in &decision.collection_runs {
                writeln!(
                    out,
                    "    {}: {:?}: {}",
                    run.collection_run_id, run.disposition, run.reason
                )
                .map_err(stdout_error)?;
            }
            for gap in &decision.uncovered_intervals {
                writeln!(out, "    uncovered: {} .. {}", gap.from, gap.until)
                    .map_err(stdout_error)?;
            }
        }
    }
    if !assertion.missing.is_empty() {
        writeln!(out, "missing:").map_err(stdout_error)?;
        for item in &assertion.missing {
            writeln!(out, "  {}: {}", item.requirement, item.reason).map_err(stdout_error)?;
        }
    }
    if !assertion.identity_joins.is_empty() {
        writeln!(out, "identity joins:").map_err(stdout_error)?;
        for join in &assertion.identity_joins {
            writeln!(
                out,
                "  {} + {}: {:?}",
                join.left_observation_id, join.right_observation_id, join.fields
            )
            .map_err(stdout_error)?;
        }
    }
    if !assertion.limitations.is_empty() {
        writeln!(out, "limitations:").map_err(stdout_error)?;
        for limitation in &assertion.limitations {
            writeln!(out, "  {limitation}").map_err(stdout_error)?;
        }
    }
    Ok(())
}

fn explain_evidence(
    out: &mut impl Write,
    heading: &str,
    evidence: &[assertions::EvidenceUse],
) -> Result<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    writeln!(out, "{heading}:").map_err(stdout_error)?;
    for item in evidence {
        writeln!(
            out,
            "  {} -> {}: {}",
            item.observation_id, item.source_id, item.reason
        )
        .map_err(stdout_error)?;
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(Error::Serialize)?;
    writeln!(stdout).map_err(stdout_error)
}

fn stdout_error(source: io::Error) -> Error {
    Error::Io {
        path: PathBuf::from("<stdout>"),
        source,
    }
}

fn require_evaluation(state: &std::path::Path, label: &str) -> Result<()> {
    let path = state.join("assertions").join(format!("{label}.json"));
    if path.exists() {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "missing historical evaluation {label:?} in {}",
            state.display()
        )))
    }
}

fn collection_error(error: Error) -> Error {
    let message = error.to_string();
    drop(error);
    Error::Collection(message)
}

fn provenance_error(error: Error) -> Error {
    let message = error.to_string();
    drop(error);
    Error::Provenance(message)
}
