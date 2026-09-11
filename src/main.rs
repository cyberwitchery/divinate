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
use divinate::model::{CollectionOutcome, Observation, ObservationKind};
use divinate::{collect, load_corpus, parse_timestamp, read_json, source_bytes, write_json};

#[derive(Parser)]
#[command(about = "preserve technical security evidence and derive traceable claims")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// initialize local evidence state
    Init {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long)]
        repository: String,
        #[arg(long, default_value = "main")]
        branch: String,
    },
    /// collect evidence
    Collect {
        #[command(subcommand)]
        command: CollectCommand,
    },
    /// list configured packs
    Packs {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
    },
    /// inspect one configured external pack
    Pack {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        id: String,
    },
    /// run a local tool and retain its provenance
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
    /// derive and save assertions
    Evaluate {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = "current")]
        label: String,
        #[arg(long)]
        contracts: Option<PathBuf>,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// compare two saved evaluations
    Review {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long)]
        since: String,
        #[arg(long, default_value = "current")]
        current: String,
        #[arg(long, default_value = "review")]
        output: String,
    },
    /// render a view from saved assertions
    Export {
        #[command(subcommand)]
        kind: ExportCommand,
    },
    /// verify all retained provenance offline
    Verify {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
    },
    /// inspect an assertion's provenance
    Provenance {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
        #[arg(long, default_value = "current")]
        evaluation: String,
        assertion_id: String,
    },
    /// extract a retained command stream
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
    #[command(hide = true)]
    Source {
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
    },
}

#[derive(Subcommand)]
enum CollectCommand {
    /// collect a release dependency diff and gate
    Release(Box<ReleaseArgs>),
    /// collect with a configured pack
    Pack {
        #[arg(long, default_value = ".evidence")]
        state: PathBuf,
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

#[derive(Clone)]
struct NamedPathArg {
    name: String,
    path: PathBuf,
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
            repository,
            branch,
        } => divinate::workflow::configure(
            &state,
            &divinate::workflow::ProjectConfig {
                repository,
                branch,
                packs: BTreeMap::default(),
            },
        ),
        Command::Collect { command } => match command {
            CollectCommand::Release(args) => collect_release(*args),
            CollectCommand::Pack {
                state,
                id,
                collector,
                context,
            } => collect_pack(&state, &id, &collector, context.as_deref()),
            CollectCommand::Manifest {
                state,
                manifest,
                acquisitions,
            } => {
                let increment = collect(&manifest).map_err(collection_error)?;
                record_increment(&state, &increment, &acquisitions).map_err(collection_error)
            }
        },
        Command::Packs { state } => list_packs(&state),
        Command::Pack { state, id } => inspect_pack(&state, &id),
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
            label,
            contracts,
            target,
        } => evaluate_state(&state, &label, contracts.as_deref(), target),
        Command::Review {
            state,
            since,
            current,
            output,
        } => state_review(&state, &since, &current, &output),
        Command::Export { kind } => match kind {
            ExportCommand::Dd {
                state,
                evaluation,
                output,
            } => state_dd(&state, &evaluation, &output),
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
        Command::Source {
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

fn collect_release(args: ReleaseArgs) -> Result<()> {
    let config = divinate::workflow::load_config(&args.state)?;
    let existing = divinate::workflow::load_executions(&args.state).map_err(provenance_error)?;
    let blobs = divinate::workflow::load_blobs(&args.state).map_err(provenance_error)?;
    let capture = divinate::release::collect(
        &divinate::release::ReleaseRequest {
            repository: config.repository,
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

fn configured_pack(state: &std::path::Path, id: &str) -> Result<divinate::pack::PackConfig> {
    divinate::workflow::load_config(state)?
        .packs
        .remove(id)
        .ok_or_else(|| Error::Invalid(format!("pack {id:?} is not configured")))
}

fn inspect_pack(state: &std::path::Path, id: &str) -> Result<()> {
    let config = configured_pack(state, id)?;
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

fn list_packs(state: &std::path::Path) -> Result<()> {
    let config = divinate::workflow::load_config(state)?;
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
    id: &str,
    collector: &str,
    context: Option<&std::path::Path>,
) -> Result<()> {
    let config = configured_pack(state, id)?;
    let (metadata, described) = divinate::pack::describe(&config)?;
    if metadata.id != id {
        return Err(Error::Invalid(format!(
            "configured pack {id:?} identifies itself as {:?}",
            metadata.id
        )));
    }
    let context = context.map_or_else(|| Ok(serde_json::Value::Null), read_json)?;
    let (plan, planned) = divinate::pack::plan(&config, &metadata, collector, &context)?;
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
        &config,
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
    let corpus = divinate::model::Corpus {
        collections: vec![],
        observations: vec![observation],
        schema_version: divinate::SCHEMA_VERSION.into(),
        sources: vec![source],
    };
    divinate::workflow::store_pack_invocations(state, &[described, planned, normalization])?;
    divinate::workflow::accumulate_with_executions(state, &corpus, &[], &[execution])?;
    print_json(&serde_json::json!({
        "pack": metadata.id,
        "collector": collector,
        "observation": observation_id,
    }))
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
    label: &str,
    contracts: Option<&std::path::Path>,
    target: TargetArgs,
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
    let target = evaluation_in_state(state, &historical.corpus, target, at)?;
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
    let project = divinate::workflow::load_config(state)?;
    let mut pack_captures = Vec::new();
    for (configured_id, config) in project.packs {
        let (metadata, described) = divinate::pack::describe(&config)?;
        if metadata.id != configured_id {
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
                &config,
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

fn state_review(state: &std::path::Path, previous: &str, current: &str, label: &str) -> Result<()> {
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
    )
}

fn state_dd(state: &std::path::Path, evaluation: &str, label: &str) -> Result<()> {
    require_evaluation(state, evaluation)?;
    let assertions: Vec<DerivedAssertion> =
        read_json(&state.join("assertions").join(format!("{evaluation}.json")))?;
    let response = divinate::views::dd_response(&assertions);
    write_view(
        state,
        label,
        &response,
        &divinate::views::render_dd(&response),
    )
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

fn evaluation_in_state(
    state: &std::path::Path,
    corpus: &divinate::model::Corpus,
    args: TargetArgs,
    at: time::OffsetDateTime,
) -> Result<EvaluationTarget> {
    let config = if args.repository.is_none() || args.branch.is_none() {
        Some(divinate::workflow::load_config(state)?)
    } else {
        None
    };
    Ok(EvaluationTarget {
        repository: args.repository.unwrap_or_else(|| {
            config
                .as_ref()
                .expect("configuration loaded for absent repository")
                .repository
                .clone()
        }),
        branch: args.branch.unwrap_or_else(|| {
            config
                .as_ref()
                .expect("configuration loaded for absent branch")
                .branch
                .clone()
        }),
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
    print_json(&serde_json::json!({
        "status": "verified",
        "acquisition_transcripts": acquisitions.len(),
        "collection_acquisition_links": acquisition_links.len(),
        "execution_transcripts": executions.len(),
        "observation_execution_links": execution_links.len(),
        "pack_invocations": pack_invocations.len(),
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
            serde_json::json!({
                "observation": observation.id,
                "uses": uses,
                "source": {"id": source.id, "sha256": source.sha256},
                "collection": collection,
                "executions": local,
                "pack_invocations": packs,
            })
        })
        .collect::<Vec<_>>();
    print_json(&serde_json::json!({
        "assertion": {
            "id": assertion.id,
            "claim": assertion.claim,
            "outcome": assertion.outcome,
            "derivation": assertion.derivation,
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
