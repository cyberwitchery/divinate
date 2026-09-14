# design

## data flow

```text
source systems and local tools
  → acquisition and execution transcripts
  → collection coverage
  → observations
  → assertions
  → views
```

remote reads produce acquisition transcripts. local commands produce execution
transcripts. both use content-addressed storage, but retain different provenance.
remote evidence includes request scope, pagination, and source-contract identity.
local evidence includes executable identity, argv, inputs, exit status, and output.

collection runs record attempts to enumerate a population. observations interpret
retained source bytes. assertions derive claims from observations and coverage.
views select saved assertions without reading raw evidence.

the product command surface composes this flow without changing its ownership:

```text
collect configured sources and packs
  → validate and persist evidence
  → evaluate current assertions
  → publish current and previous derived snapshots
```

`status` reads those saved structures. `review` compares saved assertion sets.
neither command adds evidence or assertion semantics. the explicit collection,
execution, evaluation, and provenance commands remain available for inspection
and historical reproduction.

## project intent and observed state

`divinate.yaml` is the authoritative declaration of repository, pack, and source
intent. `.evidence/` is observed and derived state. normal collection can create
missing local state from an existing YAML file, but it cannot reconstruct source
intent from command history.

repository identity is explicit in YAML and verified against Git. executable
names resolve through `PATH`; there is no machine-local override layer. source
presence means enabled, required or optional behavior is declarative, and
source-specific values remain nested under that source.

repository identity remains a canonical string with provider-specific parsing.
core currently accepts `github:owner/repository` and
`azure-devops:organization/project/repository`; this is not a claim of generic
Git-host support.

each collection stores the exact YAML under its content digest and links that
snapshot to the collection cycle. evaluations name the same configuration
digest. current configuration can therefore change without rewriting or
reinterpreting historical evidence.

## ownership

core owns:

- portable schemas and local state
- strict project configuration loading and configuration provenance
- repository and release identity, including git checkout validation, tag and
  revision resolution, predecessor selection, and evaluation intervals
- provider-aware authenticated acquisition and local execution
- evidence identity and immutable persistence
- collection coverage
- built-in source normalizers and evaluators
- provenance verification
- views

packs may provide:

- collectors
- source contracts
- normalizers
- evaluators

pack output passes through core validation and persistence. packs do not write
evidence state.

repository and release identity are core context. evidence-production semantics
belong to configured sources and packs. a source may receive core-resolved
repository, branch, release, revision, predecessor, and interval values, but it
does not independently redefine them.

repository-scoped evaluation does not require or infer a release. core evaluates
release assertions only when explicit or source-required release context exists.
the first repository interval begins at the unique Git root commit; ambiguous
multiple-root histories require an explicit start.

the release sbom integration is a built-in source registered through the same
configuration and collection surface as external collectors. it remains compiled
in because it records a diff and a policy gate as separate executions and proves
their output bytes agree. pack protocol version 1 exposes one planned command per
collector invocation, so moving that workflow behind one pack process would
weaken its execution provenance.

## provenance

an acquisition transcript stores sanitized request metadata, exact response bodies,
pagination data, termination, and a source-contract version. a collection run names
the transcripts behind its coverage statement.

an execution transcript stores the executable sha-256 and size, reported version,
argv, an optional working-directory label, explicit environment values, named
inputs and outputs, timestamps, exit status, and exact stdout and stderr. blobs are
stored once by sha-256.

offline verification checks transcript identity, blob digests, retained streams,
scope, pagination, source contracts, and links from observations to their source
bytes. it also checks immutable collection-cycle identities, exact project
configuration digests, evaluation configuration references, and their evidence
links.

immutable execution, acquisition, and pack objects can exist without a corpus.
verification checks those objects and their direct links independently, then
checks corpus and configuration graph links only when those higher-level objects
exist. it never creates an empty corpus or repository identity to make
projectless state appear complete.

local commands receive an empty environment plus explicit values. credential-like
argv and environment names are rejected. stdout and stderr are stored without
redaction.

## invariants

- a universal or absence claim requires complete coverage of its required
  population.
- authority is scoped to a proposition, subject, and interval.
- acquisitions, executions, blobs, observations, and collection runs are
  immutable.
- project configuration is mutable intent; retained configuration snapshots and
  collection cycles are immutable history.
- evidence becomes available when all supporting transcripts have been captured.
- withdrawing current source-contract authority does not alter historical
  transcripts.
- configured intent, observed operation, and observed state do not substitute for
  one another.
- views consume assertions and contain no independent assertion logic.
- supported, contradicted, insufficient evidence, stale, and not automatable are
  separate outcomes.

## trust boundaries

content addressing detects changes after capture. it does not establish source
truth, executable behavior, host-clock accuracy, hermetic execution, or remote
attestation. executable digests identify retained bytes. reported versions are
descriptive.

source contracts define the propositions and scopes a remote collector can
establish. normalizers define the meaning of retained tool output. evaluators define
claim semantics.

provider-specific observations may derive provider-neutral assertions when the
predicate is genuinely shared. the assertion keeps its stable semantic identity;
provider details remain in its evidence, reasoning, and derivation provenance.

GitHub packs select branch protection, revision check runs, or revision commit
statuses. Azure DevOps packs currently select only current branch policy. core
derives provider URLs from verified repository context, obtains a local
credential, performs HTTPS, captures pagination, and strips credential-bearing
metadata before persistence. packs receive exact retained response bytes, never
credentials.

## packs

```text
pack collector
  → core execution
  → core evidence
  → pack normalization
  → pack evaluation
  → core assertions and views
```

protocol version 1 has four operations: `describe`, `collect`, `normalize`,
and `evaluate`.

`collect` returns either a command plan or one narrow provider-aware acquisition
plan. core executes it and binds the resulting execution or acquisition
transcript to the pack invocation. `normalize` receives retained source bytes
and returns typed observation fields. core assigns observation identity and
provenance.

`evaluate` receives the observations and collection runs declared by the pack's
metadata. core assigns assertion and evaluator identity, validates evidence
references, and recomputes each coverage decision. a supported coverage-backed
assertion requires an interval and complete coverage for every proposition declared
by its evaluator.

a pack defines which propositions its claims require. core can verify declared
coverage but cannot detect an omitted requirement.

each invocation stores the pack id and version, executable digest, protocol version,
operation, exact request, canonical response, and content digests. collection
invocations also name the execution or acquisition transcripts. observation
provenance names its pack invocations, and pack assertions name the evaluation
invocation.

collection plans bind directly to execution transcripts. observations name the
execution references needed to verify their retained source bytes.

packs run as the current user. divinate clears their environment, creates a
temporary working directory, omits the state path, drains both output streams, and
applies a configurable timeout.

saved pack assertions remain verifiable without executing the pack. reevaluation
uses the currently configured executable. reproducing an old derivation requires
configuring the corresponding old executable.

protocol version 1 plans local commands, three named GitHub acquisitions, and
one Azure DevOps branch-policy acquisition. it does not expose arbitrary
authenticated HTTP or secret-bearing headers.

the repository dogfoods this boundary with in-tree Cargo.lock and GitHub packs
declared in root `divinate.yaml`. the GitHub pack owns endpoint interpretation;
core alone owns its credential and network acquisition.

## distribution

packs are separate executables configured by path. they may use a different source
tree and license from core. their derived evidence remains in the portable core
formats.

unknown protocol versions and operations fail. there is no capability fallback or
protocol negotiation.

## product scope

divinate provides repository-local evidence storage, collection and execution
provenance, coverage assessment, typed assertions, historical evaluation, and
file-based views.

it has no hosted backend, ui, account model, compliance catalog, pack registry,
policy language, confidence score, scanner framework, or llm interpretation.
