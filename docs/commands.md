# command reference

commands use `.evidence` by default and read project intent from
`divinate.yaml` in the repository root. pass `--state <path>` to select another
state directory and `--repository-path <checkout>` where supported. timestamps
use rfc 3339.

## normal commands

### `divinate init`

```text
divinate init [--branch <branch>] [--repository-path <checkout>]
  [--state <path>] [--json]
```

creates a minimal `divinate.yaml` and initializes local evidence state.
repository identity comes from the normalized Git `origin`; branch defaults to
the current symbolic branch. GitHub and Azure DevOps origins are supported. an
existing YAML file is validated, not replaced.

if YAML is absent and legacy `.evidence/config.json` exists, init converts its
live pack and source configuration to YAML. it leaves the legacy file in place
so retained historical state remains verifiable.

### `divinate collect`

```text
divinate collect [--release <tag>] [--base-release <tag>]
  [--from <timestamp>] [--until <timestamp>] [--at <timestamp>]
  [--repository-path <checkout>] [--force] [--state <path>] [--json]
```

strictly validates `divinate.yaml`, creates `.evidence/` when necessary, and
runs every declared source in deterministic source-id order. required source
failures abort before the prepared increment is persisted. optional source
failures remain visible and their pack evaluators are skipped for that cycle.
valid evidence is merged into state, current assertions are evaluated, and the
current dossier is written.

when a source requests release context, the target release defaults to the only
tag at `HEAD`. the base defaults to the unique nearest ancestor, preferring
releases represented in retained state. explicit release options override this
shared context for all relevant sources; they do not select one source.

the first release evaluation starts at the base release commit time. a first
repository-scoped evaluation starts at the unique root commit; histories with
multiple roots require `--from`. later evaluations start at the previous
current evaluation time. `until` defaults to collection start, while automatic
evaluation occurs after source executions complete. divinate rejects empty or
ambiguous intervals.

normal output contains source results, claim counts, and the dossier path. it
omits forensic identifiers. `--json` prints the product summary as JSON.

### `divinate status`

```text
divinate status [--repository-path <checkout>] [--state <path>] [--json]
```

validates the project configuration and summarizes saved repository identity,
collection and evaluation times, claim outcomes, evidence producers, unresolved
gaps, and changes from `previous` to `current`. configured sources are reported
as current, stale, incomplete, failed, or never collected. sources removed from
YAML remain visible as historical. status does not collect or reevaluate.

### `divinate review`

```text
divinate review [--since <label>] [--current <label>]
  [--output <label>] [--state <path>] [--json]
```

without labels, compares the explicit `previous` and `current` snapshots managed
by normal collection. if no predecessor exists, it requires `--since`. writes
`.evidence/views/<label>.json` and `.md`.

### `divinate export dd`

```text
divinate export dd [--evaluation <label>] [--output <label>]
  [--state <path>] [--json]
```

renders a due-diligence response from saved assertions. evaluation defaults to
`current`; output defaults to `dd-response`.

## pack inspection

```text
divinate packs [--repository-path <checkout>]
divinate pack [--repository-path <checkout>] <pack-id>
```

reads pack declarations from `divinate.yaml`, executes `describe`, and verifies
that each executable reports the configured pack identity and protocol version.
these commands do not mutate configuration.

## advanced collection and evaluation

### `divinate collect pack`

```text
divinate collect pack [--repository-path <checkout>] [--state <path>]
  <pack-id> <collector> [--context <json-file>]
```

invokes one collector from a pack declared in YAML. core validates its plan,
executes its local command or supported provider-aware acquisition, normalizes
the result, and stores the observation. omitted context is JSON `null`; remote
collectors therefore normally run through configured `collect`, which supplies
verified repository context. this command does not evaluate automatically.

### `divinate collect manifest`

```text
divinate collect manifest [--state <path>] <manifest.json>
  [--acquisition <transcript.json>]...
```

imports sources through built-in adapters. named acquisition and execution
links must already resolve. this command does not evaluate automatically.

### `divinate evaluate`

```text
divinate evaluate --from <timestamp> --until <timestamp>
  [--label <name>] [--contracts <registry.json>]
  [--repository <identity>] [--branch <branch>] [--release <release>]
  [--at <timestamp>] [--repository-path <checkout>] [--state <path>]
```

verifies provenance, selects evidence available at `at`, derives core and pack
assertions, and writes assertion and dossier files. repository and branch
default to YAML. omit `--release` for repository-scoped analysis; release-only
assertions are then not evaluated. an alternate contracts registry supports
historical reproduction.

### `divinate run`

```text
divinate run --tool <name> [--tool-version <version>]
  [--input <name>=<path>]... [--output <name>=<path>]...
  [--environment <name>=<value>]...
  [--working-directory <path>] [--stdout <path>] [--state <path>]
  <executable> [-- <argument>...]
```

runs a local command with an empty environment plus explicitly supplied values.
named inputs and outputs and exact streams are retained. credential-like
arguments and environment names are refused.

## forensic commands

```text
divinate verify [--state <path>]
divinate provenance [--evaluation <label>] [--state <path>] <assertion-id>
divinate extract [--state <path>] <execution-id>
  [--stream stdout|stderr] --output <path>
```

`verify` checks retained provenance offline. a corpus is optional: projectless
`run` state verifies its execution transcripts and blobs directly, while state
with a corpus still receives full graph verification. `provenance` prints one
assertion's evidence graph as JSON. `extract` verifies an execution and writes
its exact retained stream.

## migration from imperative setup

`source add`, `source configure`, `source enable`, `pack add`, and `pack
configure` have been removed. declare packs and sources in `divinate.yaml`
instead. `divinate init` performs the straightforward one-time conversion from
legacy live `.evidence/config.json` when YAML does not yet exist. historical
evidence formats remain verifiable.

the former scanner-specific `collect release` compatibility command has also
been removed. declare `release-sbom` in YAML and use `collect --release` for an
explicit release context.

## exit behavior

successful commands exit zero. failures print `error: <message>` to stderr and
exit one. a recorded tool's non-zero exit remains part of its transcript; the
workflow decides whether that result is acceptable.
