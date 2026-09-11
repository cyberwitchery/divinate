# command reference

all commands use `.evidence` by default. pass `--state <path>` to use another
state directory. timestamps use rfc 3339.

## `divinate init`

```text
divinate init --repository <identity> [--branch <branch>] [--state <path>]
```

creates repository-local state. `branch` defaults to `main`. the command produces
no output on success and refuses to replace a different existing configuration.

## `divinate collect release`

```text
divinate collect release \
  --repository-path <checkout> \
  --base-release <tag> --release <tag> \
  --base-sbom <file> --target-sbom <file> \
  --sbom-diff <executable> \
  [--base-revision <commit>] [--revision <commit>] \
  [--tool-version <version>] [--policy <id>] \
  [--fail-on added-components] [--force] [--state <path>]
```

records a release sbom diff and policy gate. `policy` defaults to
`supply-chain/default`; the baseline evaluator accepts only
`fail-on=added-components`. matching verified executions are reused unless
`--force` is present. output is json with releases, revisions, execution ids,
reused execution ids, and observation ids.

## `divinate collect manifest`

```text
divinate collect manifest [--state <path>] <manifest.json> \
  [--acquisition <transcript.json>]...
```

imports sources through built-in adapters and appends them to state. source paths
are relative to the manifest. acquisition transcript files must be supplied for
collection runs that name them. observations derived from local output must name
already retained execution transcripts. output reports accumulated object counts.

## `divinate collect pack`

```text
divinate collect pack [--state <path>] <pack-id> <collector> \
  [--context <json-file>]
```

asks a configured pack for a command plan, executes it through core, normalizes
its stdout, and stores the observation. omitted context is json `null`. output
contains the pack id, collector name, and observation id.

## `divinate packs`

```text
divinate packs [--state <path>]
```

describes every configured pack and prints a json array containing metadata and
the executable sha-256.

## `divinate pack`

```text
divinate pack [--state <path>] <pack-id>
```

describes one configured pack and prints its metadata and executable sha-256.

## `divinate run`

```text
divinate run --tool <name> [--tool-version <version>] \
  [--input <name>=<path>]... [--output <name>=<path>]... \
  [--environment <name>=<value>]... \
  [--working-directory <path>] [--stdout <path>] [--state <path>] \
  <executable> [-- <argument>...]
```

runs a local command with an empty environment plus explicitly supplied values.
named inputs are hashed before execution. named outputs must exist afterward and
are retained. stdout and stderr are always retained; `--stdout` also copies stdout
to the named path. output contains the execution id, exit status, success flag,
and stdout digest.

credential-like arguments and environment names are refused. see
[security](security.md) before recording arbitrary tools.

## `divinate evaluate`

```text
divinate evaluate --from <timestamp> --until <timestamp> \
  [--label <name>] [--contracts <registry.json>] \
  [--repository <identity>] [--branch <branch>] [--release <release>] \
  [--at <timestamp>] [--state <path>]
```

verifies provenance, selects evidence available at `at`, derives core and pack
assertions, and writes assertion and dossier files. `label` defaults to `current`
and may contain only letters, numbers, hyphens, and underscores. repository and
branch default to state configuration. release defaults to the latest unambiguous
release in the historical corpus. `--contracts` uses a supplied contract registry
instead of the registry in state. the command is silent on success.

## `divinate review`

```text
divinate review --since <label> [--current <label>] \
  [--output <label>] [--state <path>]
```

compares two saved assertion sets. `current` defaults to `current`; output defaults
to `review`. writes `.evidence/views/<label>.json` and `.md`.

## `divinate export dd`

```text
divinate export dd [--evaluation <label>] [--output <label>] [--state <path>]
```

renders a due-diligence response from saved assertions. evaluation defaults to
`current`; output defaults to `dd-response`. writes json and markdown under
`.evidence/views/`.

## `divinate verify`

```text
divinate verify [--state <path>]
```

verifies retained provenance without network access or tool execution. output is
a json summary of verified objects and links.

## `divinate provenance`

```text
divinate provenance [--evaluation <label>] [--state <path>] <assertion-id>
```

prints the saved assertion's evidence graph as json. evaluation defaults to
`current`.

## `divinate extract`

```text
divinate extract [--state <path>] <execution-id> \
  [--stream stdout|stderr] --output <path>
```

verifies an execution transcript and writes the exact retained stream. stream
defaults to stdout. the command does not decode, normalize, or redact the bytes.

## exit behavior

successful commands exit zero. failures print `error: <message>` to stderr and
exit one. a recorded tool's non-zero exit is part of its transcript; whether the
high-level command accepts it depends on that workflow.
