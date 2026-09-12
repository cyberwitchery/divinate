# external packs

a pack is an executable that supplies collectors, normalizers, or evaluators
without writing divinate state. core still executes commands, assigns identity,
checks provenance and coverage, and persists the result.

## declarative collection configuration

declare the pack and a source backed by one of its collectors in
`divinate.yaml`:

```yaml
packs:
  example.backup-control:
    executable: divinate-pack-backup-control
    config:
      repository: github:cyberwitchery/example

sources:
  backup-encryption:
    provider:
      pack: example.backup-control
      collector: backup-encryption
    required: true
```

`divinate collect` invokes enabled sources sequentially in deterministic source-id
order and then evaluates the current state. sources receive repository context by
default. set `context: release` on the source when the collector needs
core-resolved release and revision identities. sources are required by default;
presence in the map means enabled.

a required failure aborts the prepared collection increment. an optional failure
is shown as `failed (optional)` and the unavailable pack's evaluators are skipped
for that cycle. permission failures, protocol errors, and collector error details
remain visible in the report.

explicit pack operations remain available:

```sh
divinate packs
divinate pack example.backup-control
divinate collect pack example.backup-control backup-encryption
```

pack and source are separate concepts. the pack is the executable distribution
unit. a source selects one collector from that pack, gives it recurring
configuration and context, and controls whether it is enabled or required.

## built-in sources

built-in integrations use the same source configuration and collection loop.
the release sbom integration remains built in because its current workflow
retains two independently executed commands and requires their output bytes to
match. protocol version 1 describes one collector command per invocation, so
hiding the second command inside a pack would lose direct execution provenance.

this is a distribution choice, not a second product workflow:

```yaml
sources:
  release-sbom:
    provider:
      builtin: release-sbom
    required: true
    config:
      executable: sbom-diff
      sbom_path: dist/{release}.cdx.json
```

repository and release identity are core context. locating sboms, invoking the
configured executable, applying the gate, and interpreting its output belong to
the built-in source.

## protocol

protocol version 1 has four operations:

- `describe` returns metadata, collectors, evaluators, source contracts,
  evaluator inputs, coverage propositions, and configuration shape.
- `collect` returns a local command plan for core to execute and retain.
- `normalize` converts retained command output into typed observation fields.
- `evaluate` derives structured assertion fields from selected saved state.

requests contain one json document:

```json
{"protocol_version":1,"operation":"describe","configuration":{},"input":null}
```

successful responses contain one json document:

```json
{"ok":true,"result":{}}
```

semantic failures use `{"ok":false,"error":"..."}` and exit zero. a non-zero
exit, invalid json, trailing stdout, missing result, timeout, or incompatible
protocol version fails the operation.

`describe` returns this shape:

```json
{"ok":true,"result":{
  "id":"example.backup-control",
  "version":"0.1.0",
  "protocol_version":1,
  "collectors":["backup-encryption"],
  "evaluators":[],
  "evaluator_inputs":{},
  "evaluator_propositions":{},
  "source_contracts":[],
  "configuration_schema":{}
}}
```

`evaluator_inputs` limits an evaluator to declared claim keys.
`evaluator_propositions` limits the collection runs it receives and defines the
coverage requirements core enforces. relevant zero-result collection runs remain
available to evaluators.

the examples under [`packs/`](../packs) include an sbom collector, a
configuration collector, and a separately distributed evaluator.

## execution and retained configuration

pack processes receive the request document, an empty environment, and a
temporary working directory. they do not receive the state path. operations time
out after 30 seconds unless `timeout_seconds` changes the limit.

configuration is read from committed YAML and retained in the invocation. each
normal collection also names a content-addressed snapshot of the complete YAML.
credential-like configuration keys are refused. authenticated sources require a
core-owned acquisition path that keeps credentials out of retained protocol
data.

## evaluation

an evaluator receives only:

- observations matching its declared claim keys;
- collection runs matching its declared propositions;
- source documents referenced by those observations; and
- the evaluation target.

the response supplies assertion type, claim, subject, outcome, evaluation time,
validity, evidence uses, gaps, identity joins, reasoning, limitations, and
coverage. core computes assertion and derivation identity. legacy `id` and
`derivation` response fields are ignored.

each coverage decision must name a declared proposition and equal core's own
assessment. a supported coverage-backed assertion requires a non-empty interval
and complete coverage for every declared proposition. core validates declared
requirements but cannot detect a proposition the pack failed to declare.

## provenance and security

installing a pack grants it the invoking user's filesystem and network
permissions. divinate does not sandbox packs.

each invocation retains executable digest, pack id and version, protocol version,
operation, request, response, and content digests. collection invocations also
retain the resulting execution id.

packs cannot persist corpus files directly. core validates identities, references,
coverage, and collisions before writing state. saved invocations and assertions
verify without the pack. reevaluation executes the currently configured binary;
reproducing an older derivation requires that older executable.

protocol version 1 plans local commands only. authenticated remote collection
requires a core-owned acquisition path. unknown versions and operations fail;
there is no capability fallback.
