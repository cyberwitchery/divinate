# external packs

a pack is an executable that reads one json request from stdin and writes one json
response to stdout. protocol version 1 supports four operations:

- `describe` returns pack metadata, collectors, evaluators, source contracts,
  evaluator inputs, coverage propositions, and configuration shape.
- `collect` returns a local command plan for core to execute and retain.
- `normalize` converts retained command output into typed observation fields.
- `evaluate` derives structured assertion fields from selected observations and
  collection runs.

## protocol

requests use this envelope:

```json
{"protocol_version":1,"operation":"describe","configuration":{},"input":null}
```

successful responses contain one json document:

```json
{"ok":true,"result":{}}
```

semantic failures use `{"ok":false,"error":"..."}` and exit status zero. non-zero
exit status, invalid json, trailing stdout, a missing result, or an incompatible
protocol version fails the operation.

`describe` returns the pack's capabilities:

```json
{"ok":true,"result":{
  "id":"example.backup-control","version":"0.1.0","protocol_version":1,
  "collectors":["backup-encryption"],"evaluators":[],
  "evaluator_inputs":{},"evaluator_propositions":{},
  "source_contracts":[],"configuration_schema":{}
}}
```

`evaluator_inputs` limits an evaluator to the listed claim keys.
`evaluator_propositions` limits its collection runs and defines the coverage core
will enforce.

the examples under [`packs/`](../packs) cover a collector, a
configuration-driven collector, and a separately distributed evaluator.

## configuration

configure packs in `.evidence/config.json`:

```json
{
  "repository": "github:cyberwitchery/example",
  "branch": "main",
  "packs": {
    "example.backup-control": {
      "executable": "/opt/divinate-packs/divinate-pack-backup-control",
      "configuration": {"repository":"github:cyberwitchery/example"},
      "timeout_seconds": 30
    }
  }
}
```

available commands:

```sh
divinate packs
divinate pack <id>
divinate collect pack <id> <collector>
```

`packs` describes every configured executable. `pack` inspects one.
`collect pack` obtains its command plan, executes the command, normalizes the
output, and persists the resulting evidence.

pack processes receive the request document, an empty environment, and a temporary
working directory. the request does not contain the state path. operations time out
after 30 seconds unless `timeout_seconds` overrides the default.

configuration is retained as part of the invocation. credential-like configuration
keys are rejected. authenticated sources require a core-owned acquisition path that
keeps credentials out of retained protocol data.

## evaluation

an evaluator receives:

- observations matching its declared claim keys
- collection runs matching its declared propositions
- source documents referenced by those observations
- the evaluation target

this includes relevant zero-result collection runs.

the result contains the assertion type, claim, subject, outcome, evaluation time,
validity, evidence uses, missing evidence, identity joins, reasoning, limitations,
and coverage. core computes the assertion id and derivation identity. legacy `id`
and `derivation` fields are accepted and ignored.

each returned coverage decision must name a declared proposition and match core's
assessment. a supported coverage-backed assertion must have a non-empty interval
and one complete decision for every declared proposition. evaluators without
coverage propositions may support claims that do not require population
enumeration.

the pack defines which propositions its claim needs. core validates the declared
requirements but cannot identify a requirement the pack omitted.

## provenance and security

installing a pack grants executable code the invoking user's filesystem and network
permissions. divinate does not sandbox it.

each invocation retains the executable digest, pack id and version, protocol
version, operation, request, response, and both content digests. collection
invocations also retain the resulting execution-transcript id.

packs cannot persist corpus files directly. core assigns observation and assertion
identity, validates provenance and evidence references, checks coverage, rejects
content collisions, and writes state.

saved invocations and assertions verify without the pack. reevaluation runs the
currently configured executable. configure an archived executable explicitly to
reproduce an older derivation.

breaking protocol changes use a new integer version. unsupported versions and
operations fail.

protocol version 1 supports local command plans. it has no generic authenticated
http request plan.
