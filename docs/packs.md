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

Commercial packs use this same protocol and may declare maintained compatibility
metadata. See [commercial packs](commercial-packs.md) for the public boundary and
the historical build-validation acquisition resources.

protocol version 1 has four operations:

- `describe` returns metadata, collectors, evaluators, source contracts,
  evaluator inputs, coverage propositions, and configuration shape.
- `collect` returns either a local command plan or one supported provider-aware
  remote acquisition plan for core to execute and retain.
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
configuration collector, the in-tree GitHub and Azure DevOps sources, and a
separately distributed evaluator.

remote plans are provider-aware and deliberately narrow:

```json
{"acquisition":{"provider":"github","resource":"commit_statuses","per_page":100,"max_pages":10}}
{"acquisition":{"provider":"azure_devops","resource":"branch_policy","max_pages":10}}
```

GitHub resources are branch protection, check runs, commit statuses,
`repository_mutations`, and `pull_request_reviews`. Azure DevOps exposes branch
policy and the same two historical resource names. the pack supplies no URL, headers,
or credential. core derives each API URL from verified repository context,
scopes authentication to the provider host, disables redirects, and captures
pagination.

the commit-status resource uses GitHub's combined-status endpoint. it returns
the latest status for each context rather than the raw status history. Divinate
still follows pagination and requires `total_count` to match the retained
statuses before treating that mechanism as complete.

the Azure DevOps branch-policy resource first resolves the configured repository
name to Azure's repository ID, then calls the Git policy-configurations endpoint
for the fully qualified branch ref. both responses and every continuation page
are retained. its contract establishes the current configuration Azure DevOps
reported for that repository branch at acquisition time. it does not establish
historical review or build enforcement.

### historical approving review

both Rust reference packs expose `repository-mutations` and
`pull-request-reviews` collectors. enable both to evaluate the provider-neutral
`every_main_change_reviewed` assertion over `collect --from ... --until ...`.
intervals are half-open: `from <= integration_time < until`.

the proposition is: every branch ref mutation in the interval was attributable
to a PR with at least one recorded approval by someone other than its author
before integration. this is not a claim that the then-applicable approval policy
was satisfied. current policy never supplies historical review evidence.

GitHub core enumerates repository activity for the branch, follows pagination,
and retains commit-to-PR associations and each associated PR's reviews. activity
explicitly identified as a push or force push is a counterexample. PR merges
require a unique association whose `merge_commit_sha` matches the resulting
branch revision. GitHub defines that field for merge, squash, and rebase merges
in its [PR API documentation](https://docs.github.com/en/rest/pulls/pulls).
unsupported or ambiguous associations leave a gap. the activity resource is
queried with `time_period=year`; older requested scope is retention-limited.

Azure core enumerates branch pushes for the exact interval and completed PRs
targeting the branch. mutation association enumerates all completed PRs rather
than applying the push interval to PR closure timestamps. each unique resulting
revision is joined to `lastMergeCommit.commitId`. vote-update threads provide
reviewer identity, vote, and time; final reviewer votes alone do not establish
chronology. votes `10` and `5` record approval, `-10` and `-5` do not; zero and
unrecognized values remain unresolved. see the
[thread API](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-request-threads/list?view=azure-devops-rest-7.1).

support requires complete authoritative mutation and review coverage, complete
PR associations, and a qualifying approval for every integration. an
authoritative direct integration or a complete PR review record without a
pre-integration approval contradicts. incomplete enumeration, missing mapping,
unknown states, and retention gaps remain insufficient. dismissed GitHub
reviews cannot reconstruct their former state and remain unresolved when no
other approval establishes the predicate. recorded approval does not prove
stale-review or vote-reset policy satisfaction.

the versioned contracts remain provider-specific:
`github-repository-mutations/v1`, `github-pull-request-reviews/v1`,
`azure-devops-repository-mutations/v1`, and
`azure-devops-pull-request-reviews/v1`. core retains a composite acquisition
transcript containing every request, exact body, pagination link, and termination.
the normalizer receives that sanitized transcript, not credentials or network
access. offline verification binds the normalized source to its canonical
transcript bytes. adjacent complete windows compose; an uncovered interval does
not disappear merely because later evidence exists.

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
and complete coverage for every declared proposition. point-in-time support may
instead resolve to a complete authoritative acquisition run. core validates
declared requirements but cannot detect a proposition the pack failed to declare.

## provenance and security

installing a pack grants it the invoking user's filesystem and network
permissions. divinate does not sandbox packs.

each invocation retains executable digest, pack id and version, protocol version,
operation, request, response, and content digests. collection invocations also
retain the resulting execution id or acquisition transcript ids.

packs cannot persist corpus files directly. core validates identities, references,
coverage, and collisions before writing state. saved invocations and assertions
verify without the pack. reevaluation executes the currently configured binary;
reproducing an older derivation requires that older executable.

protocol version 1 accepts only the named provider-aware GitHub and Azure DevOps
acquisition plans above. it is not arbitrary authenticated HTTP. unknown
providers, resources, versions, and operations fail; there is no capability
fallback.
