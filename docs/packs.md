# external packs

a pack adds questions divinate can answer, and the evidence sources to answer
them. a pack's answers appear alongside the built-in ones, with the same five
results, coverage rules, and provenance.

technically, a pack is an executable that supplies collectors, normalizers, or
evaluators without writing divinate state. core still executes commands, assigns identity,
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

core writes one json request to the pack's stdin and reads one json response
from its stdout.
[`schema/pack-protocol.schema.json`](../schema/pack-protocol.schema.json)
describes the request, with `input` typed by `operation`.
[`schema/pack-response.schema.json`](../schema/pack-response.schema.json)
describes the response, and its `$defs/describe`, `collect`, `normalize`, and
`evaluate` type each operation's result. where core refuses unknown members, the
schemas do too.

| operation | `input` | `result` |
| --- | --- | --- |
| `describe` | `null` | pack metadata |
| `collect` | `collector`, `context` | one collection plan |
| `normalize` | `adapter`, `source` (`content`, `sha256`), `subject` | one observation's fields |
| `evaluate` | `evaluator`, `corpus`, `target`, `evaluated_at`, `coverage` | an array of assertions |

`configuration` is the pack's `config` from `divinate.yaml`, `{}` when it sets
none:

```json
{"configuration":{},"input":null,"operation":"describe","protocol_version":1}
```

a configured source's collector receives `repository`, `branch`, `revision`,
`repository_path`, `interval`, `observed_at`, the source's `configuration`, and
`release` as its `context`. `release` is null unless the source sets
`context: release`. `divinate collect pack` passes its `--context` file instead,
or null without one.

a pack answers `{"ok":true,"result":...}` with the operation's result, or
`{"ok":false,"error":"..."}` and exit zero for a semantic failure. a non-zero
exit, invalid json, trailing stdout, a missing or null result, timeout, or
incompatible protocol version fails the operation.

the cargo-lock pack answers `describe` with:

```json
{"ok":true,"result":{
  "id":"cyberwitchery.cargo-lock",
  "version":"0.1.0",
  "protocol_version":1,
  "collectors":["lockfile"],
  "evaluators":["lockfile-captured"],
  "evaluator_inputs":{"lockfile-captured":["cargo:dependency-lock"]},
  "evaluator_propositions":{"lockfile-captured":[]},
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
separately distributed evaluator. [`fixtures/pack-protocol`](../fixtures/pack-protocol)
holds requests core sent them for every operation and each pack's exact stdout,
captured with
`DIVINATE_PACK_PROTOCOL_CAPTURE=fixtures/pack-protocol cargo test --test pack pack_protocol_messages`.
ci validates them, and a fresh capture, against the schemas.

a collection plan names its `adapter`, `subject`, and `observed_at`, and exactly
one of `command`, a local command for core to execute, or `acquisition`, a
remote read. remote plans are provider-aware and deliberately narrow. the GitHub
pack plans `branch-protection` as:

```json
{"ok":true,"result":{
  "acquisition":{"max_pages":10,"per_page":100,"provider":"github","resource":"branch_protection"},
  "adapter":"github-branch-protection/v1",
  "observed_at":"2026-11-23T08:32:44.419494Z",
  "subject":{"branch":"main","id":"github:cyberwitchery/example","kind":"repository","repository":"github:cyberwitchery/example","revision":"166b402faf0b2ff15eba2dff6f07af02c9c9dbcc"}
}}
```

an Azure DevOps acquisition takes no `per_page`:
`{"max_pages":10,"provider":"azure_devops","resource":"branch_policy"}`.

GitHub resources are `branch_protection`, `check_runs`, `commit_statuses`,
`repository_mutations`, `pull_request_reviews`, and `build_validation_history`.
Azure DevOps exposes `branch_policy` and the same three historical resource
names. the build-validation history resources are described in
[commercial packs](commercial-packs.md#historical-build-validation). the pack
supplies no URL, headers, or credential. core derives each API URL from verified repository context,
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

### what core's evaluators read

a `normalize` result is `claim_key`, `kind`, `evidence_class`, `data`, and
optional `severity` and `status`. core binds it to the collection plan's
`subject` and `observed_at`. the response schema leaves `data` untyped. core's
own evaluators read the `data` fields below and ignore the rest. only
`pull_request`, `submitted_at`, and `enumeration_complete` may be missing; any
other missing or mistyped field in a selected observation fails the evaluation.

`every_main_change_reviewed` joins two kinds, selected by `kind`, subject, and
collection run, not by `claim_key`. the GitHub and Azure DevOps packs'
`repository-mutations` and `pull-request-reviews` normalizers emit them.

| `kind` | subject | `data` |
| --- | --- | --- |
| `mutation_history` | `id` is the repository, `branch` the branch | `events[]`: `event_id`, `kind`, `occurred_at`, `commit`, `pull_request` (number or null) |
| `review_record` | `id` or `repository` is the repository, `branch` absent or the branch | `pull_requests[]`: `number`, `author`, `merge_commit_sha`, `merged_at`, `approvals[]` (`actor`, `submitted_at`, `state`), `enumeration_complete` |

core reads them only from runs with `repository_mutations` or
`pull_request_reviews` authority, partial and interrupted runs included; denied,
failed, unattempted, and out-of-scope runs are ignored. it keeps events with
`from <= occurred_at < until`. events that share an `event_id` must be
identical, or they leave a gap.

- event `kind` `direct_push` contradicts. `pull_request_merge` joins the review
  records whose `number` is `pull_request`. a null `pull_request`, a PR without a
  record, or any other `kind` leaves a gap. both packs emit `direct_push` only
  for an integration they established as direct, and an undecided one as
  `pull_request_merge` with a null `pull_request`.
- the record's `merge_commit_sha` must equal the event's `commit`, and its
  `merged_at` must fall in the interval, or the event leaves a gap.
- an approval qualifies when `state` is `approved`, `actor` is not `author`, and
  `submitted_at` is before the event's `occurred_at`. one qualifying approval
  supports the event.
- otherwise, a state other than `approved`, `changes_requested`, `commented`, or
  `rejected`, or an `approved` whose `submitted_at` is missing, invalid, or equal
  to `occurred_at`, leaves it unresolved.
- otherwise, `enumeration_complete: true` contradicts. both packs set `false`
  unless they saw the last page of the PR's reviews or vote threads. such a
  record is set aside for a complete record of the same PR, or else leaves it
  unresolved. a missing `enumeration_complete` counts as `true`.
- records of one PR that reach different verdicts leave a gap.

[`fixtures/github-repository-mutations-direct-push.json`](../fixtures/github-repository-mutations-direct-push.json)
is a `mutation_history` `data` value with one merge and one direct push:

```json
{"branch":"main","events":[
  {"event_id":"audit-401","kind":"pull_request_merge","occurred_at":"2026-09-02T12:00:00Z","commit":"1111111111111111111111111111111111111111","pull_request":101},
  {"event_id":"audit-403","kind":"direct_push","occurred_at":"2026-09-03T14:00:00Z","commit":"cccccccccccccccccccccccccccccccccccccccc"}
]}
```

core evaluates `configured_independent_review` for `github:` repositories only.
it reads the latest `configuration_snapshot` with `evidence_class`
`configured_intent`, claim key `github:branch-protection` (the GitHub pack's)
or `github:branch-protection:<branch>`, subject `id` the repository and `branch`
the branch, from a run with `branch_configuration` authority.
`data.required_approving_review_count` of 1 or more supports, 0 contradicts.
`fresh_until` is seven days after the snapshot's `observed_at`, and a supporting
snapshot older than that is `stale`.

for Azure DevOps, the pack's `approving-review` evaluator returns the same
assertion type: supported when the latest complete `azure-devops:branch-policy`
snapshot has an enabled, blocking minimum-reviewers policy with
`minimum_approver_count` above zero. the two differ on freshness: the pack sets
`fresh_until: null` and never returns `stale`, while core applies the seven-day
window.

release-scoped evaluators match an observation to the release by its subject's
`repository` and `release` qualifiers:

- `release_review_operation` reads the latest `release_membership`
  (`published_at`, `pull_requests` as numbers, `target_revision`) and the latest
  `observed_operation` `review_record` whose `revision` qualifier is that
  `target_revision` (`pull_requests[]` as above, counting `approved` entries by
  someone other than the author submitted at or before `merged_at`). the
  required count at each merge comes from the latest `configured_intent`
  `configuration_history` for the repository and branch with
  `branch_configuration` authority: `complete_from`, `complete_through`, and
  `events[]` with `event_id`, `effective_at`, and
  `required_approving_review_count`. the latest event effective at the merge
  sets the count, and a merge outside `complete_from` to `complete_through`
  leaves a gap.
- `release_supply_chain_policy` reads the latest `change_set` and each
  observation with claim key `supply-chain-gate:supply-chain/default`. a gate
  applies when its `base_revision` and `revision` qualifiers and its
  `data.base_revision` and `data.target_revision` equal the change set's
  `base_revision` and `revision` qualifiers, and its
  `data.evaluated_sbom_diff_sha256` equals the change set's source digest. the
  latest failing gate wins, else the latest. `status` `pass` supports; any other
  status contradicts.
- `dependency_change_visibility` needs a `change_set` and reads no `data`.
  `adequate_human_security_review` reads none and is always `not_automatable`.

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
coverage. core computes assertion and derivation identity; a response that
carries `id` or `derivation` is refused.

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
