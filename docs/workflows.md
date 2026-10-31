# workflows

## recurring collection

`divinate.yaml` holds the choices that stay the same from one collection to the
next. the recurring loop is:

```sh
divinate collect
divinate status
divinate review
```

run it on a schedule, in ci, or before you need to answer. each collection adds
evidence and answers every question again over its whole period, so answers stay
current and `review` shows what changed since last time.

`collect` prepares every source's results before saving any of them. a failed
required source, or evidence that fails validation, stops the collection and
nothing is saved. a failed optional source is reported and the rest is saved.
after the evidence is saved, the new answers become `current` and the previous
ones are kept as `previous`.

if the evidence is saved but answering fails, divinate reports exactly that. the
saved evidence is still valid and the next collection will answer from it.

## answering for an audit period

auditors and questionnaires usually ask about a specific period, such as a
quarter or the year before a certification. collect and answer for exactly that
period:

```sh
divinate collect --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z
divinate export dd
```

`from` is included and `until` is not. questions about history, such as "did
every change get reviewed?", are answered for that period only. questions about
configuration, such as "is review required?", are answered from the settings as
they are when you collect; divinate cannot read past settings from GitHub or
Azure DevOps.

the next `divinate collect` replaces `current`. to keep the period's answers
under their own name, save a named evaluation and export it:

```sh
divinate evaluate --label 2026-q3 \
  --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z
divinate export dd --evaluation 2026-q3 --output 2026-q3
```

this writes `.evidence/views/2026-q3.md`. the evaluation uses all evidence
collected so far. archive `.evidence/` with it so the answers stay verifiable.

GitHub keeps about one year of repository activity. collect at least once a
year, and ideally on a regular schedule, so that the history an auditor may ask
about is retained in `.evidence/` before GitHub drops it. retained evidence
stays usable after the provider has forgotten it.

## release dependency evidence

normal release collection binds Git tags, CycloneDX SBOM identities, comparison
output, and an added-component policy decision. declare the built-in source:

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

then run `divinate collect`. the target is the only release tag at `HEAD`. the
base is the unique nearest ancestor, with releases already represented in state
taking precedence over repository tags. recorded tag revisions become expected
revisions on later runs, so a moved tag is rejected.

the workflow records two executions. one produces the dependency diff; the other
runs the same comparison with the configured gate. their output bytes must match.
identical verified executions are reused unless `--force` is present.

override shared release context for an exceptional cycle:

```sh
divinate collect --release v1.5.0 --base-release v1.4.0
```

the former scanner-specific `collect release` compatibility form has been
removed. `collect --release` supplies explicit shared release context while the
configured sources still determine what evidence is produced.

## configured packs

packs are executable distribution units. sources select their collectors in
YAML:

```yaml
packs:
  example.backup-control:
    executable: divinate-pack-backup-control
sources:
  backup-encryption:
    provider:
      pack: example.backup-control
      collector: backup-encryption
```

sources run in deterministic source-id order. presence means enabled and they
are required by default. divinate does not schedule them or infer dependencies
between them.

## authenticated provider evidence

the GitHub and Azure DevOps packs say which provider records they need. divinate
itself checks the repository, branch, and commit, obtains the local credential,
makes the requests, and keeps sanitized records of every exchange. the packs
receive only the retained responses, never the credential.

authenticate once with `gh auth login` (or set `GITHUB_TOKEN`) for GitHub, or
`az login` (or set `AZURE_DEVOPS_EXT_PAT`) for Azure DevOps, then use the normal
loop.

a denied permission, a rate limit, or an incomplete list of results is recorded
as an incomplete source result. it is never read as "the branch is
unprotected" or "there were no checks": the answers that need that evidence
become **insufficient evidence** and name the gap. `divinate verify` later
checks everything retained without network access or a credential.

## answering as of a past date

normal collection manages `current` and `previous`. a named evaluation can also
answer as divinate would have at an earlier time. `--at` limits the answer to
evidence that had been collected by then, so later collections cannot leak into
it:

```sh
divinate evaluate --label september --release v1.5.0 \
  --from 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z \
  --at 2026-10-01T00:00:00Z

divinate review --since august --current september \
  --output september-review
```

archive `.evidence/` as a unit. reproduction of pack assertions also requires
the executable whose digest identifies the original derivation.

## arbitrary local tools

use `run` when no typed collector exists:

```sh
divinate run \
  --tool example-scanner \
  --tool-version 1.2.3 \
  --input source=artifact.bin \
  --output report=report.json \
  /opt/bin/example-scanner -- artifact.bin --json report.json
```

this records provenance, not meaning. use a manifest adapter or pack to turn the
retained output into typed evidence.

## manifest import

a manifest is the low-level interchange surface for built-in adapters. it names
source files, subjects, observation times, producers, and any collection,
execution, or acquisition links. paths are relative to the manifest.

```sh
divinate collect manifest evidence-manifest.json \
  --acquisition github-commits.json
```

manifests require exact identity, provenance, and coverage. prefer normal
configured collection for recurring use.

## downstream views

```sh
divinate review
divinate export dd
```

views consume saved assertions. they do not read raw evidence, acquire new
evidence, or introduce separate assertion semantics.
