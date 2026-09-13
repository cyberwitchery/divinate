# workflows

## recurring repository maintenance

`divinate.yaml` contains choices that stay stable across collection cycles.
normal use is:

```sh
divinate collect
divinate status
divinate review
```

`collect` prepares enabled source results before merging their evidence. a
required source or provenance validation failure aborts that prepared increment.
optional source failures are reported separately. after a valid
increment is retained, evaluation publishes new `current` assertions and dossier
files while preserving the prior evaluation as `previous`.

retained evidence is independently meaningful. if evidence persistence succeeds
but evaluation fails, divinate reports that distinction instead of claiming the
whole cycle was transactional.

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

## authenticated github evidence

the in-tree GitHub pack declares branch-protection, check-run, and commit-status
acquisition intent. core verifies repository, branch, and revision context,
obtains the local GitHub credential, performs the requests, and retains
sanitized transcripts.
"observed GitHub revision results acceptable" joins complete check-run and
commit-status evidence on the exact revision. required-context configuration
remains a separate claim.
the pack receives only exact retained response bodies for normalization.

authenticate once with `gh auth login`, or set `GITHUB_TOKEN`, then use the
normal workflow:

```sh
divinate collect
divinate status
```

permission denial is a recorded incomplete source result. it is never treated as
an unprotected branch or an empty check-run population. `divinate verify` later
checks the retained graph without GitHub access or a credential.

## explicit historical evaluation

normal collection manages `current` and `previous`. use named evaluations when
the time, release, or source-contract registry must be explicit:

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
