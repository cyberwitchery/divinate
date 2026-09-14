# getting started

this guide declares a repository's evidence sources, runs collection, and opens
the resulting human-readable views.

## initialize a new repository

run this from a Git checkout with a supported `origin`:

```sh
divinate init
$EDITOR divinate.yaml
```

init infers the normalized repository identity and symbolic branch, creates
local `.evidence/` state, and writes a minimal `divinate.yaml`. commit the YAML
file. it is project intent, not collected evidence.

common GitHub SSH and HTTPS origins normalize to `github:owner/name`. Azure
DevOps SSH and HTTPS origins normalize to
`azure-devops:organization/project/repository`. divinate verifies that the
checkout still matches the identity in YAML before using it.

accepted Azure forms are
`git@ssh.dev.azure.com:v3/organization/project/repository`,
`ssh://git@ssh.dev.azure.com/v3/organization/project/repository`,
`https://dev.azure.com/organization/project/_git/repository`, and the equivalent
`organization.visualstudio.com` HTTPS form.

## declare sources

the built-in release SBOM source needs two release tags, a CycloneDX SBOM for
each release, and its configured comparison executable:

```yaml
repository:
  identity: github:cyberwitchery/example
  branch: main

sources:
  release-sbom:
    provider:
      builtin: release-sbom
    required: true
    config:
      executable: sbom-diff
      sbom_path: dist/{release}.cdx.json
```

the `{release}` placeholder is required. the source substitutes the resolved
tag and validates the SBOM's embedded identity. it does not infer identity from
the filename.

external collectors declare an executable pack and select a collector:

```yaml
repository:
  identity: github:cyberwitchery/example
  branch: main

packs:
  example.github:
    executable: divinate-pack-github

sources:
  github-repository:
    provider:
      pack: example.github
      collector: repository
    required: true
```

source IDs are repository-owned stable names. presence means enabled. set
`required: false` for a source whose failure may leave a visible incomplete
cycle. use `context: release` only when an external collector needs
core-resolved release context.

plain executable names resolve through `PATH`; explicit absolute or
repository-relative paths are also accepted. divinate has no local override
file in this release because PATH covers the current machine-local requirement.
do not put secrets in YAML. credential-like configuration keys are rejected.

the divinate repository's own [`divinate.yaml`](../divinate.yaml) is a complete
example. it configures the in-tree Cargo.lock and GitHub packs through
repository-relative executable paths. the GitHub source needs an authenticated
`gh` installation or `GITHUB_TOKEN`; neither credential is declared in YAML.

an authenticated GitHub source is declared like any other pack source:

```yaml
packs:
  cyberwitchery.github:
    executable: divinate-pack-github

sources:
  github-branch-protection:
    provider:
      pack: cyberwitchery.github
      collector: branch-protection
    required: true
  github-check-runs:
    provider:
      pack: cyberwitchery.github
      collector: check-runs
    required: true
  github-commit-statuses:
    provider:
      pack: cyberwitchery.github
      collector: commit-statuses
    required: true
```

core obtains a token from `gh auth token`, then falls back to `GITHUB_TOKEN`.
packs receive neither the token nor ambient environment. acquisition transcripts
retain sanitized request metadata and exact response bodies.

"observed GitHub revision results acceptable" considers both Checks API check
runs and classic commit statuses for the same revision. it supports only when
both populations are completely enumerated, at least one result exists, and
every result is terminal and acceptable. `success`, plus the Checks API's
`neutral` and `skipped` conclusions, are acceptable. failures contradict the
claim. pending, unknown, absent, or incomplete results leave it insufficient.
this is an observed-result claim; it does not assert that every
branch-protection-required context ran.

an Azure DevOps branch-policy source uses the same declarative model:

```yaml
repository:
  identity: azure-devops:example-org/example-project/example-repository
  branch: develop

packs:
  cyberwitchery.azure-devops:
    executable: divinate-pack-azure-devops

sources:
  azure-branch-policy:
    provider:
      pack: cyberwitchery.azure-devops
      collector: branch-policy
    required: true
```

core asks Azure DevOps for the repository identity and policies applying to the
configured branch. it obtains an access token from `az account
get-access-token`, then falls back to `AZURE_DEVOPS_EXT_PAT`. neither credential
appears in YAML or pack input. the resulting assertions describe current
configured blocking policies, approving reviews, and build validation. they do
not establish historical operating effectiveness, pull-request review history,
pipeline existence, or pipeline results.

## collect and evaluate

```sh
divinate collect
```

normal collection:

1. strictly validates `divinate.yaml` and repository identity;
2. resolves repository and release context requested by the sources;
3. validates and runs each declared source in deterministic order;
4. retains normalized evidence, exact transcripts, and the configuration used;
5. evaluates the current scope; and
6. writes `.evidence/dossiers/current.md`.

the first release evaluation starts at the preceding release's commit time. a
first repository-scoped evaluation starts at the unique Git root commit; a
multiple-root history requires `--from`. later evaluations start at the former
current evaluation time. the evaluation ends at collection time.

when a release value is not unique, collection stops before committing the
prepared increment:

```text
error: cannot determine previous release for v1.5.0; candidates are stable, v1.4.0; choose one with --base-release
```

resolve it explicitly:

```sh
divinate collect --release v1.5.0 --base-release v1.4.0
```

## clone an already configured repository

if `divinate.yaml` is committed, init is not required:

```sh
git clone <repository>
cd <repository>
divinate collect
```

collect creates `.evidence/` and records the verified repository identity when
state is absent. the checkout must also have the declared packs and tools on
`PATH`, plus any external credentials handled outside YAML.

## inspect and review

```sh
divinate status
```

status reads saved structured state and YAML. it reports claim counts, evidence
gaps, degraded collections, configured sources that are current, stale, failed,
or never collected, and historical sources removed from current configuration.
it does not rerun evaluators.

after another collection cycle:

```sh
divinate collect
divinate review
```

normal collection preserves the former `current` evaluation as `previous`.
parameterless review compares that explicit pair. the first collection has no
predecessor and review asks for `--since` rather than guessing.

export a due-diligence response with:

```sh
divinate export dd
```

## verify and inspect provenance

```sh
divinate verify
divinate provenance <assertion-id>
divinate extract <execution-id> --output retained-output.json
```

verification is offline. each normal collection records a content-addressed
snapshot of the exact YAML and links its collection cycle and evaluation to that
digest. later YAML edits do not rewrite old evidence.

projectless execution state is also verifiable:

```sh
divinate run --tool derive ./derive -- input
divinate verify
```

when `corpus.json` is absent, verify checks retained executions, blobs,
acquisitions, pack invocations, and their available links directly. it does not
create a corpus or repository identity.

review `.evidence/` before committing, sharing, or archiving it. retained source
content, stdout, and stderr are byte-exact and may contain sensitive data.
