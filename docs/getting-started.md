# getting started

this guide declares a repository's evidence sources, runs collection, and opens
the resulting human-readable views.

## initialize a new repository

run this from a Git checkout with a GitHub `origin`:

```sh
divinate init
$EDITOR divinate.yaml
```

init infers the normalized repository identity and symbolic branch, creates
local `.evidence/` state, and writes a minimal `divinate.yaml`. commit the YAML
file. it is project intent, not collected evidence.

common GitHub SSH and HTTPS origins normalize to `github:owner/name`. divinate
verifies that the checkout still matches the identity in YAML before using it.

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

the first release evaluation starts at the preceding release's commit time.
later evaluations start at the former current evaluation time. the evaluation
ends at collection time.

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

review `.evidence/` before committing, sharing, or archiving it. retained source
content, stdout, and stderr are byte-exact and may contain sensitive data.
