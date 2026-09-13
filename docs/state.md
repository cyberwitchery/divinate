# configuration, state, and formats

divinate separates declared project intent from observed state:

```text
divinate.yaml
  current repository, pack, and source configuration

.evidence/
  repository.json
  contracts.json
  corpus.json
  project-configs/
  collection-cycles/
  acquisitions/
  assertions/
  blobs/
  dossiers/
  executions/
  pack-invocations/
  views/
```

`divinate.yaml` is intended to be committed and reviewed. `.evidence/` records
what happened and may need a different commit, retention, and access policy.

## project configuration

the canonical configuration is strict YAML at the repository root:

```yaml
repository:
  identity: github:example/acme
  branch: main

packs:
  example.github:
    executable: divinate-pack-github
    config: {}
    timeout_seconds: 30

sources:
  release-sbom:
    provider:
      builtin: release-sbom
    required: true
    config:
      executable: sbom-diff
      sbom_path: dist/{release}.cdx.json

  github:
    provider:
      pack: example.github
      collector: repository
    required: false
```

source IDs are stable, repository-owned names. a provider is either one named
built-in source or one collector from a declared pack. source and pack settings
are mappings under `config`. presence means enabled; `required` defaults to
true. `context` defaults to `repository` and may be `release` for external
collectors. the built-in release source always receives release context.

unknown fields, malformed provider shapes, missing collectors, unknown built-in
providers, unresolved executables, pack identity mismatches, and credential-like
configuration keys fail validation. plain executable names resolve through
`PATH`; absolute and repository-relative paths are accepted.

repository identity is explicit in YAML because it is security-relevant intent.
init infers it from Git once, and later commands verify it against the checkout.
`.evidence/repository.json` binds local historical state to the same identity.

there is no `divinate.local.yaml` in this version. PATH covers the current need
for machine-local executable selection without allowing an unreviewed file to
change evidence semantics.

## evidence files

- `repository.json` binds the state directory to its repository identity.
- `contracts.json` records source-contract invalidations used in evaluation.
- `corpus.json` contains collection runs, observations, and normalized source
  documents.
- `project-configs/` contains exact content-addressed snapshots of YAML used by
  collection and evaluation.
- `collection-cycles/` links one configuration digest and source results to the
  collection runs, observations, executions, and pack invocations produced by
  the cycle.
- `acquisitions/` contains remote acquisition transcripts.
- `executions/` contains local execution transcripts.
- `pack-invocations/` contains pack requests, responses, and executable identity.
- `blobs/` contains content-addressed executable, input, output, stdout, and
  stderr bytes.
- `assertions/` contains saved evaluations, contract registries, and each
  evaluation's configuration reference.
- `dossiers/` contains JSON dossiers and their Markdown rendering.
- `views/` contains JSON and Markdown reviews and due-diligence responses.

## configuration provenance

normal collection hashes and stores the exact `divinate.yaml` bytes before
recording its collection cycle. the cycle names that digest, source outcome,
collection-run IDs, observation IDs, execution transcript IDs, and pack
invocation IDs. evaluations
store their own configuration-digest reference. pack invocations retain their
normalized source configuration, reported identity and version, executable
digest, protocol version, and source contract metadata.

changing YAML affects the next collection only. existing corpus objects,
transcripts, invocations, cycles, and configuration snapshots remain immutable.
status reports current evidence as stale when its cycle used a different YAML
digest. a source removed from YAML remains visible as historical and its evidence
still verifies.

the digest covers the exact file, so a formatting-only edit conservatively marks
the previous collection stale. it does not create a security assertion by
itself.

## persistence rules

acquisition transcripts, execution transcripts, pack invocations, configuration
snapshots, collection cycles, and blobs are immutable. accumulation reuses equal
content-addressed objects and rejects different content under an existing ID.
corpus objects are merged by stable ID with deterministic ordering.

assertions, dossiers, and views are named outputs. normal collection publishes
`current` and preserves the former current result as `previous`. rewriting a
derived label does not alter retained evidence.

copy or archive `.evidence/` as one unit. moving it does not break internal
links. partial copies can leave provenance incomplete.

## migration

`.evidence/config.json` is the pre-YAML live configuration. if no YAML exists,
`divinate init` converts it to `divinate.yaml`. the old file is retained as
historical input but is no longer authoritative for subsequent collection.
verification does not require a current YAML file, so pre-migration evidence
remains verifiable offline.

## schemas

the `schema/` directory publishes draft 2020-12 schemas for project
configuration, configuration provenance, evidence corpora, transcripts,
contract registries, assertions, dossiers, pack protocol messages, and views.
`project-config.schema.json` describes the YAML data model;
`legacy-project-config.schema.json` describes old state configuration.

schema validity is not semantic verification. `divinate verify` also checks
identities, content digests, retained bytes, and cross-object links.

## backup and retention

state can be large because streams and declared files are retained exactly, with
content deduplication by SHA-256. establish retention and access rules before
collecting confidential material. divinate does not encrypt state or provide
remote storage.
