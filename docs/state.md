# state and formats

divinate stores evidence in one repository-local directory:

```text
.evidence/
  config.json
  contracts.json
  corpus.json
  acquisitions/
  assertions/
  blobs/
  dossiers/
  executions/
  pack-invocations/
  views/
```

## files

- `config.json` identifies the repository and branch and configures packs.
- `contracts.json` records source-contract invalidations used during evaluation.
- `corpus.json` contains collection runs, observations, and normalized source
  documents.
- `acquisitions/` contains remote acquisition transcripts.
- `executions/` contains local execution transcripts.
- `pack-invocations/` contains pack requests, responses, and executable identity.
- `blobs/` contains content-addressed executable, input, output, stdout, and stderr
  bytes.
- `assertions/` contains saved evaluations and the contract registry used for each.
- `dossiers/` contains json dossiers and their markdown rendering.
- `views/` contains json and markdown reviews and due-diligence responses.

## persistence rules

acquisition transcripts, execution transcripts, pack invocations, and blobs are
immutable. accumulation reuses equal content-addressed objects and rejects
different content under an existing id. corpus objects are merged by stable id
with deterministic ordering.

assertions, dossiers, and views are named outputs. running an evaluation with an
existing label rewrites those derived files; it does not alter retained evidence.
use distinct labels when the earlier result must remain available.

copy or archive the state directory as one unit. moving it does not break internal
links. partial copies can leave provenance incomplete.

## json schemas

the `schema/` directory publishes draft 2020-12 schemas for project configuration,
evidence corpora, acquisition and execution transcripts, contract registries,
derived assertions, dossiers, pack invocations, pack protocol messages, isms
updates, and due-diligence responses.

the corpus format version is `0.1.0`. the pack protocol version is `1`. these are
separate version spaces. readers reject unsupported corpus versions and pack
operations reject incompatible protocol versions.

schemas describe serialized compatibility. semantic verification still requires
`divinate verify`; a document can be schema-valid while referring to missing or
incorrectly addressed bytes.

## backup and retention

state can be large because streams and declared files are retained exactly, with
content deduplication by sha-256. establish retention and access rules before
collecting confidential material. divinate does not encrypt state or provide
remote storage.
