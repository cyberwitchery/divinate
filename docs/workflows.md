# workflows

## release dependency evidence

`collect release` is the complete built-in workflow. it binds git tags, cyclonedx
sbom identities, `sbom-diff` output, and an added-component policy decision.

the workflow records two executions. the first produces the dependency diff. the
second runs the same comparison with `--fail-on added-components`. divinate
requires their output bytes to match, so the gate cannot silently evaluate a
different delta.

identical verified executions are reused. `--force` captures them again. the
resulting assertions state only what the supplied sboms cover; they do not claim
to enumerate runtime-loaded software or comparable generator environments.

## arbitrary local tools

use `run` when no normalizer or typed collector exists:

```sh
divinate run \
  --tool example-scanner \
  --tool-version 1.2.3 \
  --input source=artifact.bin \
  --output report=report.json \
  /opt/bin/example-scanner -- artifact.bin --json report.json
```

this records provenance, not meaning. `run` alone does not create an observation
or assertion. use a built-in adapter through a manifest, or a pack, to turn output
into typed evidence.

## manifest import

a manifest imports json sources through built-in adapters. the top level contains
`sources` and an optional `collection_runs` array:

```json
{
  "collection_runs": [],
  "sources": [
    {
      "adapter": "sbom-diff",
      "collection_run": null,
      "execution_transcripts": ["exec_..."],
      "path": "sbom-diff.json",
      "observed_at": "2026-09-01T12:00:00Z",
      "producer": {
        "name": "sbom-diff",
        "version": "0.8.0",
        "collector": "local/sbom-diff"
      },
      "subject": {
        "kind": "release",
        "id": "github:example/acme:v1.5.0",
        "repository": "github:example/acme",
        "release": "v1.5.0",
        "revision": "<commit>",
        "base_revision": "<commit>"
      }
    }
  ]
}
```

source paths are relative to the manifest. `execution_transcripts` must identify
retained executions whose stdout, stderr, or declared output matches the source
bytes. a source tied to population enumeration also names its `collection_run`;
that run names the acquisition transcripts establishing its coverage.

manifests are a low-level interchange surface: they require exact subjects,
provenance, and coverage. prefer `collect release` or a pack for repeatable use.

## packs

packs add collectors, normalizers, and evaluators without changing core. configure
their executable paths in `.evidence/config.json`, inspect them with `packs` and
`pack`, then call `collect pack`. see [packs](packs.md) for the protocol and trust
model.

## repeated evaluations

use stable labels for review points:

```sh
divinate evaluate --label august --release v1.4.0 \
  --from 2026-08-01T00:00:00Z --until 2026-09-01T00:00:00Z

divinate evaluate --label september --release v1.5.0 \
  --from 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z

divinate review --since august --current september --output september-review
```

the review is written as json and markdown under `.evidence/views/`. it compares
saved assertion outcomes and evidence, not raw sources.

## due-diligence response

```sh
divinate export dd --evaluation september --output customer-response
```

this writes a concise assertion-based response under `.evidence/views/`. it does
not add compliance mappings or infer answers absent from the saved evaluation.

## reproducible historical evaluation

record `--at`, `--from`, `--until`, `--release`, and the evaluation label in the
review process. archive `.evidence/` as a unit. if pack assertions must be
re-derived later, retain and configure the exact pack executable version; saved
pack assertions can be verified without executing it.
