# getting started

this guide records a release dependency comparison, evaluates it, and follows one
result back to the retained command output.

## prerequisites

you need:

- divinate built from this repository
- a local git checkout whose `origin` identifies the configured repository
- two distinct release tags
- a cyclonedx sbom for each release
- an `sbom-diff` executable

the sbom metadata component must identify the repository and release expected by
divinate. the baseline policy currently requires `--fail-on added-components`.

## initialize state

run this in the repository whose evidence you want to retain:

```sh
divinate init --repository github:example/acme --branch main
```

this creates `.evidence/` and writes its repository identity to
`.evidence/config.json`. running the same command again is harmless. changing the
identity requires an intentional edit to the configuration file.

repository identities are compared with the checkout's `origin`. common github
ssh and https origin forms normalize to `github:owner/name`.

## collect a release

```sh
divinate collect release \
  --repository-path . \
  --base-release v1.4.0 \
  --release v1.5.0 \
  --base-sbom dist/acme-v1.4.0.cdx.json \
  --target-sbom dist/acme-v1.5.0.cdx.json \
  --sbom-diff /opt/bin/sbom-diff \
  --tool-version 0.8.0
```

collection checks the checkout identity, both tag resolutions, both sbom
identities, the diff json, the gate status, and equality of the two emitted diffs.

the command prints json containing the resolved revisions, execution ids,
observation ids, and any executions reused from state. use `--base-revision` and
`--revision` when the expected commits should be explicit. use `--force` to run the
tool again instead of reusing an identical verified execution.

## evaluate the evidence

```sh
divinate evaluate \
  --label release-v1_5 \
  --release v1.5.0 \
  --from 2026-08-01T00:00:00Z \
  --until 2026-09-01T00:00:00Z
```

`from` is inclusive and `until` is exclusive. omit `--release` only when the
latest release in state is unambiguous. use `--at` to reproduce what was knowable
at a particular instant; otherwise evaluation uses the current time.

the command writes:

```text
.evidence/assertions/release-v1_5.json
.evidence/assertions/release-v1_5.contracts.json
.evidence/dossiers/release-v1_5.json
.evidence/dossiers/release-v1_5.md
```

start with the markdown dossier. it summarizes the controls, then explains the
reasoning, evidence, coverage, gaps, identity joins, and limitations for each
assertion.

## inspect provenance

copy an assertion id from the dossier:

```sh
divinate provenance --evaluation release-v1_5 <assertion-id>
```

the json response identifies every observation considered by the assertion and
the source, collection, execution, or pack invocation behind it.

copy an execution id from that response to recover its exact output:

```sh
divinate extract <execution-id> --stream stdout --output retained-output.json
```

`extract` verifies the stored execution and blobs before writing the stream.

## verify the state

```sh
divinate verify
```

verification is offline. it checks object identities, content digests, retained
streams, source contracts, pack invocations, and links between evidence and its
provenance. success prints a json count summary with `"status": "verified"`.

commit or archive `.evidence/` only after reviewing its contents. retained source,
stdout, and stderr are byte-exact and may contain sensitive data.
