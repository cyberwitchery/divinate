# divinate

## what is this

divinate records technical security evidence and derives claims that remain
traceable to the bytes behind them.

it is a repository-local command-line tool. it retains remote acquisitions and
local tool executions, records which population a collection covered, and writes
typed assertions with explicit support, contradictions, limitations, and gaps.
when the evidence cannot establish a claim, the result says why.

divinate is useful when a security answer needs to survive the command that
produced it. its state can be verified offline and inspected without rerunning the
original tool.

## these are the commands

the shortest useful demo is a release dependency review. it needs a git checkout,
cyclonedx sboms for two release tags, and an `sbom-diff` executable.

initialize state:

```sh
divinate init \
  --repository github:example/acme \
  --branch main
```

collect the diff and run the release gate:

```sh
divinate collect release \
  --repository-path /path/to/acme \
  --base-release v1.4.0 \
  --release v1.5.0 \
  --base-sbom /path/to/acme-v1.4.0.cdx.json \
  --target-sbom /path/to/acme-v1.5.0.cdx.json \
  --sbom-diff /path/to/sbom-diff \
  --tool-version 0.8.0
```

this resolves both tags, checks that each sbom describes the expected repository
and release, and records the diff and policy gate as separate executions.

turn the retained evidence into assertions and a dossier:

```sh
divinate evaluate \
  --label release-v1_5 \
  --release v1.5.0 \
  --from 2026-08-01T00:00:00Z \
  --until 2026-09-01T00:00:00Z
```

open `.evidence/dossiers/release-v1_5.md`. its first section is the result a
reviewer sees:

```text
| control                               | state                 | semantics                        |
|---------------------------------------|-----------------------|----------------------------------|
| approval required on main             | insufficient evidence | configured intent                |
| changes received required review      | insufficient evidence | observed operating effectiveness |
| release dependency changes preserved | supported             | historical release evidence      |
| release dependency gate               | supported             | cross-source derived claim       |
| adequate human security review        | not automatable       | human judgement boundary         |
```

the release assertions can be supported while repository review assertions remain
insufficient. divinate does not treat missing collection as proof that an event did
not occur.

inspect and verify the result:

```sh
divinate verify
divinate provenance --evaluation release-v1_5 <assertion-id>
divinate extract <execution-id> --stream stdout --output retained-output.json
```

the dossier contains the assertion ids. `provenance` supplies the corresponding
execution ids and shows how the assertion used each observation.

## install

divinate requires rust 1.95 or newer. build this checkout with:

```sh
cargo build --release --bin divinate
install -m 0755 target/release/divinate /usr/local/bin/divinate
```

the second command is optional and may need a different destination or additional
permissions.

## documentation

- [getting started](docs/getting-started.md) explains the release workflow.
- [command reference](docs/commands.md) documents every public command and output.
- [concepts](docs/concepts.md) defines evidence, coverage, assertions, and time.
- [workflows](docs/workflows.md) covers manifests, arbitrary tools, and views.
- [state and formats](docs/state.md) describes `.evidence/` and the json schemas.
- [security](docs/security.md) states the trust boundaries and retention rules.
- [troubleshooting](docs/troubleshooting.md) covers common failures and gaps.
- [packs](docs/packs.md) documents the external pack protocol.
- [design](DESIGN.md) records implementation invariants for maintainers.

## scope

divinate is not a scanner, hosted evidence service, dashboard, compliance catalog,
or policy language. the generated markdown dossier is the human-readable product
surface. json assertions and views are available for other systems.

content addressing detects changes after capture. it does not prove that a source
was truthful, a tool was correct, or a host clock was accurate.

## license

apache-2.0. external packs carry their own licenses.
