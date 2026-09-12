# divinate

## what is this

divinate keeps a repository's technical security evidence current and derives
claims that remain traceable to the bytes behind them.

the repository declares its evidence sources in `divinate.yaml`. divinate
records what those sources actually produced under `.evidence/`. ordinary use is:

```sh
divinate collect
divinate status
divinate review
```

`collect` runs the declared sources and updates the current evaluation. `status`
says what divinate currently knows. `review` says what changed since the
preceding evaluation.

underneath that interface, divinate retains remote acquisitions and local tool
executions, records collection coverage, and keeps historical evidence
immutable. when the available evidence cannot establish a claim, the result
names the gap instead of guessing.

## configure a repository

bootstrap a new repository from its checkout:

```sh
divinate init
$EDITOR divinate.yaml
```

`init` derives repository identity from `origin`, derives the branch from Git,
creates `.evidence/`, and writes a minimal `divinate.yaml`. commit the YAML file
so source configuration can be reviewed with the rest of the repository.

a repository using the built-in release SBOM source can declare:

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

plain executable names are resolved through `PATH`. source-specific settings,
including the SBOM tool and path, stay inside that source's configuration.
filenames are not guessed as evidence identity.

an external pack and one of its collectors use the same source model:

```yaml
repository:
  identity: github:cyberwitchery/example
  branch: main

packs:
  cyberwitchery.github:
    executable: divinate-pack-github

sources:
  github:
    provider:
      pack: cyberwitchery.github
      collector: repository
    required: true
```

pack executables are installed separately. the configured pack name must equal
the identity reported by the executable. secrets do not belong in
`divinate.yaml`; credential-like configuration keys are refused.

## collect and review

after configuration:

```sh
divinate collect
divinate status
```

`collect` validates `divinate.yaml`, resolves shared repository or release
context, invokes every declared source in deterministic order, retains valid
evidence and configuration provenance, evaluates the current assertions, and
writes `.evidence/dossiers/current.md`.

after a later collection cycle:

```sh
divinate collect
divinate review
```

the former current evaluation becomes `previous`, so `review` can compare the
pair without arguments. export a due-diligence view with:

```sh
divinate export dd
```

an already configured checkout needs no initialization ceremony:

```sh
git clone <repository>
cd <repository>
divinate collect
```

when `divinate.yaml` exists, `collect` creates local `.evidence/` state and binds
it to the verified repository identity automatically.

## explicit and forensic operations

normal collection accepts explicit scope when repository history is ambiguous:

```sh
divinate collect --release v1.5.0 --base-release v1.4.0
```

lower-level operations remain available for historical analysis, pack
development, and provenance inspection:

```sh
divinate packs
divinate pack cyberwitchery.github
divinate collect release --help
divinate collect pack --help
divinate collect manifest --help
divinate evaluate --help
divinate run --help
divinate verify
divinate provenance <assertion-id>
divinate extract <execution-id> --output retained-output.json
```

see the [command reference](docs/commands.md) for the complete interface.

## install

divinate requires rust 1.95 or newer:

```sh
cargo build --release --bin divinate
install -m 0755 target/release/divinate /usr/local/bin/divinate
```

the second command is optional and may require another destination or additional
permissions.

## documentation

- [getting started](docs/getting-started.md) configures and runs the normal loop.
- [command reference](docs/commands.md) documents normal and advanced commands.
- [concepts](docs/concepts.md) defines evidence, coverage, assertions, and time.
- [workflows](docs/workflows.md) covers recurring and explicit workflows.
- [state and formats](docs/state.md) describes `divinate.yaml`, `.evidence/`, and
  the schemas.
- [security](docs/security.md) states the trust boundaries and retention rules.
- [troubleshooting](docs/troubleshooting.md) covers common failures and gaps.
- [packs](docs/packs.md) documents declarative pack configuration and protocol
  behavior.
- [design](DESIGN.md) records implementation invariants for maintainers.

## scope

divinate is not a scanner, hosted evidence service, dashboard, compliance
catalog, or policy language. markdown dossiers and views are the
human-readable product surface. json remains available through `--json` and the
forensic commands.

content addressing detects changes after capture. it does not prove that a
source was truthful, a tool was correct, or a host clock was accurate.

## license

apache-2.0. external packs carry their own licenses.
