# example packs

each directory contains one executable implementing pack protocol version 1. see
[the protocol documentation](../docs/packs.md).

- `sbom-collector` collects and normalizes `sbom-diff` output.
- `config-collector` shows a configuration-driven collector.
- `external-evaluator` evaluates observations produced by another pack.

the examples are fixtures. they use python for readability and are executed by the
test suite. to run one manually, copy it outside the repository and configure its
path in `.evidence/config.json`.
