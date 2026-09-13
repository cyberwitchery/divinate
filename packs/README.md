# in-tree packs

each directory contains one executable implementing pack protocol version 1. see
[the protocol documentation](../docs/packs.md).

- `cargo-lock` is the repository's dogfood source. it retains and parses the
  exact Cargo.lock dependency inventory and derives a repository-scoped claim.
- `github` plans branch-protection, check-run, and commit-status reads. core performs the
  authenticated requests; the pack receives only retained response bytes.
- `sbom-collector` collects and normalizes `sbom-diff` output.
- `config-collector` shows a configuration-driven collector.
- `external-evaluator` evaluates observations produced by another pack.

the three `example.*` packs are fixtures. they use Python for readability and are
executed by the test suite. declare pack executables and collectors in
`divinate.yaml`; no pack configuration is installed into `.evidence/`.
