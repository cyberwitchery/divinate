# in-tree packs

the GitHub and Azure DevOps reference packs are Rust binaries, built and installed
with Divinate. the other directories contain executable fixtures. all implement
pack protocol version 1. see
[the protocol documentation](../docs/packs.md).

- `cargo-lock` is the repository's dogfood source. it retains and parses the
  exact Cargo.lock dependency inventory and derives a repository-scoped claim.
- `github` plans branch-protection, check-run, commit-status, branch activity,
  PR association, and review reads. core performs the
  authenticated requests; the pack receives only retained response bytes.
- `azure-devops` plans current branch-policy, branch-push, completed PR, and
  vote-history reads. core resolves the repository
  ID, authenticates, and retains the exact Azure responses without exposing the
  credential to the pack.
- `sbom-collector` collects and normalizes `sbom-diff` output.
- `config-collector` shows a configuration-driven collector.
- `external-evaluator` evaluates observations produced by another pack.

the three `example.*` packs are fixtures. they use Python for readability and are
executed by the test suite. declare pack executables and collectors in
`divinate.yaml`; no pack configuration is installed into `.evidence/`.
