# changelog

## unreleased

- add configuration-driven collection with automatic current evaluation
- add saved-state status and parameterless review
- keep explicit collection, historical evaluation, and provenance commands as
  advanced operations
- make `divinate.yaml` the strict, reviewable project configuration and keep
  `.evidence/` for observed and derived state
- let collection initialize local state from committed configuration without
  imperative source or pack setup
- retain content-addressed configuration snapshots and collection-cycle links
- run release sbom evidence through the same configured-source interface as
  external collectors
