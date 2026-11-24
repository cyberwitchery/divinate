# changelog

## unreleased

divinate was rebuilt before its first release. it now keeps a record and holds
no verdicts.

- read github, gitlab, and azure devops: organisations, groups, and projects
  with their repositories and default branch settings, and single repositories
  or projects with their tickets, changes, checks, and branch updates
- read github code, dependency, and secret scanning findings
- record every statement as a value or as a gap with its reason, and keep every
  source response as a transcript addressed by its digest
- `collect`, `show`, and `ledger` to add to the record and read it
- `verify` to check the record offline: digests, and every statement derived
  again from the transcripts
- `check` to read a collection against a process definition: steps on work
  items, rules on branches, summaries across collections and scopes, and json
  output
- remove claims and their five results, the dossier, the pack protocol, the
  manifest import, and the release workflow
