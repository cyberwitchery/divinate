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
- read releases with their attached files, and the files each change touches,
  on github and gitlab
- on gitlab, record each job of a merge request's latest pipelines as a check
  under its own name
- process definitions: select changes by `paths`, select releases, ask for
  checks by name with `named`, for approval by named accounts, for a label
  or an attached file, and for numbers with `measures`
- rules can map to the requirements of a framework with a strength and a
  limitation, and `check` lists what each requirement is covered by
- `check` takes several definitions, and `<pack>:` for all a pack ships
- packs: external programs declared in `divinate.yaml` that judge items in a
  `check`, ship process definitions, or read a system as a source, with
  `divinate pack` to list what one offers
- an osv pack that reads the sboms attached to a repository's releases and
  records known vulnerabilities as findings
- remove claims and their five results, the dossier, the earlier pack protocol, the
  manifest import, and the release workflow
