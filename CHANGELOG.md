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
- dogfood committed configuration with a repository-scoped Cargo.lock source
- collect authenticated GitHub branch protection, check runs, and commit
  statuses through credential-safe core acquisition
- verify projectless execution state without inventing a corpus or repository
- support canonical Azure DevOps repository identity and current branch-policy
  evidence through credential-safe core acquisition
- keep typed branch-policy evaluators scoped to their observation schema
- render shared governance claims without duplicate provider-specific rows or gaps
- remove the scanner-specific `collect release` compatibility command
- allow repository-scoped evaluation without inventing a release
- run each pack in its own working directory, removed when the run ends
- never credit a collection run with coverage at or after its own start; remote
  acquisitions observe only up to their capture time
- reject a `collect --until` later than the collection time
- parse git origins with `gix-url`, accepting every url form git does, including
  the empty-port form `insteadOf` rewrites produce
- declare a mirror with `repository.mirror_of`, withdrawing its authority for
  integration, review, branch configuration, and ci propositions, whether the
  evidence was collected or imported
- reject pack support or contradictions drawn from a failed, denied, or
  unattempted collection run, or from a declared mirror
- stop the github pack from contradicting required status checks it never observed
- name the actual reason when branch-protection evidence is not authoritative
- follow github history pagination onto `/repositories/{id}` links, proven
  equivalent by a retained repository lookup
- re-evaluate the whole interval on every collection instead of only the time
  since the previous evaluation, and pair review claims without the interval end
- report the transport error when a github or azure devops request fails before
  a response
- keep a github or azure devops error response whose body is not json, such as
  an empty 500 or an html sign-in page, as its classified http failure instead
  of aborting collection
- derive one repository identity from every origin form: a `*.visualstudio.com`
  origin keeps its organization's case as the `dev.azure.com` and ssh forms do,
  github's `ssh.github.com` ssh origin is accepted, and a github origin whose
  owner or repository name github would not allow yields no identity
- reject an acquisition transcript linked to a collection run about another kind
  of subject or other qualifiers, such as another branch, or recorded for a
  branch other than the one the run requested
- read github and azure devops history by each response's exact api route, so an
  owner, repository, organization, or project named like a route segment, such
  as `activity`, `pulls`, or `PullRequests`, no longer fails normalization or
  loses a merge's pull request
- refuse github check-run, commit-status, and commit pagination onto another
  repository or revision, following only `/repositories/{id}` links that a
  retained repository lookup proves equivalent
- count the commit-status pages github links through
  `/repositories/{id}/status/{sha}`, so a build-validation history whose
  statuses for a revision span more than one page no longer fails assessment
- verify a long github or azure devops history in time linear in its exchanges
  instead of quadratic
- leave the repository lookup that opens a github repository-mutation,
  pull-request-review, or build-validation history out of the pages and items
  its collection run and dossier report, as check runs, commit statuses, and
  commits already do
- report a wrong or expired azure devops credential as permission denied, with
  azure's own `TF400813` message, instead of as a failed collection citing a
  refused redirect to azure's sign-in page
- report a github secondary rate limit, and any rate limit `gh` reports, as rate
  limited instead of as permission denied or a failed collection
