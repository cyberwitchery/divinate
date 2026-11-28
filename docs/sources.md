# sources

divinate reads from github, gitlab, and azure devops. this page lists what you
can point it at, what it reads on each platform, and the places where the
platforms behave differently enough that you should know about it.

## what you can collect

the argument to `divinate collect` is the platform, a colon, and a path:

| you write | divinate reads |
|---|---|
| `github:acme/shop` | the repository, its branches’ settings, and its issues, pull requests, releases, and alerts |
| `github:acme` | the organisation, its repositories, and the settings of each default branch |
| `gitlab:acme/shop` | the project, its branches’ settings, and its issues, merge requests, and releases |
| `gitlab:acme` | the group, the projects in it and in its subgroups, and the settings of each default branch |
| `azure:acme/shop` | the project, its repositories and their branch policies, its work items, and its pull requests |
| `azure:acme` | the organisation, its projects and repositories, and the policies of each default branch |

collecting a single repository gives you everything, including the tickets and
pull requests you need for most rules. collecting an organisation is the quick
way to see the branch settings of every repository at once.

on gitlab a path like `acme/shop` can be a group or a project. divinate tries
it as a group first.

divinate talks to `github.com`, `gitlab.com`, and `dev.azure.com`.

## every repository of an organisation

collecting an organisation reads the branch settings of its repositories, but
not their tickets, pull requests, releases, or findings. for those, collect
each repository on its own. on github, `gh repo list` gives you their names:

```sh
for repository in $(gh repo list acme --no-archived --limit 1000 \
    --json nameWithOwner --jq '.[].nameWithOwner'); do
  divinate collect "github:$repository"
done
divinate check change-governance.yaml --all
```

without `--limit`, `gh repo list` stops after 30 repositories. `--no-archived`
skips archived repositories, so leave the flag out if one was archived during
the period you collect. each repository gets a collection of its own, and
`check --all` prints a summary for the latest one of each. on gitlab and azure
devops the loop is the same, over the paths of the projects.

a repository that can’t be read doesn’t stop the loop. what divinate couldn’t
read becomes a gap in that repository’s collection, and `collect` succeeds as
usual. if the loop itself is stopped partway, the repository it was reading
gets no collection, because divinate writes one only at the end of a run. run
the loop again for that repository and the ones after it.

the loop makes many requests, about five per pull request on github. when the
platform says to wait a short while, as gitlab.com does, divinate waits, and
the loop takes longer. when the wait is long or not given, as when a github
token has used up its requests, divinate stops reading that repository and
marks the rest of its readings `not attempted`. the repositories after it will
likely get the same answer until the limit lifts, so the line `collect` prints
for each of them says `0 records`. collect that repository and the ones after
it again later. the new collections are the ones `check` uses, and the old
ones stay where they are.

## what comes from where

divinate uses the same words on every platform. this is what they stand for:

| | github | gitlab | azure devops |
|---|---|---|---|
| tickets | issues | issues | work items |
| changes | pull requests | merge requests | pull requests |
| review policy | branch protection and rulesets | approval settings and approval rules | branch policies |
| required checks | branch protection and rulesets | the project’s merge settings | build and status policies |
| checks on a change | check runs and commit statuses | pipelines, and the jobs on the latest commit | policy evaluations |
| branch updates | the branch’s activity | push events | pushes |
| which change fixes a ticket | closing keyword in the description | the closing reference gitlab keeps | the pull request link on the work item |
| changed files | the pull request’s file list | the merge request’s diffs | |
| releases | releases and their assets | releases and their asset links | |
| findings | code scanning, dependabot, and secret scanning alerts | | |

## github

divinate asks `gh auth token` for a token and falls back to `GITHUB_TOKEN`.

- **permissions.** read access to the repository covers almost everything.
  classic branch protection can only be read by an admin, and rulesets can be
  read by anyone with read access. if you aren’t an admin, the `branch
  protection` row is a gap and `review policy` shows what the rulesets
  require, with a note. the three alert rows need a token that may read
  security events.
- **scanners that are off.** a scanner that isn’t enabled shows up as `no
  findings` with a note saying so.
- **reviews.** a dismissed review is recorded as `approval withdrawn`.
- **commit times.** github knows when a commit was made, and that can be long
  before it was pushed to the pull request. divinate uses the order of commits
  and the commit each review looked at, so a commit that came after a review
  is never dated before it. force pushes are recorded when they happened.
- **branch updates** go back one year at most.
- **changed files.** github lists at most 3000 files of a pull request. the
  description of a ticket or pull request is kept as github returns it.
- **releases.** drafts are left out. github reports a sha-256 checksum for
  each attached file, and divinate keeps it.
- **how long it takes.** expect about five requests per pull request in the
  period.

## gitlab

divinate asks `glab config get token --host gitlab.com` for a token and falls
back to `GITLAB_TOKEN`.

- **permissions.** approval settings and approval rules are only shown to
  members of the project. for everyone else, `review policy` is a gap.
- **reviews.** gitlab only lists the approvals that stand right now. the ones
  that were given and taken back earlier, and the times commits were added,
  come from the system notes on the merge request (“approved this merge
  request”). divinate reads the english notes that gitlab.com writes.
- **checks.** every pipeline of a merge request is recorded as a check called
  `pipeline`. the jobs of the pipelines that ran on the latest commit are
  recorded as checks under their own names, so a rule can ask for `secret-scan` or `sast` specifically.
  a job that was skipped or is waiting for someone to start it is neither
  passed nor failed. pipelines started by a schedule are left out, since
  gitlab lists them with a merge request whenever they ran on one of its
  commits.
- **releases.** what’s attached to a gitlab release is a list of links, so
  divinate has their names and no checksums. a release dated in the future
  is left out.
- **merges.** gitlab’s push events don’t say whether a push was a merge.
  divinate counts a push as a merge when it ends on a commit of a merged merge
  request. force pushes look like ordinary pushes.
- **how long it takes.** gitlab.com slows down clients that ask a lot in a
  short time. divinate waits when it’s told to, and a project with a few
  hundred merge requests can take several minutes.

## azure devops

divinate asks `az account get-access-token` for a token and falls back to
`AZURE_DEVOPS_EXT_PAT`. with neither it reads anonymously, which works for the
visible parts of public projects.

- **projects and repositories.** a project has the work items, and its
  repositories have the pull requests. `azure:acme/shop` reads both.
- **policies.** a policy counts as a requirement when it’s enabled and
  blocking. the other policies are listed under `branch rules`.
- **tickets.** a work item is closed when its state belongs to the completed
  or removed category of its type, so custom states work. comments are counted
  from the work item’s comment count, and their text isn’t read.
- **reviews.** a vote that was reset to zero is recorded as `approval
  withdrawn`, and a push to a pull request as a `commit`.
- **merges.** a push counts as a merge when it ends on the merge commit of a
  completed pull request. force pushes look like ordinary pushes.
- **account names** are email addresses on azure devops, and they end up in
  `evidence/`.
