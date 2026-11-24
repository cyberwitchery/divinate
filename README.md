# divinate

divinate collects and preserves technical evidence for security review and
compliance. what does that mean?

consider this: you review your company’s ssdlc and find the sentence: "every
ticket tagged 'security' must be triaged within 7 days and closed within 30.
if a merge request was made to close it, it has to be reviewed by someone other
than the author." how would you check that this is how everyone in your team
actually works?

divinate can help gather information about your development process and check
it against the rules you care about. it reads tickets, merge requests, reviews,
ci results, and branch settings from github, gitlab, and azure devops, and
keeps them in a local directory. it’s also extensible and customizable, and is
made to fit your workflow.

## installation

```sh
cargo install --path .
```

we’ll publish it to crates.io soon!

## usage

by default divinate reads using `gh`, `glab`, or `az`. you can also set
`GITHUB_TOKEN`, `GITLAB_TOKEN`, or `AZURE_DEVOPS_EXT_PAT` (read
access is enough!).

to gather the information for a repository, run:

```sh
divinate collect github:acme/shop
```

this reads the last 90 days of the repository and stores them in `evidence/`.
`--from` sets an earlier start. gitlab projects are `gitlab:acme/shop`, and
azure devops projects are `azure:acme/shop`. if you leave out the repository,
divinate goes through the whole organisation and reads the branch settings of
every repository in it.

every run is added to the directory, so running `collect` on a schedule gives
you a history. `divinate show` prints what the latest run found, and
`divinate ledger` puts the runs side by side and marks what changed between
them.

our case study from above would get this workflow definition:

```yaml
process: security tickets
items:
  kind: ticket
  label: security
steps:
  - name: triaged
    event: comment
    by: someone else
    within: 7d
  - name: closed
    event: closed
    within: 30d
  - name: fix reviewed
    linked: change
    event: approval
    by: someone else
    before: merge
```

then you can run:

```sh
divinate check security-tickets.yaml
```

this prints every ticket tagged `security` with a result for each step:

| result | meaning |
|---|---|
| kept | the ticket kept its promise |
| broken | it did not, and the output says why |
| pending | the deadline has not passed yet |
| cannot tell | divinate could not read what it needed, for instance because the token lacks a permission |
| n/a | the step does not apply, such as a ticket without a merge request |

rules can also be about merge requests (approved by two people, all required
checks passed before the merge) and about branches (a review is required,
nobody pushes directly). `--all` prints a summary for every repository you
collected, and `--json` prints the results for a script.

when you pass `evidence/` on to someone else, such as an auditor, they can run
`divinate verify` on it. it confirms that the files are complete and unchanged,
and it needs neither network access nor a login. they can then run their own
checks on the same data.

## documentation

- [getting started](docs/getting-started.md)
- [reading the record](docs/record.md)
- [process definitions](docs/processes.md)
- [sources](docs/sources.md)
- [commands](docs/commands.md)
- [state and formats](docs/state.md)
- [security](docs/security.md)
- [troubleshooting](docs/troubleshooting.md)

there is also an [agent skill](skills/divinate/SKILL.md) for collecting and
checking with divinate, in case you want to try your hand at vibe-verifying.

<hr/>

have fun!
