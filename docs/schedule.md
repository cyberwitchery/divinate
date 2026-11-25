# collecting on a schedule

divinate knows more the more often it collects. branch settings are recorded
as of each collection, so a rule that needs the settings at the time of a
merge answers `cannot tell` when they changed between the collections around
it. and github keeps one year of branch activity, so older updates can only be
checked if they were collected in time.

this page describes a ci job that runs `divinate collect` on a schedule, where
`evidence/` should live between its runs, and how fast the directory grows.

## where to keep `evidence/`

the directory holds what the platform returned: the texts of tickets and pull
requests, comments, account names, settings, scanner alerts, and, unless you
collect with `--no-files`, the diff of every pull request.
[security](security.md#whats-in-evidence) lists all of it. the people who may
see the repository’s issues and security alerts are the people who should see
`evidence/`.

a private git repository that holds nothing but the record is a good home for
it, because you decide who can read it. divinate only ever adds files, and
names each one by a checksum of its contents, so every run is a commit that
adds files and changes none. any clone is a complete copy that `divinate
verify` can check. the examples below run the job in that repository as
well. that way, changing the job takes the same access as changing the
record, and write access to the repository you collect gives you neither.

a ci cache or an artifact is no place for a record. both are meant to be
temporary, and the ci platform deletes them after a while. a record is only as
useful as its oldest collection, and when the directory is gone, the next
`collect` starts a new one without complaint, so nothing tells you that the
history before it is lost.

## the jobs

[examples/schedule](../examples/schedule) has a github actions workflow and a
gitlab ci job. copy one into the record’s repository, set `SCOPE` in it to
what you collect, and add the tokens below. the workflow runs once a day,
and the gitlab job whenever the project’s pipeline schedule says. each run
clones the record’s repository, runs `divinate collect` and `divinate
verify`, and commits and pushes `evidence/` back. `verify` checks the whole
directory, the old collections as well as the new one, so a damaged copy
fails the job before anything is pushed.

only one run writes at a time: the workflow is in a `concurrency` group and
the gitlab job in a `resource_group`. a run that had to wait for another
starts from the commit that one pushed, not from the one it was queued with.

there is no release of divinate yet, so both jobs build it from a fixed commit
of this repository with `cargo install`. change `--rev` to update it.

each job uses two tokens, one to read what it collects and one to push to the
record:

| | reads | pushes |
|---|---|---|
| github actions | the secret `DIVINATE_TOKEN`, passed to divinate as `GITHUB_TOKEN` | the job’s own token, with `contents: write` |
| gitlab ci | the variable `GITLAB_TOKEN` | the variable `RECORD_PUSH_TOKEN`, a project access token with `write_repository` |

on github, the job’s own token only reaches the record’s repository, so
reading takes a token of its own. divinate takes a github token from `gh auth
token` and then from `GITHUB_TOKEN`, and a gitlab token from `glab` and then
from `GITLAB_TOKEN`. what the reading token has to be allowed is in
[sources](sources.md). on github, read access to the repository covers almost
everything, the three alert rows need a token that may read security events,
and only an admin’s can read `branch protection`. on gitlab, approval
settings and approval rules are only shown to members of the project.

## how it grows

collections don’t share transcripts. a transcript is named by a checksum of
its contents, and the contents include the time it was captured, so a second
collection stores its own copy of everything, even when the platform said the
same thing as before. each collection also reads its whole period again, the
last 90 days unless you pass `--from` and `--until`. so every run adds about
as much as the first one did.

we ran the steps of the github job twice, a few minutes apart, on divinate’s
own repository, with a bare git repository called `record.git` standing in
for the record’s repository. the period had 28 tickets and 47 pull requests.
after the first run, `evidence/` took 12M and `record.git` 1.8M. after the
second, in a fresh clone:

```console
$ divinate verify
verified 2 collections and 550 transcripts
$ du -sh evidence/collections evidence/transcripts evidence ../record.git
2.0M	evidence/collections
 23M	evidence/transcripts
 25M	evidence
3.5M	../record.git
```

each collection had 275 transcripts, and none of them was in both. git
compresses the files, so the repository grows by much less than the
directory. the lists of files that the pull requests touched, which
`--no-files` leaves out, were a third of the transcripts. a job that runs
every day on a repository this busy adds about 12M a day to the directory,
and under 2M to its git repository.
the jobs clone the latest commit, which holds every collection, so the clone
takes a little longer every time.
