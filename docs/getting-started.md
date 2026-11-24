# getting started

this guide walks through divinate once from start to finish: install it,
collect a repository, look at what came back, and check a rule against it. we
use divinate’s own repository as the example. it’s public, so you can run
every command yourself. your numbers will differ from the ones here, because
the repository keeps changing.

## install

```sh
cargo install --path .
```

## log in

divinate uses the login of your command line tool or an env var:

| for | it asks | or reads |
|---|---|---|
| github | `gh auth token` | `GITHUB_TOKEN` |
| gitlab | `glab config get token --host gitlab.com` | `GITLAB_TOKEN` |
| azure devops | `az account get-access-token` | `AZURE_DEVOPS_EXT_PAT` |

if `gh auth status` says you are logged in, you are ready for this tutorial
(it’s on github). read access is enough.

## collect a repository

```console
$ divinate collect github:cyberwitchery/divinate
collected github:cyberwitchery/divinate: 179 records, 0 gaps
col_6005c5db32e5a3a13363
```

this can take a few minutes. divinate reads the repository’s settings, every
issue and pull request opened or merged in the last 90 days, and what happened
to each. comments, reviews, ci results, and merges are all accounted for. to
cover a different period, pass `--from` and `--until` with times such as
`2026-01-01T00:00:00Z`.

everything is stored in a new directory called `evidence/`. the last line is
the id of this collection, which you can use later to refer to it.

## look at the collection

```console
$ divinate show
github:cyberwitchery/divinate · collected 2026-11-24T17:21:38Z · col_6005c5db32e5a3a13363
179 records, 0 gaps

github:cyberwitchery/divinate
  ■ repository              public, default branch main
  ■ tickets                 28 tickets
  ■ changes                 44 changes
  ■ merged changes          41 changes
  ■ code scanning findings  9 findings
  ■ dependency findings     no findings
  ■ secret findings         no findings

github:cyberwitchery/divinate@claude/docs-ci-cleanup
  ■ updates                 1 event
  ■ branch protection       not protected
  ■ branch rules            no rules
  ■ review policy           no review required
  ■ required checks         none required

github:cyberwitchery/divinate@main
  ■ updates                 51 events
  ■ branch protection       protected
  ■ branch rules            deletion, non_fast_forward, required_status_checks
  ■ review policy           1 approval (branch protection)
  ■ required checks         success (ruleset 26609762)

■ recorded   ▣ changed since previous   ⬚ not available: reported as a gap
```

the first block is the repository. divinate calls issues “tickets” and pull
requests “changes”, so that the same words work for all forges and origins.
there were 28 issues and 44 pull requests in the last 90 days, and 41 pull
requests were merged.

the other two blocks are branches. `main` requires one approval and a passing
check called `success`, and it was updated 51 times. the second branch is there
because one pull request was merged into it. divinate looks at every branch
that something was merged into.

a row that starts with `⬚` is something divinate could not read, with the
reason on the right. the usual reason is a token that lacks a permission, but
failures are weird and wonderful and multitudinous. there are none in the run
above. in our document [reading the record](record.md) we explain every row.

## check a rule

say the team has agreed on this: someone answers every bug report within a
week, the bug is closed within 30 days, and the fix is reviewed by someone
other than its author (the example from the readme). written down for divinate,
that is:

```yaml
process: bug tickets
items:
  kind: ticket
  label: bug
steps:
  - name: answered
    event: comment
    by: someone else
    within: 7d
  - name: resolved
    event: closed
    within: 30d
  - name: fix reviewed
    linked: change
    event: approval
    by: someone else
    before: merge
```

save it as `bug-tickets.yaml` and run:

```console
$ divinate check bug-tickets.yaml
bug tickets · github:cyberwitchery/divinate · as of 2026-11-24T17:23:42Z
tickets opened 2026-08-26T17:21:38Z to 2026-11-24T17:21:38Z: 28 read, 6 labelled "bug"

item                              answered     resolved     fix reviewed
github:cyberwitchery/divinate#27  broken       kept         broken
github:cyberwitchery/divinate#28  broken       pending      n/a
github:cyberwitchery/divinate#31  broken       kept         broken
github:cyberwitchery/divinate#32  broken       kept         broken
github:cyberwitchery/divinate#40  broken       kept         kept
github:cyberwitchery/divinate#49  broken       kept         kept

answered      6 broken
resolved      5 kept, 1 pending
fix reviewed  2 kept, 3 broken, 1 n/a

not kept
  github:cyberwitchery/divinate#27 · answered: broken, no comment by someone else within 7d
  github:cyberwitchery/divinate#27 · fix reviewed: broken, github:cyberwitchery/divinate#64: merge without approval by someone else before it
  github:cyberwitchery/divinate#28 · answered: broken, no comment by someone else within 7d
  github:cyberwitchery/divinate#28 · resolved: pending, closed due by 2026-11-30T14:33:49Z
  github:cyberwitchery/divinate#28 · fix reviewed: n/a, no change closes it or is linked to it
  ...
```

there is one line per bug report and one column per step. below the table,
every result other than `kept` comes with its reason. reading a few of them:

- nobody but the reporter commented on any of the six within a week, so
  `answered` is broken everywhere.
- `#28` is still open and its 30 days run until 30 november, so `resolved` is
  pending. it has no pull request yet, so there is no fix to review.
- `#27`, `#31`, and `#32` were all closed by pull request `#64`, which was
  merged without an approval.

divinate finds the fix for a bug through the closing keyword in the pull
request, such as “fixes #27”, or through the link that the platform itself
keeps.

[process definitions](processes.md) lists everything a rule can use,
including rules about pull requests and branches.

## run it again later

each `collect` adds a new collection and leaves the earlier ones alone. once
you have a few, `divinate ledger` shows them next to each other, one column per
collection, and marks the rows that changed with `▣`. this helps you discover
slipping controls!

a scheduled job that runs `divinate collect` once a day or once a week is the
easiest way to build up this history. in other words: your ci can check your
ci.

## hand it over

the `evidence/` directory is the whole thing! you can copy it, archive it, or
give it to an auditor. whoever receives it can run:

```console
$ divinate verify
verified 1 collections and 215 transcripts
```

this checks that the directory is complete and that nothing in it was changed,
and it works without network access or a login. after that they can run
`show`, `ledger`, and `check` with their own rules on your data.

the directory contains what the platform returned, including issue texts,
comments, and account names, so handle it with the same care as the repository
itself. [security](security.md) has the details.
