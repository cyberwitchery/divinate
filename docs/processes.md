# process definitions

a process definition is a yaml file in which you write down a rule your team
works by. `divinate check <file>` then goes through the latest collection and
tells you, item by item, whether the rule held.

the file is yours and lives wherever you like (next to the code it’s about is
a good place). it isn’t stored in `evidence/`, so you can write a new rule
tomorrow and check it against the collections you already have.

there are two kinds of rules. steps are about tickets, pull requests,
findings, and releases: “every bug is answered within a week”. branch rules
are about settings: “main requires a review”. one file can have both. a file
can also ask for [numbers](#numbers), such as the median time it takes to
close a bug.

## steps

this is the example from [getting started](getting-started.md):

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

`process` is the name that shows up in the output. `items` picks what the
rule is about, and every entry in `steps` is one thing that has to happen to
each of those items.

### picking items

| key | meaning |
|---|---|
| `kind` | `ticket`, `change` (a pull or merge request), `finding` (a scanner alert), or `release` |
| `label` | only items with a label matching this pattern, or one of a list of patterns. for a finding, the label is its severity, such as `high` |
| `when` | `opened` picks the items opened in the period, which is the default. `merged` picks the pull requests merged in it |
| `into` | only pull requests into this branch. give a branch name, or `default branch` for the default branch of each repository |
| `paths` | only pull requests that touch a file matching one of these patterns, such as `src/auth/**` |

### writing a step

a step names an event and says when it has to happen. the events are the ones
listed in [reading the record](record.md): `comment`, `closed`, `approval`,
`merge`, `check passed`, and so on.

| key | meaning |
|---|---|
| `name` | what the step is called in the output |
| `event` | the event that has to happen. a list such as `[closed, dismissed]` means any one of them |
| `by` | `someone else` means anyone but the person who opened the item. a list of account names such as `[alice, bob]` means one of them (and still not the person who opened the item) |
| `named` | one such event for each of these names. this is how you ask for a ci check by its name |
| `within` | how long after the item was opened, such as `7d` or `12h` |
| `before` | the event it has to come before, such as `merge` |
| `after` | the event it has to come after, such as `commit` |
| `at least` | how many times it has to happen, each time by a different person. the default is once |
| `linked` | look for the event on a linked item of this kind. `linked: change` on a ticket means the pull request that closes it |
| `of` | `required checks` asks for the event once for every check the branch requires |
| `ref` | where the rule comes from, such as “ssdlc 4.2”. it’s printed below the results |

a step can have `within` or `before`, but not both.

two kinds of step ask for something other than an event, and are written
without `event`:

| key | meaning |
|---|---|
| `label` | the item has a label matching one of these patterns |
| `asset` | the release has an attached file whose name matches one of these patterns |

a few of these are easier to understand in an example. this one is about pull
requests: each one merged into a default branch needs as many approvals as the
branch requires, the approvals have to be given after the last commit, and
every required check has to pass before the merge.

```yaml
process: merged changes
items:
  kind: change
  when: merged
  into: default branch
steps:
  - name: reviewed
    event: approval
    by: someone else
    at least: required
    after: commit
    before: merge
  - name: validated
    event: check passed
    of: required checks
    before: merge
```

`at least: required` takes the number from the review policy of the branch,
so the same file works for a repository that wants one approval and one that
wants two. you can also write a number. `after: commit` together with `before:
merge` means the approval has to come after the last commit before the merge,
which catches the pull request that was approved and then changed. an approval
only counts while it stands: it’s gone when the reviewer asks for changes
later or takes it back, or when someone dismisses it.

`of: required checks` looks up which checks the branch requires and asks for
a `check passed` for each of them by name. if the branch requires none, the
step is `n/a`. it can’t be combined with `within` or `at least`.

here is one that puts several of the newer pieces together. pull requests that
change the ci workflows are the sensitive ones in many repositories, so this
rule only looks at those, and wants a review and a passing check called
`success` on each:

```yaml
process: workflow changes
items:
  kind: change
  when: merged
  paths: .github/workflows/**
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
  - name: tests passed
    event: check passed
    named: [success]
    before: merge
```

```console
$ divinate check workflow-changes.yaml
workflow changes · github:cyberwitchery/sbom-diff · as of 2026-11-24T23:53:50Z
changes merged 2026-08-26T23:51:01Z to 2026-11-24T23:51:01Z: 58 read, 11 touching .github/workflows/**

item                                reviewed     tests passed
github:cyberwitchery/sbom-diff#141  kept         kept
github:cyberwitchery/sbom-diff#152  kept         kept
github:cyberwitchery/sbom-diff#159  kept         kept
github:cyberwitchery/sbom-diff#168  cannot tell  cannot tell
github:cyberwitchery/sbom-diff#170  kept         kept
github:cyberwitchery/sbom-diff#171  broken       kept
...
```

`#168` is `cannot tell` because github answered one request of that run with
an error, so divinate doesn’t know which files the pull request touched. it
keeps it in the list for that reason.

### patterns

`paths`, `named`, `label`, and `asset` take patterns. `*` stands for any
number of characters and `?` for one. in `paths`, a `*` stops at a `/`, and
`**` goes across directories, so `src/*.rs` matches `src/main.rs` and
`src/**` matches everything below `src`. a pattern that starts with `*` has to
be in quotes, because yaml gives a leading `*` a meaning of its own.

### releases

releases have no reviews or comments, but they have attached files. this rule
wants a cyclonedx sbom and a signature on every release:

```yaml
process: releases
items:
  kind: release
steps:
  - name: sbom attached
    asset: '*.cdx.json'
  - name: signed
    asset: ['*.sig', '*.bundle']
```

```console
$ divinate check releases.yaml
releases · github:cyberwitchery/sbom-diff · as of 2026-11-24T23:53:50Z
releases published 2026-08-26T23:51:01Z to 2026-11-24T23:51:01Z: 5 read

item                                            sbom attached  signed
github:cyberwitchery/sbom-diff release v0.9.0   kept           broken
github:cyberwitchery/sbom-diff release v0.9.1   kept           broken
github:cyberwitchery/sbom-diff release v0.9.2   kept           broken
github:cyberwitchery/sbom-diff release v0.10.0  kept           broken
github:cyberwitchery/sbom-diff release v0.11.0  kept           broken
...
```

a release also has one event, `published`, so `event: published` with `by:
[alice, bob]` checks that only certain people cut releases.

### findings

every alert of high severity is closed or dismissed within 30 days:

```yaml
process: high findings
items:
  kind: finding
  label: high
steps:
  - name: dealt with
    event: [closed, dismissed]
    within: 30d
```

## branch rules

```yaml
process: change governance
branches:
  - name: review required
    approvals: 1
  - name: checks required
    checks: 1
  - name: no direct updates
    without: [push, force push]
```

every rule has a `name` and exactly one of these:

| key | meaning |
|---|---|
| `approvals` | the branch requires at least this many approvals before a merge |
| `checks` | the branch requires at least this many checks before a merge |
| `without` | none of these events happened on the branch in the period |

the rules are checked for every branch in the collection, which means the
default branch of each repository and every branch a pull request was merged
into.

## numbers

some questions want a number as an answer. `measures` works them out over the
items the file picks:

```yaml
measures:
  - name: reviewed share
    share: reviewed
  - name: time to merge
    from: opened
    to: merge
```

`share` takes the name of a step and gives the percentage of items that kept
it, among those that kept or broke it. `from` and `to` take two events and
give the median time between them. added to the workflow example from above,
this prints:

```
reviewed share  80% (8 of 10 kept; 1 pending, unknown, or not applicable left out)
time to merge   9.3 hours (median from opened to merge over 11 of 11 items)
```

the part in parentheses says how many items the number rests on.

## frameworks

a rule usually exists because some standard, contract, or policy asks for
it. `maps` records that, and `frameworks` lists the requirements you care
about, so the output can tell you what your rules add up to:

```yaml
process: software change governance
frameworks:
  iso 27001:
    title: iso/iec 27001:2022
    targets:
      a.5.3: segregation of duties
      a.8.4: access to source code
      a.8.29: security testing in development and acceptance
      a.8.32: change management
items:
  kind: change
  when: merged
  into: default branch
steps:
  - name: reviewed
    event: approval
    by: someone else
    at least: required
    after: commit
    before: merge
    maps:
      - framework: iso 27001
        target: a.8.32
        strength: partial
        limitation: authorization of the change, its testing, and approval of its deployment
      - framework: iso 27001
        target: a.5.3
        strength: partial
        limitation: that the reviewer is independent of the author beyond being another account
```

(the full file has three more rules, mapped the same way.) a mapping names a
requirement, says whether the rule answers it in `full` or in `partial`, and
can say what the rule doesn’t establish even when it’s kept. that last part
is worth writing down: “every pull request was approved” is evidence for
change management, but it says nothing about whether the change was tested.

after the usual results, `check` prints every requirement with the rules that
speak to it and what they found:

```
iso/iec 27001:2022
  a.5.3 segregation of duties
    reviewed (partial): 50 kept, 7 broken, 1 cannot tell
      does not establish: that the reviewer is independent of the author beyond being another account
  a.8.4 access to source code
    no direct updates (partial): 1 broken
      does not establish: who has write access, which is not read
  a.8.29 security testing in development and acceptance: no rule
  a.8.32 change management
    reviewed (partial): 50 kept, 7 broken, 1 cannot tell
      does not establish: authorization of the change, its testing, and approval of its deployment
    validated (partial): 57 kept, 1 cannot tell
      does not establish: that the required checks test what matters
    review required (partial): 1 kept
    no direct updates (partial): 1 broken
```

a requirement with `no rule` is one you listed and have nothing for yet.
divinate doesn’t turn this into a verdict on the requirement. it shows what
you have, and whoever signs off decides whether that’s enough.

you can check several definitions in one run (`divinate check a.yaml
b.yaml`). when they name the same framework, the list at the end covers all
of them together.

## checks from packs

when a rule needs something divinate can’t express, such as “the checklist in
the description is filled in”, a pack can do the judging. a step then names
the pack’s check with `uses`:

```yaml
steps:
  - name: checklist completed
    uses: acme/checklist-completed
```

packs can also judge all items together under `overall`, and work out
numbers under `measures`. [packs](packs.md) explains how to use and write
them.

## results

every step and every rule gets one of five results:

| result | meaning |
|---|---|
| kept | it happened, and in time |
| broken | it didn’t happen, or it happened too late. the output says which |
| pending | it can still happen: the deadline hasn’t passed, or the item is still open |
| cannot tell | divinate is missing something it needed, and the output says what |
| n/a | the step doesn’t apply to this item, such as a review step on a ticket that has no pull request |

`cannot tell` is what you get when the collection has a
[gap](record.md#gaps) where the answer would be. a token without permission to
read the branch settings, for instance, makes every `at least: required` step
answer `cannot tell`. fix the gap, collect again, and the step gets a real
result. when the list of tickets or pull requests itself couldn’t be read,
the whole check answers `cannot tell`, since divinate doesn’t know which items
there are.

## many repositories, many collections

`check` looks at the latest collection. with `--all` it prints a summary for
every repository you collected:

```console
$ divinate check change-governance.yaml --all
change governance

github:cyberwitchery/divinate · as of 2026-11-24T17:23:42Z
  review required    1 kept, 1 broken
  checks required    1 kept, 1 broken
  no direct updates  1 kept, 1 broken
```

the collection has two branches, so each rule has two results.

`--last 8` does the same for the last eight collections of one repository,
oldest first, so you can see whether things are getting better.

`--json` prints the results for a script. you get one report, or a list of
them with `--all` or `--last`. each report has the repository, the time of the
collection, what was picked, and a row per item and per branch. a result looks
like `{"outcome": "broken", "reason": "..."}`, and the outcomes are `kept`,
`broken`, `pending`, `cannot_tell`, and `not_applicable`.

## good to know

- `someone else` compares accounts. a person with two accounts counts as two
  people.
- `within` counts from the moment the item was opened. a ticket that got its
  `security` label a week after it was opened has already used up that week.
- `check passed` looks at the checks on the last commit of the pull request.
- labels are the ones the item has at the time of the collection. divinate
  doesn’t know when a label was added.
- a list of accounts in `by` uses the account names as the platform spells
  them, without the `github:` in front. upper and lower case don’t matter.
- without `into`, `when: merged` picks the pull requests merged into any
  branch.
- `required` uses the branch settings from the first collection after the
  merge. if the collection before the merge had different settings, divinate
  doesn’t know which ones applied and the step answers `cannot tell`.
  collecting more often makes that rarer.
