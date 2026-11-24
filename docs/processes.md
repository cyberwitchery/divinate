# process definitions

a process definition is a yaml file in which you write down a rule your team
works by. `divinate check <file>` then goes through the latest collection and
tells you, item by item, whether the rule held.

the file is yours and lives wherever you like (next to the code it’s about is
a good place). it isn’t stored in `evidence/`, so you can write a new rule
tomorrow and check it against the collections you already have.

there are two kinds of rules. steps are about tickets, pull requests, and
findings: “every bug is answered within a week”. branch rules are about
settings: “main requires a review”. one file can have both.

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
| `kind` | `ticket`, `change` (a pull or merge request), or `finding` (a scanner alert) |
| `label` | only items with this label. for a finding, this is its severity, such as `high` |
| `when` | `opened` picks the items opened in the period, which is the default. `merged` picks the pull requests merged in it |
| `into` | only pull requests into this branch. give a branch name, or `default branch` for the default branch of each repository |

### writing a step

a step names an event and says when it has to happen. the events are the ones
listed in [reading the record](record.md): `comment`, `closed`, `approval`,
`merge`, `check passed`, and so on.

| key | meaning |
|---|---|
| `name` | what the step is called in the output |
| `event` | the event that has to happen. a list such as `[closed, dismissed]` means any one of them |
| `by` | `someone else` means anyone but the person who opened the item |
| `within` | how long after the item was opened, such as `7d` or `12h` |
| `before` | the event it has to come before, such as `merge` |
| `after` | the event it has to come after, such as `commit` |
| `at least` | how many times it has to happen, each time by a different person. the default is once |
| `linked` | look for the event on a linked item of this kind. `linked: change` on a ticket means the pull request that closes it |
| `of` | `required checks` asks for the event once for every check the branch requires |

a step can have `within` or `before`, but not both.

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

and one about findings: every alert of high severity is closed or dismissed
within 30 days.

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
- without `into`, `when: merged` picks the pull requests merged into any
  branch.
- `required` uses the branch settings from the first collection after the
  merge. if the collection before the merge had different settings, divinate
  doesn’t know which ones applied and the step answers `cannot tell`.
  collecting more often makes that rarer.
