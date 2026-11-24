---
name: divinate
description: Read how a team develops and releases software from GitHub, GitLab, or Azure DevOps into a dated, verifiable record, and check a written process against it, using the divinate CLI. Use when asked whether changes are reviewed or validated before merge, whether a branch requires review or checks, whether anyone pushed to a branch directly, whether tickets or scanner findings were handled in time, what changed in repository settings between two dates, or when setting up, running, or reading divinate (`divinate collect`, `divinate check`, the `evidence/` directory, process definitions).
---

# checking a development process with divinate

divinate copies facts about a repository out of github, gitlab, or azure
devops into a local directory: branch settings, tickets, pull requests,
reviews, ci results, branch updates, and scanner alerts. you then write the
user’s rule as a small yaml file, and `divinate check` says for every ticket
or pull request whether the rule held.

the user will often pass your answer on to someone else, such as an auditor
or a customer. so the most important part of this job is to report what
divinate found and nothing beyond it. the next section says how.

## how to report results

divinate gives every step one of five results. report each of them as what it
is:

| result | what it means | what to tell the user |
|---|---|---|
| `kept` | the rule held | say so, with the repository and the period it was checked for |
| `broken` | it didn’t happen, or happened too late | list every item with its reason |
| `pending` | it can still happen | give the deadline |
| `cannot tell` | divinate couldn’t read what it needed | say that this could not be established, what’s missing, and how to get it. don’t round it to “no problems found” |
| `n/a` | the step doesn’t apply to this item | say why |

some more things to keep in mind:

- a row in `divinate show` that starts with `⬚` is something divinate
  couldn’t read, and a `note:` line means the row is only part of the
  picture. mention both when your answer relies on that row.
- divinate checks the rule the user wrote. whether that rule satisfies iso
  27001 or a customer’s contract is for the user or their auditor to decide,
  so leave words like “compliant” to them.
- “the branch requires one approval” is a setting at the time of the
  collection. “every merged pull request was approved” is about what happened
  in the period. they’re different questions with different rows, so report
  them separately.
- always name the repository, the time of the collection, and the period.
- the definition is the user’s rule. if a check comes out `broken`, report
  that. if you think the definition doesn’t say what the user meant, ask them
  before you change a deadline, a label, or a step.
- leave the files in `evidence/` alone. when something is missing, fix the
  cause (usually the token) and collect again.

## step 1: find out what the user is asking

| question | where the answer is |
|---|---|
| does the branch require review? how many approvals? | the `review policy` row, or a `branches` rule with `approvals` |
| does the branch require ci checks? | the `required checks` row, or a rule with `checks` |
| did anyone push to the branch directly? | a rule with `without: [push, force push]` |
| was every pull request into the default branch approved by someone else before the merge? | steps on `kind: change`, `when: merged`, `into: default branch` |
| were there as many approvers as the branch requires? | the same step with `at least: required`, or a number |
| was the approval given after the last commit? | the same step with `after: commit` |
| did every required check pass before the merge? | `event: check passed`, `of: required checks`, `before: merge` |
| were tickets with a label answered or closed in time? | steps on `kind: ticket` with `label` and `within` |
| was the fix for a ticket reviewed? | a step with `linked: change` |
| were scanner alerts handled in time? | steps on `kind: finding` (github only) |
| what changed in the settings since last time? | `divinate ledger`, rows marked `▣` |

if a part of the question isn’t in this table, tell the user that divinate
doesn’t cover it. whether a review was thorough, for example, is something a
person has to judge.

## step 2: check the setup

```sh
divinate --help        # installed? if not: cargo install --path <divinate checkout>
gh auth status         # github, or GITHUB_TOKEN
glab auth status       # gitlab, or GITLAB_TOKEN
az account show        # azure devops, or AZURE_DEVOPS_EXT_PAT
```

read access is enough. divinate never changes anything on the platform.

## step 3: collect

```sh
divinate collect github:OWNER/REPOSITORY
divinate collect gitlab:GROUP/PROJECT --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z
divinate collect azure:ORGANISATION/PROJECT
```

- collect a single repository when the question is about tickets or pull
  requests. `github:OWNER` alone only reads the branch settings of every
  repository.
- the period is the last 90 days unless you pass `--from` and `--until`. use
  the period the user asked about. tickets opened before it aren’t read.
- the command succeeds even when parts couldn’t be read. it prints the number
  of gaps, and `divinate show` lists them.
- a busy repository can take a few minutes. on gitlab you may see `rate
  limited; waiting N seconds`, which is normal.
- everything goes to `evidence/` in the current directory, or to `--state
  <path>`. each run adds a collection.

## step 4: write the definition

ask the user for their written process first. if they don’t have one, propose
a definition and let them confirm it, since it’s their rule that gets checked.

```yaml
process: change governance
items:
  kind: change
  when: merged
  into: default branch
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
  - name: validated
    event: check passed
    before: merge
branches:
  - name: review required
    approvals: 1
  - name: checks required
    checks: 1
  - name: no direct updates
    without: [push, force push]
```

- `items.kind` is `ticket`, `change`, or `finding`. `label` narrows it down.
  `when` is `opened` (the default) or `merged`. `into` keeps only pull
  requests into one branch, given by name or as `default branch`.
- a step needs a `name` and an `event`. the events are `comment`, `closed`,
  `reopened`, `dismissed`, `approval`, `changes requested`, `merge`, `check
  passed`, and `check failed`. a list means any one of them.
- `by: someone else` excludes the author of the item.
- `at least: 2` asks for two events by different people, and `at least:
  required` for as many as the branch requires.
- `after: commit` only counts events after the last commit.
- `of: required checks` asks for one event per check the branch requires.
- `within: 7d` (or `12h`) counts from when the item was opened.
- `before: merge` says the event has to come before the merge.
- `linked: change` looks at the pull requests that close a ticket.
- a branch rule has exactly one of `approvals`, `checks`, and `without`.

`docs/processes.md` in the divinate repository has the full reference.

## step 5: check

```sh
divinate show                             # every row of the latest collection
divinate check definition.yaml            # every item and branch, with reasons
divinate check definition.yaml --all      # a summary per repository
divinate check definition.yaml --last 8   # one repository over its last collections
divinate check definition.yaml --json     # the same results as json
divinate ledger                           # settings over time
```

the full check prints a table with one line per item, a count per step, and
under `not kept` the reason for every result other than `kept`. read the
reasons, since they tell you which pull request or which missing permission
is behind a result.

## step 6: answer

for each part of the user’s question, give:

```text
<the question in plain words>
result: <kept | broken | pending | could not be established | not applicable>
checked: <the step or rule, in the definition's words>
where: <repository>, collected <time>, period <from> to <until>
<for broken>       items: <each one, with its reason>
<for pending>      due: <each deadline>
<for cannot tell>  missing: <the reason>, and what would fix it
notes: <anything from the list below that affects this answer>
```

things that can affect an answer:

- `by: someone else` compares accounts, so a person with two accounts counts
  as two people.
- deadlines count from when the item was opened, even if its label was added
  later.
- an approval that was taken back, or followed by a request for changes,
  doesn’t count. an approval given before a later commit does count, unless
  the step says `after: commit`.
- `required` uses the branch settings from the first collection after the
  merge. with a single collection, that means today’s settings.
- without `into`, `when: merged` covers pull requests merged into any branch.

finish with the parts of the question divinate doesn’t cover, if there are
any.

## step 7: handing the directory over

```sh
divinate verify      # offline: checks that evidence/ is complete and unchanged
```

`evidence/` contains what the platform returned: ticket and pull request
texts, comments, account names (email addresses on azure devops), and scanner
alerts. ask the user before you commit, upload, or share it, and always copy
the whole directory.

`verify` shows that the directory is intact. the directory isn’t signed, so
if the user wants to give it to someone who has no reason to trust them,
suggest that this person runs `divinate collect` themselves with read access.

## when something goes wrong

| what you see | what to do |
|---|---|
| `divinate: command not found` | `cargo install --path <divinate checkout>` |
| `cannot read "…"; a scope is one of: …` | the scope is misspelled, or the platform isn’t supported |
| `no credential found` | log in with `gh`, `glab`, or `az`, or set the variable |
| rows with `gap: permission denied` or `gap: not authenticated` | the token can’t read them. collect with one that can, or report the gap |
| `rate limited; waiting N seconds` | normal on gitlab. let it run |
| a check says `cannot tell` | the reason names what’s missing |
| a check finds nothing to check | the label doesn’t match exactly, or the items are outside the period |
| `invalid peer certificate: UnknownIssuer` | a proxy on the network intercepts tls. collect from a network with direct access |
| `verify` fails | a file in `evidence/` was changed or is missing. restore the directory from a copy |
