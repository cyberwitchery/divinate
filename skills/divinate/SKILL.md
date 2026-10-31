---
name: divinate
description: Answer technical compliance, audit, security-questionnaire, and due-diligence questions about a git repository's controls with verifiable evidence, using the divinate CLI. Use when asked whether changes to a branch are reviewed or approved before merge, whether review or CI is required by branch protection or branch policy, whether CI passed, which dependencies a release changed or whether they passed policy, or when setting up, running, or reading divinate (divinate.yaml, .evidence/, dossiers, `divinate collect`). Covers GitHub and Azure DevOps repositories.
---

# answering compliance questions with divinate

divinate answers narrow technical questions about a repository, such as "did
every change to `main` get an approving review before it was merged?", from the
provider's own records. every answer has one of five results, its reasons, and
evidence that someone else can verify offline.

your job is to get the evidence collected, read the answers, and report them
**exactly as strong as they are**. the people relying on your report may repeat
it to an auditor.

## the reporting rules

these matter more than anything else in this skill.

1. **report the result divinate gave, never a stronger one.**
   - `supported`: yes, for the stated subject and period only.
   - `contradicted`: no. list every counterexample.
   - `insufficient_evidence`: *could not be established*. it is not "yes", not
     "no issues found", and not "probably fine". state the gap.
   - `stale`: the evidence is too old. collect again before answering.
   - `not_automatable`: the question needs a person. say so and name what they
     need to judge.
2. **never call anything "compliant".** divinate answers technical
   sub-questions. whether those satisfy a framework or policy is the user's or
   auditor's decision.
3. **keep configured and operating apart.** "review is required by branch
   protection" (configured) does not mean "every change was reviewed"
   (operating), and the reverse does not hold either. report each from its own
   answer.
4. **always give the scope**: repository, branch, and for history questions the
   period, with `until` excluded. an answer says nothing outside it.
5. **carry the limitations.** every `supported` answer lists what it does not
   establish. include them.
6. **cite the answer id** (`asrt_…`) so the user can run `divinate provenance`.

never try to change a result. do not edit anything in `.evidence/`, do not
make a required source optional or remove it, do not change the repository
identity, and do not stretch or shrink the period to avoid a gap. if a gap can
be closed legitimately, for example by adding a missing source or granting a
permission, propose it to the user and explain why.

## step 1: map the question

compliance questions are broader than any single answer. split the user's
question into the claims below, and say which part no claim covers.

| question | claim id | sources (collectors) | GitHub | Azure DevOps |
|---|---|---|---|---|
| is approval required before merging? | `configured_independent_review` | `branch-protection` / `branch-policy` | yes | yes |
| are two approvals, including one after the last push, required? | `configured_review_requirement` | `branch-protection` | yes | — |
| did every change get an approving review before merge? | `every_main_change_reviewed` | `repository-mutations` and `pull-request-reviews` | yes | yes |
| were reviews adequate or security-focused? | `adequate_human_security_review` | always `not_automatable` | — | — |
| does the branch require named status checks? | `github_required_status_checks_configured` | `branch-protection` | yes | — |
| did ci pass for the current commit? | `github_current_revision_checks_passed` | `check-runs` and `commit-statuses` | yes | — |
| does the branch have blocking build validation? | `azure_devops_blocking_build_validation_configured` | `branch-policy` | — | yes |
| does the branch have any blocking policy? | `azure_devops_blocking_branch_policy_configured` | `branch-policy` | — | yes |
| which dependencies did this release change? | `dependency_change_visibility` | built-in `release-sbom` | any | any |
| did this release's dependency changes pass policy? | `release_supply_chain_policy` | built-in `release-sbom` | any | any |

notes:

- `configured_review_requirement` tests one fixed policy: two approvals plus
  last-push approval. a repository that deliberately requires one approval gets
  `contradicted` here. explain that, and answer "is approval required?" from
  `configured_independent_review` instead.
- `every_main_change_reviewed` counts an approval only from someone other than
  the pull request's author, recorded before the merge. it does not check the
  required number of approvals, stale-review dismissal, or vote resets.
- history questions are about a period. ask for it if the user did not give
  one, for example the audit period or the last quarter.
- configuration questions are answered from the settings at collection time.
  divinate cannot read what the settings were in the past.
- the `release-sbom` claims need a release context: release tags and a
  CycloneDX sbom per release.
- packs can add claims beyond this table. read the `claim` text of any unknown
  `assertion_type`, and report it with the same rules.

## step 2: check the setup

```sh
divinate --help                     # installed? if not: cargo install --path <divinate checkout>
cat divinate.yaml                   # which sources exist?
divinate status                     # validates config; shows sources and last collection
gh auth status                      # GitHub credential, or GITHUB_TOKEN
az account show                     # Azure DevOps credential, or AZURE_DEVOPS_EXT_PAT
```

run these from the repository's checkout, or pass `--repository-path`.

if `divinate.yaml` is missing, `divinate init` creates one from the git origin.
add the sources the question needs. a GitHub example covering review and ci:

```yaml
repository:
  identity: github:OWNER/NAME
  branch: main

packs:
  cyberwitchery.github:
    executable: divinate-pack-github

sources:
  branch-protection:
    provider: {pack: cyberwitchery.github, collector: branch-protection}
  branch-changes:
    provider: {pack: cyberwitchery.github, collector: repository-mutations}
  reviews:
    provider: {pack: cyberwitchery.github, collector: pull-request-reviews}
  check-runs:
    provider: {pack: cyberwitchery.github, collector: check-runs}
  commit-statuses:
    provider: {pack: cyberwitchery.github, collector: commit-statuses}
```

for Azure DevOps, use `identity: azure-devops:ORG/PROJECT/REPO`, the pack
`cyberwitchery.azure-devops` with `executable: divinate-pack-azure-devops`, and
the collectors `branch-policy`, `repository-mutations`, and
`pull-request-reviews`.

`divinate.yaml` is meant to be committed and reviewed. tell the user what you
added and why. never put a token, password, or other credential in it: divinate
rejects credential-like keys and keeps an exact copy of the file.

## step 3: collect

```sh
divinate collect                                                     # everything since the first commit
divinate collect --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z   # an audit period
```

- times are rfc 3339. `--until` cannot be in the future.
- GitHub keeps about one year of activity. a default period on an older
  repository leaves the older part uncovered, so prefer the period the question
  is actually about.
- if a required source fails, the whole collection stops and **nothing is
  saved**. read the error, fix the cause, and run it again.
- the output lists each source and the count of each result. collection
  replaces `current` answers; the previous ones become `previous`.

## step 4: read the answers

prefer the structured answers over the markdown views. this skill includes a
reader that prints every answer with the fields the reporting rules need:

```sh
python3 <this skill>/scripts/answers.py .evidence
python3 <this skill>/scripts/answers.py .evidence --claim every_main_change_reviewed
```

without it, read `.evidence/assertions/current.json` directly. each element is
one answer:

| field | use |
|---|---|
| `assertion_type` | the claim id from the table above |
| `claim` | the exact claim, with branch and period. quote it. |
| `outcome` | the result |
| `subject` | repository, branch, release, and `from`/`until` |
| `support` / `contradictions` | evidence for it / counterexamples, each with a `reason` |
| `missing` | gaps, each with a `requirement` and a `reason` |
| `coverage` | whether each needed population was completely read, with `uncovered_intervals` |
| `limitations` | what the claim does not establish even when supported |
| `id` | the answer id for `divinate provenance` |

other views, all generated from the same json:

- `divinate status` (add `--json`): result counts, source health, open gaps.
- `.evidence/dossiers/current.md`: full reasoning for each answer.
- `divinate export dd`: a hand-over document in `.evidence/views/dd-response.md`.
- `divinate review`: what changed since the previous collection.

## step 5: write the response

for each part of the user's question:

```text
<question in plain words>
result: <supported | contradicted | could not be established | stale | needs human judgement>
claim: "<exact claim text>"  (<answer id>)
scope: <repository>, branch <branch>, <from> to <until> (until excluded)
<for contradicted>  counterexamples: <each one>
<for insufficient>  gap: <each missing reason>; to close it: <legitimate next step>
<for supported>     does not establish: <each limitation>
```

then list the parts of the original question that no claim covers, and who
should judge them.

## step 6: let the user hand it over

```sh
divinate verify                         # offline recheck of every answer against its records
divinate provenance <answer-id>         # the evidence behind one answer, as json
divinate export dd --output <name>      # the answer document
```

`.evidence/` contains provider responses byte for byte, including pull request
titles, descriptions, and review comments. do not commit, upload, or share it
without the user's explicit agreement. it is copied as one directory; a partial
copy breaks verification.

to keep a period's answers under their own name, so the next collection does
not replace them:

```sh
divinate evaluate --label 2026-q3 --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z
divinate export dd --evaluation 2026-q3 --output 2026-q3
```

## when something fails

| symptom | cause and fix |
|---|---|
| `divinate: command not found` or a pack executable not found | install with `cargo install --path <divinate checkout>`; packs must be on `PATH` |
| repository identity mismatch | `divinate.yaml` names a different repository than the git origin. use the right checkout; do not edit the identity to get past the check |
| permission denied, unauthenticated, rate limited | a credential problem, recorded as a gap. fix the credential (`gh auth login`, `az login`) and collect again |
| `invalid peer certificate: UnknownIssuer` | the network intercepts TLS (a corporate or sandbox proxy). divinate trusts only its built-in public roots, so it cannot reach the provider from here. tell the user; collection must run from a network with direct access |
| `cannot determine previous release` | pass `--release <tag> --base-release <tag>` |
| review asks for `--since` | there is no previous collection yet. collect twice, or name the evaluations |
| an answer is `insufficient_evidence` | read its `missing` and `coverage`; it is usually a correct answer, and the gap says what would close it |

never run a command that prints secrets through `divinate run`: its output is
stored byte for byte. local tools and packs get an empty environment, so pass
non-secret values with `--environment name=value`.
