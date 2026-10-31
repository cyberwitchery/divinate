# questions divinate answers

each entry below is one question divinate can answer about a repository. it
gives:

- the question in plain words, and the exact claim divinate records;
- which sources in `divinate.yaml` provide its evidence;
- what each result means for that question;
- what the answer never tells you, even when it is **supported**.

the claim id, such as `every_main_change_reviewed`, is what appears as
`assertion_type` in `.evidence/assertions/current.json`. the results are
explained in [reading an answer](answers.md).

a compliance requirement is usually broader than any single question here.
answer it with the questions that apply, and keep the parts that need judgement
for a person. the "never tells you" lines say where that boundary is.

## at a glance

| question | claim id | evidence from | providers |
|---|---|---|---|
| [is approval required before merging?](#is-approval-required-before-merging) | `configured_independent_review` | current branch settings | GitHub, Azure DevOps |
| [does the branch require two approvals, including one after the last push?](#does-the-branch-require-two-approvals-including-one-after-the-last-push) | `configured_review_requirement` | current branch settings | GitHub |
| [did every change get an approving review before it was merged?](#did-every-change-get-an-approving-review-before-it-was-merged) | `every_main_change_reviewed` | change and review history | GitHub, Azure DevOps |
| [were the reviews adequate?](#were-the-reviews-adequate) | `adequate_human_security_review` | — | needs a person |
| [does the branch require named status checks?](#does-the-branch-require-named-status-checks) | `github_required_status_checks_configured` | current branch settings | GitHub |
| [did ci pass for the current commit?](#did-ci-pass-for-the-current-commit) | `github_current_revision_checks_passed` | current ci results | GitHub |
| [does the branch have blocking build validation?](#does-the-branch-have-blocking-build-validation) | `azure_devops_blocking_build_validation_configured` | current branch policy | Azure DevOps |
| [does the branch have any blocking policy?](#does-the-branch-have-any-blocking-policy) | `azure_devops_blocking_branch_policy_configured` | current branch policy | Azure DevOps |
| [which dependencies did this release change?](#which-dependencies-did-this-release-change) | `dependency_change_visibility` | release sboms | any |
| [did this release's dependency changes pass policy?](#did-this-releases-dependency-changes-pass-policy) | `release_supply_chain_policy` | release sboms and gate | any |
| [did every change in this release get the required number of reviews?](#did-every-change-in-this-release-get-the-required-number-of-reviews) | `release_review_operation` | imported history | GitHub |

the [Software Change Governance](commercial-packs.md) pack adds maintained
controls on the same evidence, including "was anything pushed directly, bypassing
pull requests?" and "did every change pass build validation before merge?".

## three kinds of evidence

the same topic often appears as more than one question, because each kind of
evidence answers something different:

- **configured intent**: what the settings say today, such as "branch protection
  requires one approval". it says nothing about what happened before today.
- **observed operation**: what actually happened over a period, such as "every
  merge in Q3 had an approval". it says nothing about whether the settings
  required it.
- **observed state**: what is true of one thing now, such as "ci passed for this
  commit".

an auditor asking "is review enforced?" usually needs both configured intent and
observed operation. divinate never substitutes one for the other.

## code review

### is approval required before merging?

claim: "changes to `<branch>` are configured to require approval before merge"
(`configured_independent_review`)

evidence from: the GitHub `branch-protection` collector, or the Azure DevOps
`branch-policy` collector.

- **supported**: the current branch settings require at least one approving
  review. on Azure DevOps, the setting must be an enabled, blocking minimum
  reviewers policy.
- **contradicted**: the settings were read completely and require no approval.
- **insufficient evidence**: the settings were not read, or not completely, for
  example because the credential lacks permission to see branch protection.
- **stale**: on GitHub, the settings were last read more than 7 days before
  the evaluation. collect again.

never tells you: that reviews actually happened, that approvers were
independent of the author in any organisational sense, or what the settings
were in the past.

### does the branch require two approvals, including one after the last push?

claim: "main is configured to require two approvals, including approval of the
last push by someone else" (`configured_review_requirement`)

evidence from: the GitHub `branch-protection` collector.

this checks one fixed policy: at least two required approvals, and approval of
the most recent push by someone other than its author. it is not configurable,
and the claim text names `main` whichever branch is governed.

- **supported**: current branch protection requires both.
- **contradicted**: current branch protection is readable and requires fewer
  than two approvals or does not require last-push approval. a repository that
  intentionally requires one approval gets this result.
- **insufficient evidence**, **stale**: as for the previous question.

never tells you: the same limits as the previous question.

### did every change get an approving review before it was merged?

claim: "every change integrated into `<branch>` during `<from>` .. `<until>`
received at least one approving review before integration"
(`every_main_change_reviewed`)

evidence from: the `repository-mutations` and `pull-request-reviews` collectors
of the GitHub or Azure DevOps pack. both are required.

how it is answered:

1. list every change to the branch in the period, from the provider's record of
   pushes and merges;
2. match each change to exactly one pull request, by the commit the merge
   produced;
3. check that pull request for an approval by someone other than its author,
   recorded before the merge.

on Azure DevOps, an approval is a vote of `10` (approved) or `5` (approved with
suggestions), taken from the vote history so its time is known.

- **supported**: the complete list of changes and their reviews was read, and
  every change had a qualifying approval.
- **contradicted**: at least one change was pushed directly, or came from a pull
  request whose complete review record has no approval before the merge. each is
  listed.
- **insufficient evidence**: nothing contradicts the claim, but the complete
  history was not established. common reasons:
  - part of the period is older than the provider keeps; GitHub's activity
    record covers about one year;
  - a change could not be matched to exactly one pull request;
  - a review was dismissed, and GitHub no longer shows what it was;
  - a page of results was missing, or permission was denied;
  - the repository is declared a mirror, so it is not authoritative for how
    changes were integrated.

the period defaults to everything since the repository's first commit, or since
the previous release when a release is being evaluated. for an audit period,
pass it explicitly: `divinate collect --from 2026-07-01T00:00:00Z --until
2026-10-01T00:00:00Z`.

never tells you: that the reviews were adequate, that the required number of
approvals was met, or that rules such as dismissing stale approvals or resetting
votes on new pushes were applied.

### were the reviews adequate?

claim: "all security-relevant changes in release `<release>` received adequate
human security review" (`adequate_human_security_review`)

this question is evaluated whenever a release is evaluated, and its result is
always **not automatable**. records show that a review happened and who approved
it. they do not show what the reviewer examined, which changes were
security-relevant, or what adequate means for your organisation.

the answer lists the review and check records it considered, so a person can
start from them. to answer it, define what counts as security-relevant and what
an adequate review is, then inspect the reviews themselves.

## ci and build validation

### does the branch require named status checks?

claim: "the protected branch requires named status checks"
(`github_required_status_checks_configured`)

evidence from: the GitHub `branch-protection` collector.

- **supported**: current branch protection requires at least one named status
  check, and the settings were read completely.
- **contradicted**: branch protection requires no status checks.
- **insufficient evidence**: branch protection was not read, did not report its
  status-check settings, or was not read completely.

never tells you: that those checks ran or passed for any change, or what was
required in the past.

### did ci pass for the current commit?

claim: "GitHub check runs and commit statuses for the current revision were
completely enumerated and had acceptable terminal outcomes"
(`github_current_revision_checks_passed`)

evidence from: the GitHub `check-runs` and `commit-statuses` collectors. both
are required.

this looks at the commit currently checked out. GitHub has two ci result
systems, check runs and classic commit statuses, and both are read.

- **supported**: both lists were read completely for the same commit, at least
  one result exists, and every result finished as `success`, `neutral`, or
  `skipped`.
- **contradicted**: at least one result finished as a failure or error.
- **insufficient evidence**: a result is still pending or unrecognised, there
  are no results at all, a list was incomplete, or the two lists were for
  different commits.

never tells you: that every check required by branch protection ran, or
anything about earlier commits.

### does the branch have blocking build validation?

claim: "the Azure DevOps branch has enabled blocking build validation"
(`azure_devops_blocking_build_validation_configured`)

evidence from: the Azure DevOps `branch-policy` collector.

- **supported**: the complete list of policies for the branch includes an
  enabled, blocking build validation policy.
- **contradicted**: the complete list includes none.
- **insufficient evidence**: the policy list was not read completely.

never tells you: that a pipeline exists, ran, or passed, or what the policies
were in the past.

### does the branch have any blocking policy?

claim: "the Azure DevOps branch has at least one enabled blocking policy"
(`azure_devops_blocking_branch_policy_configured`)

evidence from: the Azure DevOps `branch-policy` collector.

results follow the previous question, for any enabled blocking policy.

never tells you: which kind of policy it is. use the review and build
validation questions for that.

## dependencies and releases

these questions are evaluated for a release. they need the built-in
`release-sbom` source, a CycloneDX sbom for each release, and two release tags.
see [workflows](workflows.md#release-dependency-evidence).

### which dependencies did this release change?

claim: "dependency changes for release `<release>` are identified and preserved"
(`dependency_change_visibility`)

- **supported**: an sbom comparison between the previous release and this one
  was run and retained.
- **insufficient evidence**: no comparison matches this release and its exact
  commits.

never tells you: about software loaded at runtime, or anything the sboms do not
list. two sboms produced by different generators or environments may not be
comparable.

### did this release's dependency changes pass policy?

claim: "release `<release>` introduced no dependency changes forbidden by
supply-chain/default" (`release_supply_chain_policy`)

- **supported**: the dependency gate ran on exactly this release's comparison
  and accepted it.
- **contradicted**: the gate ran on exactly this comparison and rejected it.
- **insufficient evidence**: there is no comparison, or no gate result for this
  exact comparison.

never tells you: about dependencies outside the sboms, or rules other than
those the gate applied.

### did every change in this release get the required number of reviews?

claim: "every change included in release `<release>` received the configured
number of reviews before merge" (`release_review_operation`)

this answer needs release membership and branch-policy history evidence, which
divinate cannot currently collect from GitHub. it can only be answered from
evidence imported with `divinate collect manifest`. without that, the result is
**insufficient evidence**.

never tells you: review quality or organisational independence.

## questions you add

packs can add their own questions. a pack's claims appear in the same answers,
with the same five results and the same provenance. see [packs](packs.md). this
repository's own `cargo-lock` pack, for example, answers "is dependency
resolution recorded?" (`cargo_dependency_lock_captured`).
