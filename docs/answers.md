# reading an answer

every question divinate answers gets one result, its reasons, and the evidence
behind it. this page explains how to read that, how to repeat it accurately to
someone else, and how they can check it.

## the five results

| result | what it means | what you can say |
|---|---|---|
| **supported** | the evidence establishes the claim, including that every relevant record was seen where the claim needs that | "yes, for this branch and period", with the evidence and the answer's limitations |
| **contradicted** | retained evidence contains at least one counterexample | "no", with each counterexample |
| **insufficient evidence** | nothing contradicts the claim, but something it requires was not established | "we could not establish this", with the named gap; not "yes", and not "no" |
| **stale** | suitable evidence exists but is older than the claim's freshness window | nothing yet: collect again, then answer |
| **not automatable** | the claim requires judgement records cannot supply | the question needs a person; the answer lists records they can start from |

two mistakes are easy to make:

- **reporting insufficient evidence as yes.** "no problems were found" is not the
  same claim as "there were no problems". divinate keeps them apart; keep them
  apart when you repeat the answer.
- **reporting a supported configuration answer as an operating answer.** "review
  is required by the settings" does not mean "every change was reviewed". these
  are separate questions with separate answers. see
  [questions divinate answers](questions.md#three-kinds-of-evidence).

an answer is about one subject and, where it applies, one period: a repository,
a branch, and a `from` .. `until` interval. it says nothing outside them.

## where answers appear

`divinate collect` answers every question its configured sources provide
evidence for, and writes the results to several places:

| where | for |
|---|---|
| `divinate status` | a summary: counts per result, source health, open gaps |
| `.evidence/dossiers/current.md` | the full answer set with reasons, evidence, coverage, and gaps |
| `divinate export dd` → `.evidence/views/dd-response.md` | a compact answer document to hand to someone else |
| `divinate review` → `.evidence/views/review.md` | what changed since the previous collection |
| `.evidence/assertions/current.json` | the same answers as structured json, for tools and agents |

the markdown files are generated from the json. they never contain an answer
that the json does not.

## anatomy of an answer

this is a real dossier entry for a repository whose review history has not been
collected yet:

```markdown
## changes received approving review before integration

state: **insufficient evidence**
semantics: observed operating effectiveness
derivation: `main-changes-reviewed/v2` (`asrt_363ec8c890b700a1e7ef`)

### why

- no counterexample was found, but the complete authoritative population was not established

### coverage

- repository mutations: **incomplete**, 2026-09-12T01:17:42+02:00 to 2026-10-31T13:36:18.011447483Z
- pull request reviews: **incomplete**, 2026-09-12T01:17:42+02:00 to 2026-10-31T13:36:18.011447483Z
- uncovered: 2026-09-12T01:17:42+02:00 to 2026-10-31T13:36:18.011447483Z
  - missing coverage: pull request reviews, repository mutations

### limitations

- an approval recorded before integration does not establish that every provider-specific stale-review or vote-reset condition remained satisfied
```

reading it from the top:

- **state** is the result.
- **semantics** says which kind of evidence the answer rests on: configured
  intent, observed operation, or observed state.
- **derivation** names the rule that produced the result and its version, and
  the answer's id. `divinate provenance asrt_363ec8c890b700a1e7ef` prints
  everything the answer rests on.
- **why** gives the rule's reasoning in one or more steps.
- **evidence** and **contradictions** list the records that support or
  contradict the claim. they are empty here.
- **coverage** says, for each population the claim needs, which parts of the
  period were completely read. a claim about "every change" is only supported
  when nothing is uncovered.
- **evidence gaps** say what is missing and why.
- **limitations** say what the claim would not establish even if it were
  supported. repeat these when you repeat a supported answer.

## turning an answer into a response

a questionnaire or auditor asks a broader question than any single claim. a
useful response:

1. names the question divinate answered, in its exact words, with the branch
   and period;
2. gives the result;
3. for **supported**, adds the limitations; for **contradicted**, lists the
   counterexamples; for **insufficient evidence**, states the gap and what you
   will do about it;
4. says which part of the original question needs human judgement, if any;
5. points to the evidence: the answer id and the `.evidence/` archive.

for example:

> every change merged into `main` between 1 July and 30 September 2026 had an
> approving review from someone other than its author before it was merged
> (divinate: supported, `asrt_…`). this establishes that approvals were
> recorded, not their quality. review quality is assessed separately by our
> security lead. evidence: attached `.evidence/` archive, verifiable with
> `divinate verify`.

## letting someone else check

the answer is only as useful as someone else's ability to confirm it.

```sh
divinate verify                       # recheck every link from raw records to answers
divinate provenance <answer-id>       # the evidence graph behind one answer
divinate export dd                    # the answer document
```

- `.evidence/` holds everything divinate captured and derived. copy or archive
  it as one directory; a partial copy breaks the links.
- `divinate verify` runs offline. the person checking needs neither network
  access, provider credentials, nor access to the repository's provider.
- verification proves the records were not altered after capture and that every
  answer follows from them. it cannot prove that GitHub or Azure DevOps reported
  the truth, or that the host clock was right.

`.evidence/` contains provider responses byte for byte, including pull request
titles, descriptions, and review comments. treat it as confidential as the
repository itself. see [security](security.md).

## when the answer is "can't tell"

insufficient evidence is a correct answer, not a malfunction. the gap names
what is missing. the usual fixes are:

- add the source that provides the missing evidence in `divinate.yaml`;
- give the credential the permission it lacked;
- narrow the period to one the provider still has records for;
- collect again if a collection failed part way.

do not edit `.evidence/` or change a source's settings to make a gap disappear.
see [troubleshooting](troubleshooting.md#the-answer-is-insufficient-evidence).

## answers over time

each `divinate collect` re-answers every question over its whole period, using
all evidence collected so far. the new answers become `current`, and the
previous ones are kept as `previous`. `divinate review` lists what changed
between them: results that moved, new gaps, and coverage that got worse.

to answer as of a past date, for example the end of an audit period, use a
named evaluation. see [workflows](workflows.md#answering-for-an-audit-period).
