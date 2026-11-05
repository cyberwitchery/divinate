# divinate

divinate answers technical compliance questions about your repositories with
evidence that anyone can check, and says plainly when the evidence cannot answer.

> is every change to `main` reviewed before it is merged?
> is ci required before merge?
> which dependencies did this release add, and did they pass our policy?

questions like these come up in audits, security questionnaires, customer due
diligence, and certifications such as ISO 27001 or SOC 2. divinate is for
whoever has to answer them: an engineer, a security or compliance lead, a CTO,
or an auditor checking someone else's answer. without it, the usual method is
clicking through settings pages, taking screenshots, and hoping nothing changed
in between.

divinate reads the records that can answer those questions from GitHub, Azure
DevOps, and your build tools. it keeps them byte-for-byte, and answers each
question with one of five results:

| result | meaning |
|---|---|
| **supported** | yes. the evidence establishes it, and the answer lists that evidence. |
| **contradicted** | no. the answer names the counterexample, such as a direct push or a failed check. |
| **insufficient evidence** | can't tell. nothing contradicts it, but something required is missing, and the answer says what. |
| **stale** | the evidence was suitable but is too old to describe today. collect again. |
| **not automatable** | the question needs human judgement. divinate says so instead of guessing. |

there are no scores, percentages, or confidence levels. a result is a decision
under explicit rules, with its reasons attached.

## how it can know

take "did every change to `main` get reviewed?". divinate does not look at the
branch settings and infer the rest. it:

1. lists every change made to `main` during the period, from the provider's own
   record of pushes and merges;
2. finds the pull request behind each change;
3. checks that someone other than the author approved it before it was merged.

a direct push, or a pull request merged without a prior approval, makes the
answer **contradicted** and is named. if the list of changes cannot be shown to
be complete, for example because the provider only keeps a year of history,
part of the result was not readable, or the credential lacked permission, the
answer is **insufficient evidence** and the gap is named.

this is the rule that makes the answers trustworthy: **finding nothing is not
proof that nothing is there.** divinate only answers "every" or "none" after it
has shown that it saw the whole population.

the same question has separate answers for different kinds of evidence. "review
is configured" is answered from today's branch settings. "review happened" is
answered from the history of changes. one never stands in for the other.

## what it does with qualitative questions

some questions cannot be answered from records. "were the reviews adequate?" is
one. divinate does not turn that into a number. it splits the question into the
parts records can settle and the part they cannot:

```text
"changes are properly reviewed"
  ├ review is required by configuration           → answered from settings
  ├ every change had a prior approval by          → answered from history
  │ someone other than its author
  └ the reviews were adequate                     → not automatable: needs a person
```

the person answering the compliance question still owns the judgement. divinate
removes the manual fact-finding underneath it and is explicit about where the
facts stop. see [questions divinate answers](docs/questions.md) for each
question, what it checks, and what it never tells you.

## an answer, as you get it

a repository with no review history collected yet gets this from
`divinate export dd`:

```markdown
## every change integrated into main during 2026-09-12T01:17:42+02:00 .. 2026-10-31T13:36:32.601944665Z received at least one approving review before integration

result: **insufficient evidence**

- gap: no collection attempt matched this population and scope; uncovered intervals: 2026-09-12T01:17:42+02:00 to 2026-10-31T13:36:32.601944665Z
  - missing coverage: pull request reviews, repository mutations
- limitation: an approval recorded before integration does not establish that every provider-specific stale-review or vote-reset condition remained satisfied
```

the question, the result, what is missing, and what even a positive answer
would not establish all appear together. every answer also carries an id that
`divinate provenance` traces back to the exact retained responses it was
derived from.

## anyone can check the answer

an answer is only useful in an audit if someone else can confirm it.

- everything divinate used is kept in `.evidence/` and addressed by its
  sha-256 content hash.
- `divinate verify` checks the whole chain from raw responses to answers
  offline, without the network, credentials, or provider access.
- `divinate provenance <id>` shows exactly which records an answer rests on.

hand the `.evidence/` directory to an auditor and they can check the answers
themselves. content addressing proves the records were not changed after they
were captured. it cannot prove that the provider reported the truth.

## get started

divinate requires rust 1.95 or newer:

```sh
cargo install --path .
```

this installs `divinate` and the GitHub and Azure DevOps packs. then, from the
repository you need to answer for:

```sh
divinate init            # writes divinate.yaml from the git origin
$EDITOR divinate.yaml    # choose which questions to collect evidence for
divinate collect         # gather evidence and answer
divinate status          # what is known now, and what is missing
divinate export dd       # the answers, as a document to hand over
```

[getting started](docs/getting-started.md) walks through answering the review
question for a GitHub or Azure DevOps repository. this repository answers its
own questions with divinate; [`divinate.yaml`](divinate.yaml) is a working
configuration.

## documentation

for answering questions:

- [questions divinate answers](docs/questions.md): every question, what it
  checks, what yes, no, and can't tell look like, and what it never tells you.
- [reading an answer](docs/answers.md): the five results, the dossier, and
  passing answers to someone else.
- [getting started](docs/getting-started.md): from a repository to a first
  answer.
- [workflows](docs/workflows.md): audit periods, recurring collection, releases.
- [troubleshooting](docs/troubleshooting.md): failures, and what to do when the
  answer is "can't tell".

for running and trusting divinate:

- [commands](docs/commands.md): every command and option.
- [how answers are derived](docs/concepts.md): evidence, completeness,
  authority, and time.
- [security](docs/security.md): credentials, what is retained, and trust limits.
- [state and formats](docs/state.md): `divinate.yaml`, `.evidence/`, and the
  schemas.

for extending divinate:

- [packs](docs/packs.md): add questions and evidence sources through the pack
  protocol.
- [commercial packs](docs/commercial-packs.md): maintained control definitions
  and framework mappings built on the same public protocol.
- [design](DESIGN.md): implementation invariants for maintainers.

for agents:

- [`skills/divinate`](skills/divinate/SKILL.md) is an agent skill that lets an
  AI agent set up divinate, collect evidence, and answer compliance questions
  without overstating what the evidence shows. it follows the agent skills
  format: copy the directory into your agent's skills directory, for example
  `~/.claude/skills/divinate` for Claude Code.

## scope

divinate runs locally against one repository at a time. it is not a scanner,
hosted service, dashboard, compliance catalog, or policy language, and it does
not decide whether you are compliant. it answers the technical questions
underneath that decision, with evidence.

## license

apache-2.0. external packs carry their own licenses.
