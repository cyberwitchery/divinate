# contributing

use rust stable and edition 2021. keep documentation lowercase and follow nearby
code patterns.

before submitting a change, run:

```sh
scripts/ci.sh
```

## evidence rules

- acquisitions, executions, pack invocations, and blobs are immutable. conflicting
  content under an existing id is an error.
- unsupported claims identify the missing population and remain valid assertion
  outcomes.
- configured intent, observed operation, and observed state are separate evidence
  classes.
- format changes include the corresponding files under `schema/` and must validate
  against the example corpus.


## documentation

user documentation starts from the question a reader needs answered, then
explains the mechanism. when a change adds, removes, or changes a claim, update
[questions divinate answers](docs/questions.md): the question in plain words,
the sources it needs, what each result means, and what it never establishes.
keep the [agent skill](skills/divinate/SKILL.md) consistent with it.
