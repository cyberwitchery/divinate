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

