# agent guidelines

guidelines for ai agents working on this codebase.

## constraints

- do not introduce new dependencies without discussion
- do not refactor code outside the scope of the task
- do not add features beyond what was requested
- preserve existing error handling patterns
- maintain deterministic output ordering

## workflow

1. understand the task fully before making changes
2. read relevant existing code first
3. make minimal, focused changes
4. add tests for new functionality
5. run `scripts/ci.sh` before submitting

## rust-specific

- use `thiserror` for error types
- use `BTreeMap`/`BTreeSet` for deterministic iteration
- prefer `&str` over `String` in function signatures where possible
- document public items in lowercase, with `# Errors` on anything fallible
- use `#[cfg(test)] mod tests` for unit tests

## evidence semantics

this is the part that is easy to break without noticing.

- never widen what a claim asserts to make a test pass. `insufficient_evidence` with a named gap is a correct answer.
- absence of returned records is not absence of the fact. a universal or absence claim needs a collection run proving complete enumeration of the required population.
- authority is scoped to a proposition, subject, and interval. there is no global source ranking.
- an observation is unavailable until every transcript justifying it was captured. a declared `observed_at` never makes evidence available before its own provenance.
- a pack supplies interpretation, never evidence. core computes identity, executes commands, recomputes coverage, and writes state.

## security considerations

this is a security tool. when modifying:

- never execute untrusted code from analyzed projects
- validate all external tool output before parsing
- do not retain credentials: authorization headers, cookies, and credential-like argv are refused, not redacted
- stdout and stderr are retained byte-exact and unredacted, so never route a secret-printing tool through `run`

## testing

- unit tests go in the same file as the code
- integration tests live in `tests/` and use `fixtures/`
- test both success and error cases
- assert on semantics, not on rendered markdown
- never pin a fixed future timestamp in a test; derive it from the evidence or the clock
