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

## what is easy to break

divinate records what a platform said and lets people check rules against it.
these properties hold that together, and a change can break them without a
test failing right away.

- everything in a collection comes out of a stored response. the derivation
  makes no requests and reads no clock, so `verify` can repeat it offline.
- a change that makes the same responses produce a different model needs a new
  `DERIVATION` in `src/record.rs`.
- a collection holds what was read, and no results of rules. `kept` and
  `broken` belong to `check`, which stores nothing.
- a list that wasn’t read to the end is a gap. don’t record the part that was
  read as the whole.
- something that is only partly known is recorded with a note saying what is
  missing, and a rule that finds nothing in it answers `cannot tell`.
- an entity is identified by the platform’s own id, never by its name.
- every platform produces the same shapes. build scopes with
  `source/build.rs` and work items and events with `source/work.rs`.

## security

this is a security tool, and it handles tokens.

- core makes the requests for the built-in platforms, through the one reader
  in `src/source/reading.rs`. a platform module says what to read and what
  the responses mean.
- tokens are never stored. request headers aren’t kept, and a response that
  repeats a token is refused.
- only follow links on the platform’s own host, and build a url only from
  values that were checked.
- a pack gets an almost empty environment plus the variables its entry in
  `divinate.yaml` lists. don’t pass it more.
- what a source pack hands back is checked before it’s stored: no inherited
  secret in a reading, ids in the pack’s own namespace, statements that cite
  transcripts which exist. keep those checks in `src/pack/source.rs`.

## testing

- unit tests go in the same file as the code
- integration tests live in `tests/` and read canned responses through `tests/common`
- test both success and error cases
- assert on semantics, not on rendered markdown
- never pin a fixed future timestamp in a test; derive it from the evidence or the clock
