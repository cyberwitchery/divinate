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

- the record holds no verdicts. a statement is a recorded value or a gap with its reason. kept and broken belong to a process check, which is not stored.
- no absence claim without a complete read. a listing that did not complete is a gap, and nothing is concluded from what it did not return.
- what is partly known is recorded with a note that says what is missing. a check that finds nothing in a partial reading answers cannot tell.
- derivation is a pure function of the transcripts. it makes no requests and reads no clock, so `verify` can repeat it offline.
- a change to what is derived from the same transcripts needs a new `DERIVATION` in `src/record.rs`.
- an entity is identified by the source's own id, never by its name.
- every source produces the same shapes. build scopes with `source/build.rs` and work items and events with `source/work.rs`.

## security considerations

this is a security tool. when modifying:

- core makes every request. a source says what to read and what the responses mean.
- do not retain credentials. request headers are never kept, and a response that repeats a credential is refused.
- only follow links on the source's own origin.
- build a url only from values that were checked, never from a response as it came.

## testing

- unit tests go in the same file as the code
- integration tests live in `tests/` and read canned responses through `tests/common`
- test both success and error cases
- assert on semantics, not on rendered markdown
- never pin a fixed future timestamp in a test; derive it from the evidence or the clock
