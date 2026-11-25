# contributing

thanks for wanting to help! divinate is written in rust (stable, edition
2021). before you send a change, run:

```sh
scripts/ci.sh
```

it runs the same checks as ci: formatting, clippy, the tests, the minimum
rust version, the docs build, packaging, `cargo deny`, the unsafe budget, and
coverage. it tells you which tools to install if one is missing.

## how the code is laid out

[DESIGN.md](DESIGN.md) explains how divinate works inside and why. the short
version:

| where | what |
|---|---|
| `src/source/` | one module per platform, plus the code they share |
| `src/model.rs` | the model every platform is translated into |
| `src/process/` | process definitions and `check` |
| `src/pack.rs`, `src/pack/` | running packs |
| `src/record.rs`, `src/verify.rs` | storing collections and verifying them |
| `packs/`, `examples/` | packs that live in this repository |

## things to keep in mind

a few properties are easy to break without a test noticing right away.

- **what divinate says has to come out of a stored response.** the step that
  turns responses into the model makes no requests and doesn’t look at the
  clock. `verify` relies on that. if your change makes the same responses
  produce a different model, bump `DERIVATION` in `src/record.rs`.
- **a list that wasn’t read to the end is a gap.** don’t record the part that
  was read as if it were the whole list, since rules would then say “none” or
  “all” about something divinate only saw part of.
- **a new platform uses the shared builders** in `src/source/build.rs` and
  `src/source/work.rs`, so it produces the same shapes as the others and
  `check` works on it without changes.
- **tokens stay out of `evidence/`.** request headers aren’t stored, and a
  response that contains the token is refused.
- **a pack that changes what it derives changes its version.**

## tests

unit tests live next to the code. the tests in `tests/` read a whole
repository from canned responses and check rules against it. when you add
something a platform reads, add its response to the fixture in the matching
test file. a request the fixture doesn’t know makes the test fail, which is
how you notice that a change reads more than you meant it to.

## documentation

if a change adds or changes something a user can see (what is read, what a
row says, what a definition can ask), update the page under [docs/](docs/) in
the same change, and [DESIGN.md](DESIGN.md) and the
[agent skill](skills/divinate/SKILL.md) if they’re affected. output in the
docs comes from a real run.
