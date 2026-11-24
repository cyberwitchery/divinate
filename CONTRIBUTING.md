# contributing

use rust stable and edition 2021. keep documentation lowercase and follow nearby
code patterns.

before submitting a change, run:

```sh
scripts/ci.sh
```

## rules of the record

- a statement is a recorded value or a gap with its reason. the record holds no
  verdicts.
- nothing is concluded from what a reading did not return. a listing that did
  not complete is a gap.
- derivation is a pure function of the retained transcripts, so `verify` can
  repeat it offline. a change to what the same transcripts say needs a new
  `DERIVATION` in `src/record.rs`.
- a new source implements `Source` and builds its entities and statements with
  the shared builders under `src/source/`, so every source produces the same
  shapes.

[DESIGN.md](DESIGN.md) explains the model and the reasons behind these rules.

## documentation

when a change adds or changes what is read, what a statement says, or what a
process definition can ask, update the pages under [docs/](docs/) and
[DESIGN.md](DESIGN.md) in the same change, and keep the
[agent skill](skills/divinate/SKILL.md) consistent with them. show output from
a real run.
