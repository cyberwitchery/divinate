# commands

divinate has six commands. `collect` is the only one that talks to a
platform. `show`, `ledger`, `check`, and `verify` work on what `collect`
stored, so they run offline. `pack` tells you about an installed
[pack](packs.md).

all of them use the directory `evidence/` in the current directory. pass
`--state <path>` to use another one. packs are declared in `divinate.yaml` in
the current directory, or in the file you pass with `--config <file>`.

## `divinate collect`

```text
divinate collect <scope> [--from <time>] [--until <time>] [--no-files]
```

reads a repository or an organisation and stores the result as a new
collection. `<scope>` is something like `github:acme/shop`, and
[sources](sources.md) lists what else you can write there. a scope can also
start with the name of a [pack](packs.md) that reads another system, such as
`osv:acme/shop`.

`--from` and `--until` set the period for tickets, pull requests, findings,
and branch updates. times look like `2026-01-01T00:00:00Z`. without them you
get the last 90 days. when you collect an organisation, only settings are
read and the period doesn’t matter.

`--no-files` leaves out the list of files each pull request touches. that
saves a request per pull request, and keeps the diffs (and with them your
source code) out of `evidence/`. rules that use `paths` then answer `cannot
tell`.

when it’s done it prints how many rows it recorded, how many of them are
gaps, and the id of the collection:

```console
$ divinate collect github:cyberwitchery/divinate
collected github:cyberwitchery/divinate: 180 records, 0 gaps
col_b25ba381174bcdfec8ce
```

something divinate can’t read becomes a gap in the collection, and the command
still succeeds. it only fails when it doesn’t understand the scope or can’t
find a token.

## `divinate show`

```text
divinate show [<collection>]
```

prints one collection: a block for the repository and one for each branch,
with a row per thing divinate read. without an argument you get the latest
collection. rows that changed since the collection before are marked `▣`.
[reading the record](record.md) explains the rows.

## `divinate ledger`

```text
divinate ledger [--scope <scope>] [--last <n>]
```

prints several collections of the same repository next to each other, one
column per collection and oldest first, so you can see when a setting changed.
it shows the last eight collections of the repository you collected most
recently. `--last` changes how many, and `--scope` picks another repository.

a repository that was renamed keeps its history, since divinate goes by the
platform’s id for it.

## `divinate check`

```text
divinate check <definition>... [--collection <id>] [--json]
divinate check <definition>... --last <n> [--scope <scope>] [--json]
divinate check <definition>... --all [--json]
```

checks the rules in a [process definition](processes.md) against a collection.
`<definition>` is a yaml file, `<pack>:<name>` for a definition that a
configured [pack](packs.md) ships, or `<pack>:` for all of that pack’s
definitions. you can give several. each gets its own results, and the
[framework](processes.md#frameworks) list at the end covers them together.

| option | what you get |
|---|---|
| none | the latest collection in full: a result per item and step, a count per step, and the reason for everything that isn’t `kept` |
| `--collection` | the same for the collection with this id |
| `--last` | a summary for each of the last collections of one repository, oldest first |
| `--all` | a summary for the latest collection of every repository in `evidence/` |
| `--json` | the same results as json |

`check` doesn’t store anything, so you can run it as often as you like and
with as many definitions as you like.

## `divinate pack`

```text
divinate pack <name>
```

prints what a configured pack offers: its version, what it collects, its
checks, and the process definitions it ships.

## `divinate verify`

```text
divinate verify
```

checks that `evidence/` is complete and unchanged. run it after you copied the
directory somewhere, before you rely on an old one, or when someone hands you
theirs.

```console
$ divinate verify
verified 1 collections and 260 transcripts
```

divinate stores every response it got from the platform. `verify` checks each
of them against its checksum, then works out every collection again from the
stored responses and compares the result with what’s in the file. it stops at
the first difference and tells you which file it is.

a collection written by a different version of divinate may have been worked
out differently. `verify` still checks its files and lists it as `derived by
other rules`. the same goes for a collection that a pack read, when that pack
isn’t configured where you run `verify`.
