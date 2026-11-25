# packs

a pack adds to what divinate can do. it’s a small program that you (or
someone you trust) write in any language. a pack can do three things: judge
things that a process definition can’t express on its own, ship ready-made
process definitions, and read a system that divinate doesn’t know.

a typical reason to write one: your policy says that every pull request has a
checklist in its description and that all boxes are ticked. divinate has the
description, but no step that reads task lists. a pack can read it.

## using a pack

packs are declared in `divinate.yaml`, which divinate looks for in the
directory you run it in (`--config <file>` names another one):

```yaml
packs:
  checklist:
    command: ./divinate-pack-checklist
```

the name under `packs` is how definitions and commands refer to the pack.
these are the keys of an entry:

| key | meaning |
|---|---|
| `command` | the program. a path is taken relative to the configuration file, and a bare name is looked up on your `PATH` |
| `args` | arguments for the program |
| `working_dir` | the directory the pack runs in. the directory of the configuration file by default |
| `inherit` | names of environment variables the pack gets from your environment, such as a token it needs |
| `env` | environment variables set for the pack, written out here. don’t put secrets in this one |
| `timeout_seconds` | how long a request to the pack may take. 300 by default |
| `setup` | settings for the pack, handed to it with every request. what goes here is up to the pack |

a pack starts with an almost empty environment. it only sees a token when its
entry lists the variable under `inherit`.

this repository has an example in [examples/](../examples/divinate.yaml):

```console
$ cd examples
$ divinate pack checklist
checklist 0.1.0
checks the task list in the description of a ticket or change

checks
  checklist/completed  for a step. every box is checked
  checklist/share  for a measure. the share of items with every box checked

process definitions
  checklist:merged  merged changes have a completed checklist
```

the definitions a pack ships can be checked right away, by writing
`<pack>:<name>` where the file would go:

```console
$ divinate check checklist:merged
checklists · github:cyberwitchery/divinate · as of 2026-11-24T23:59:25Z
changes merged 2026-08-26T23:57:02Z to 2026-11-24T23:57:02Z: 41 read

item                              checklist completed
github:cyberwitchery/divinate#6   broken
github:cyberwitchery/divinate#7   broken
...

checklist completed  41 broken

completed share  0% (0 of 41 items)

not kept
  github:cyberwitchery/divinate#6 · checklist completed: broken, the description has no checklist
  ...

packs: checklist 0.1.0
```

the last line names the packs that took part, with their versions, so a result
can be traced to the code that produced it.

you can also use a pack’s checks in your own definitions. a check goes in one
of three places, depending on what it answers:

```yaml
process: merge requests
items:
  kind: change
  when: merged
steps:
  - name: reviewed
    event: approval
    by: someone else
    before: merge
  - name: checklist completed
    uses: checklist/completed        # a result for each item
overall:
  - name: enough reviewers
    uses: acme/reviewer-spread       # one result for all items together
    with:
      minimum: 3
measures:
  - name: completed share
    uses: checklist/share            # a number
```

`divinate check checklist:` (with nothing after the colon) checks every
definition the pack ships in one run.

`with` passes settings to the check. what they are is up to the pack.
`divinate pack <name>` tells you which of the three places each check is for.
steps that use a pack sit next to ordinary steps and get the same five
results. a step with `uses` can also have `linked`, which hands the pack the
pull requests that close a ticket instead of the ticket.

## a pack as a source

a pack can also read a system and add collections of its own. the pack in
[packs/](../packs/divinate-pack-osv) does that: for every release of a github
repository it reads the sboms attached to it, and asks [osv.dev](https://osv.dev)
which known vulnerabilities their components have.

```yaml
packs:
  osv:
    command: ./divinate-pack-osv
    inherit: [GITHUB_TOKEN]
    timeout_seconds: 900
    setup:
      sbom: '*.cdx.json'
```

```console
$ divinate collect osv:cyberwitchery/sbom-diff
collected osv:cyberwitchery/sbom-diff: 14 records, 0 gaps
col_6ea5e976003a755e4ab7
$ divinate show
osv:cyberwitchery/sbom-diff · collected 2026-11-25T08:46:51Z · col_6ea5e976003a755e4ab7
14 records, 0 gaps

osv:cyberwitchery/sbom-diff
  ■ findings  1 finding
  ■ releases  5 releases
```

the name before the colon picks the pack. the result is an ordinary
collection: `show` and `ledger` print it, and rules work on it. every known
vulnerability is a finding that is opened when it’s first known of a release
and closed by the next release that no longer has it, so this definition asks
whether vulnerable dependencies get replaced within a month:

```yaml
process: known vulnerabilities
items:
  kind: finding
steps:
  - name: fixed in a release
    event: closed
    within: 30d
```

```console
$ divinate check known-vulnerabilities.yaml
known vulnerabilities · osv:cyberwitchery/sbom-diff · as of 2026-11-25T08:47:36Z
findings opened 2026-08-27T08:46:51Z to 2026-11-25T08:46:51Z: 1 read

item                                           fixed in a release
osv:cyberwitchery/sbom-diff RUSTSEC-2026-0543  broken

fixed in a release  1 broken

not kept
  osv:cyberwitchery/sbom-diff RUSTSEC-2026-0543 · fixed in a release: broken, no closed within 30d
```

(that one is “chrono is unmaintained”, and all five releases of the period
have it.)

a finding’s label is its severity: the word the database gives (`high`), the
band of its cvss 3 score, or for a notice that isn’t a vulnerability the kind
of notice (`unmaintained`). `items.label` selects by it.

a source pack makes its own requests, and hands divinate every response it
got. divinate stores them the same way it stores its own, so `verify` covers
them. `verify` also asks the pack to work out the collection again from the
stored responses, as long as the same version of the pack is configured. on a
machine without the pack, `verify` still checks the files and says which pack
it would need for the rest:

```
col_…: derived by the pack osv 0.1.0, which is not configured here; bytes checked, statements not recomputed
```

## writing a pack

divinate starts the pack, writes one json request to its standard input, and
reads one json answer from its standard output. every request has
`"protocol": 1`, a `"request"` that says what is asked, and the `"setup"`
from the configuration. a pack answers `describe`, and then `check` if it has
checks, or `collect` and `derive` if it is a source.

### describe

```json
{"protocol": 1, "request": "describe", "setup": null}
```

the pack answers with what it offers:

```json
{
  "protocol": 1,
  "name": "checklist",
  "version": "0.1.0",
  "description": "checks the task list in the description of a ticket or change",
  "checks": [
    {"name": "completed", "answers": "each_item", "description": "every box is checked"},
    {"name": "share", "answers": "number", "description": "the share of items with every box checked"}
  ],
  "processes": [
    {"name": "merged", "description": "merged changes have a completed checklist", "definition": "process: checklists\n..."}
  ]
}
```

a pack can also declare `"frameworks"`, in the same form as in a
[process definition](processes.md#frameworks). the definitions it ships can
then map to them without repeating the list of requirements, which is how a
pack carries the mapping of a whole set of rules to a standard.

`name` has to match the name in `divinate.yaml`. a source also has
`"collects": {"scopes": "osv:<owner>/<repository>", "description": "..."}`.
`answers` is `each_item` for a check used in
a step, `all_items` for one used under `overall`, and `number` for a measure.
a `definition` is the text of a [process definition](processes.md), and it can
use the pack’s own checks.

### check

```json
{
  "protocol": 1,
  "request": "check",
  "check": "completed",
  "setup": null,
  "with": {},
  "collection": {
    "scope": "github:cyberwitchery/divinate",
    "as_of": "2026-11-24T23:59:25Z",
    "interval": {"from": "2026-08-26T23:57:02Z", "until": "2026-11-24T23:57:02Z"}
  },
  "items": [
    {
      "id": "github.com/ticket/6136000333",
      "kind": "ticket",
      "name": "github:cyberwitchery/divinate#27",
      "author": "github:hellerve",
      "state": {
        "number": 27,
        "title": "configured_review_requirement tests a fixed two-approval policy and always names main",
        "description": "## problem\n\n...",
        "labels": ["bug"],
        "state": "closed",
        "opened_at": "2026-10-31T14:33:40Z",
        "closed_at": "2026-11-20T21:16:12Z",
        "merged_at": null
      },
      "events": [
        {"kind": "opened", "at": "2026-10-31T14:33:40Z", "by": "github:hellerve", "name": null},
        {"kind": "closed", "at": "2026-11-20T21:16:13Z", "by": "github:hellerve", "name": null}
      ],
      "unread": null,
      "closed_by": [
        {"id": "github.com/change/6519720155", "kind": "change", "name": "github:cyberwitchery/divinate#64", "...": "..."}
      ]
    }
  ]
}
```

`items` are the items the definition picked. each one has:

| field | meaning |
|---|---|
| `id` | the id to answer with |
| `state` | what the item is. a pull request also has `target_branch` and `paths`, and a release has `tag` and `assets`. [state and formats](state.md) shows them |
| `events` | everything that happened to it, oldest first. the `name` of a check event is the name of the check |
| `unread` | which events are missing and why, when a part of them couldn’t be read. `events` is `null` when none of them could |
| `closed_by` | the pull requests that close it, each with its own state and events |

what the pack answers depends on the kind of check. for `each_item`, a result
per item:

```json
{"results": [
  {"item": "github.com/ticket/6136000333", "outcome": "broken", "reason": "the description has no checklist"}
]}
```

for `all_items`, one result:

```json
{"outcome": "kept"}
```

and for `number`:

```json
{"value": 0, "unit": "percent", "basis": "0 of 41 items"}
```

an `outcome` is one of `kept`, `broken`, `pending`, `cannot_tell`, and
`not_applicable`, and every outcome but `kept` needs a `reason`, which is
what the person reading the output sees. an item the pack returns no result
for is shown as `cannot tell`.

a good pack is as careful as divinate itself about what it doesn’t know: when
`events` is `null`, or `unread` names the kind of event the check needs, the
right answer is `cannot_tell`.

if something goes wrong, the pack should write a message to its standard
error and exit with a status other than zero. divinate prints the message and
stops.

### collect

```json
{
  "protocol": 1,
  "request": "collect",
  "setup": {"sbom": "*.cdx.json"},
  "path": "acme/shop",
  "period": {"from": "2026-08-26T00:00:00Z", "until": "2026-11-24T00:00:00Z"}
}
```

`path` is what came after the colon. the pack reads what it needs and answers
with a list of readings. a reading is one question to the system, with every
request it took:

```json
{"readings": [
  {
    "resource": "osv/query/v1",
    "subject": "osv:acme/shop",
    "parameters": {"release": "v1.2.0", "asset": "shop.cdx.json", "part": "0"},
    "captured_at": "2026-11-24T10:00:03Z",
    "exchanges": [
      {
        "request": {"method": "POST", "url": "https://api.osv.dev/v1/querybatch", "body": "{\"queries\":[...]}"},
        "response": {"status": 200, "headers": {"date": "..."}, "body": "{\"results\":[...]}"}
      }
    ],
    "termination": {"kind": "exhausted"}
  }
]}
```

- `resource` names the kind of question and starts with the pack’s name.
- bodies go in as they arrived, as text. leave out request headers, since
  that’s where tokens are, and only keep the response headers you need.
- `termination` says how it ended: `exhausted` when everything was read, or
  one of the kinds in [state and formats](state.md#a-transcript) with a
  `diagnostic`. a reading that failed is still a reading. hand it back with
  what happened, and say in `derive` what is missing because of it.

divinate refuses the whole answer if a reading contains the value of a
variable the pack got through `inherit`.

### derive

```json
{"protocol": 1, "request": "derive", "transcripts": [{"id": "acq_…", "contents": {"...": "..."}}]}
```

the transcripts are the readings from `collect`, each with the id divinate
gave it. the pack answers with what they mean, in the model that
[state and formats](state.md) describes:

```json
{
  "entities": [
    {"uid": "osv/repository/github.com/acme/shop", "class": "scope", "kind": "repository", "native_kind": "repository", "name": "osv:acme/shop"}
  ],
  "statements": [
    {
      "about": "osv/repository/github.com/acme/shop",
      "aspect": "findings",
      "population": {"of": "finding", "interval": {"from": "...", "until": "..."}},
      "value": {"members": []},
      "transcripts": ["acq_…"]
    }
  ],
  "relations": []
}
```

a statement has a `value`, or a `gap` with the reason when it couldn’t be
read, and can have a `note`. to work with the built-in rules, use the same
kinds, aspects, and events as divinate does: a `finding` has a state with
`title`, `state`, `labels`, `opened_at`, and `closed_at`, and an `events`
statement that lists its event entities.

four rules make sure a pack’s collection can be trusted like any other:

- the pack’s `version` changes whenever `derive` would say something
  different about the same transcripts. `verify` only asks a pack of the
  version that made the collection, and a pack that changed its mind without
  changing its version makes `verify` fail.
- `derive` gets no `setup` and must not read anything else. the answer has to
  follow from the transcripts alone, since `verify` asks again later.
- every `uid` starts with the pack’s name and a `/`.
- every statement is about an entity in the answer and names transcripts from
  the request.

divinate refuses an answer that breaks one of them.

### what a pack can rely on

- a pack gets one request per start.
- it runs with an almost empty environment: `PATH`, `HOME`, `LANG`, `TMPDIR`,
  and what its entry lists under `inherit` and `env`.
- a check only gets the items of the request, and nothing it answers is
  stored.
- `protocol` is `1`. divinate refuses a pack that names another version.

the [checklist pack](../examples/divinate-pack-checklist) is about 70 lines
of python and a good place to start for checks. the
[osv pack](../packs/divinate-pack-osv) is a complete source.
