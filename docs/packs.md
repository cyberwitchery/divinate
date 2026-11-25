# packs

a pack adds to what divinate can check. it’s a small program that you (or
someone you trust) write in any language. a pack can do two things: judge
things that a process definition can’t express on its own, and ship
ready-made process definitions.

a typical reason to write one: your policy says that every pull request has a
checklist in its description and that all boxes are ticked. divinate has the
description, but no step that reads task lists. a pack can read it.

## using a pack

a pack is a program named `divinate-pack-<name>`. divinate finds it in the
directories listed in `DIVINATE_PACKS`, and after that on your `PATH`. this
repository has an example in [examples/](../examples/divinate-pack-checklist):

```console
$ export DIVINATE_PACKS=$PWD/examples
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

`with` passes settings to the check. what they are is up to the pack.
`divinate pack <name>` tells you which of the three places each check is for.
steps that use a pack sit next to ordinary steps and get the same five
results. a step with `uses` can also have `linked`, which hands the pack the
pull requests that close a ticket instead of the ticket.

## writing a pack

divinate starts the pack, writes one json request to its standard input, and
reads one json answer from its standard output. there are two requests.

### describe

```json
{"protocol": 1, "request": "describe"}
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

`name` has to match the file name. `answers` is `each_item` for a check used in
a step, `all_items` for one used under `overall`, and `number` for a measure.
a `definition` is the text of a [process definition](processes.md), and it can
use the pack’s own checks.

### check

```json
{
  "protocol": 1,
  "request": "check",
  "check": "completed",
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

### what a pack can rely on

- a pack gets one request per start, and is started once per check and
  collection.
- it runs with an almost empty environment (`PATH`, `HOME`, `LANG`, and
  `TMPDIR`), so the tokens divinate uses aren’t passed on.
- it only gets the items of the request. it has no access to `evidence/`
  through divinate, and nothing it answers is stored.
- `protocol` is `1`. divinate refuses a pack that names another version.

the [example pack](../examples/divinate-pack-checklist) is about 70 lines of
python and a good place to start.
