# state and formats

everything divinate knows is in one directory, `evidence/` by default. this
page describes the files in it, for when you want to read them with your own
tools or just want to know what you’re handing to someone.

```text
evidence/
  collections/
    col_<id>.json     one run of `divinate collect`
  transcripts/
    acq_<id>.json     one thing divinate asked the platform, and the answer
```

files are only ever added. a collection points to the transcripts it was built
from, so always copy the directory as a whole.

everything is json. the formats can still change between versions.

## a collection

```json
{
  "id": "col_6005c5db32e5a3a13363",
  "contents": {
    "tool": "divinate/0.0.1",
    "derivation": "6",
    "scope": "github:cyberwitchery/divinate",
    "started_at": "2026-11-24T17:21:38Z",
    "completed_at": "2026-11-24T17:23:42Z",
    "transcripts": ["acq_331acd61b8e91d794a93"],
    "entities": [],
    "statements": [],
    "relations": []
  }
}
```

the id is a checksum of the contents. `derivation` is the version of the code
that turned the responses into the three lists below. `divinate verify` can
rebuild a collection when its own version is the same.

### entities

an entity is a thing divinate knows about: a repository, a branch, a person,
a ticket, a pull request, or something that happened.

```json
{
  "uid": "github.com/event/check-run/111808187362",
  "class": "event",
  "kind": "check passed",
  "native_kind": "check passed",
  "name": "Analyze (actions)",
  "parent": "github.com/change/5706323831",
  "occurred_at": "2026-10-05T14:18:51Z"
}
```

| field | meaning |
|---|---|
| `uid` | the host, the kind, and the platform’s own id. it stays the same when the thing is renamed, so use it to join |
| `class` | `scope`, `actor`, `work_item`, `event`, `product`, or `rule` |
| `kind` | divinate’s word, the same on every platform: `ticket`, `change`, `approval`, ... |
| `native_kind` | the platform’s word, such as `code scanning alert` |
| `name` | what `show` prints |
| `parent` | the entity it belongs to. for an event, the ticket or pull request it happened on |
| `occurred_at` | for events, when it happened |

### statements

a statement is one fact about one entity. every row of `divinate show` is a
statement.

```json
{
  "about": "github.com/repository/1373627563",
  "aspect": "repository",
  "reading": "recorded",
  "value": {"archived": false, "default_branch": "main", "fork": false, "visibility": "public"},
  "digest": "3653a87eae5542572d8b108847d755770893fee44f26589722be4575741948b9",
  "transcripts": ["acq_331acd61b8e91d794a93"]
}
```

`aspect` is the name of the row, `value` is what the platform said, and
`transcripts` lists the responses the value was taken from. a
[gap](record.md#gaps) has `"reading": "gap"` and a `reason` where the value
would be. a `note` appears when the value is only part of the picture.

lists are statements too. they have a `population` that says what is listed
and for which period, and the value holds the `uid` of each member:

```json
{
  "about": "github.com/repository/1373627563",
  "aspect": "tickets",
  "population": {
    "of": "ticket",
    "interval": {"from": "2026-08-26T17:21:38Z", "until": "2026-11-24T17:21:38Z"}
  },
  "reading": "recorded",
  "value": {"members": ["github.com/ticket/5479864619"]}
}
```

each ticket, pull request, finding, and release has two statements of its
own. the first has the aspect `ticket`, `change`, `finding`, or `release`, and
holds its state. for a pull request:

```json
{
  "closed_at": "2026-10-13T07:26:57Z",
  "labels": [],
  "merged_at": "2026-10-13T07:26:57Z",
  "number": 10,
  "opened_at": "2026-10-13T06:55:06Z",
  "state": "merged",
  "target_branch": "main",
  "targets_default_branch": true,
  "title": "replace serde_yaml_ng with serde-saphyr to drop unmaintained unsafe-libyaml",
  "description": "...",
  "paths": ["Cargo.lock", "Cargo.toml", "src/error.rs", "src/project.rs"]
}
```

`paths` are the files a pull request touches (the example leaves some out).
it is `null` when divinate couldn’t read them. a release has the aspect
`release` and looks like this:

```json
{
  "tag": "v0.10.0",
  "title": "v0.10.0",
  "prerelease": false,
  "published_at": "2026-11-04T20:39:05Z",
  "assets": [
    {
      "name": "sbom-v0.10.0-sbom-diff.cdx.json",
      "size": 147812,
      "digest": "sha256:6a233713fdc1c4ccc87ed3db481e6b4c625732ce80664bb29015a9f7cfa6249a"
    }
  ]
}
```

the second has the aspect `events` and lists the events that happened to it.
when a part of them couldn’t be read (say the ci results, while the reviews
could), its value has an `unread` entry with the kinds of event that are
missing and the reason.

### relations

a relation connects two entities.

```json
{
  "from": "github.com/change/5822381209",
  "kind": "refers to",
  "to": "github.com/change/5789551915",
  "basis": "mention",
  "transcripts": ["acq_a2946f468470297bd499"]
}
```

| kind | meaning |
|---|---|
| `by` | who did it: the author of a ticket, the person behind an approval |
| `into` | the branch a pull request goes into |
| `refers to` | one item names another. `basis` says how: `closing keyword in the description`, `recorded by the source`, or `mention` |

## a transcript

a transcript is one question to the platform with everything that came back.

```json
{
  "id": "acq_331acd61b8e91d794a93",
  "contents": {
    "resource": "github/repository/v1",
    "subject": "github:cyberwitchery/divinate",
    "captured_at": "2026-11-24T17:21:39Z",
    "exchanges": [
      {
        "request": {"method": "GET", "url": "https://api.github.com/repos/cyberwitchery/divinate"},
        "response": {"status": 200, "headers": {}, "body": "...", "body_sha256": "..."}
      }
    ],
    "termination": {"kind": "exhausted"}
  }
}
```

`resource` names what was asked for, and `parameters` (when there are any)
narrow it down to a branch, a pull request, or a period. there is one exchange
per request, so a long list that came in ten pages has ten of them. the body
is stored exactly as it arrived, together with its checksum.

`termination` says how it ended. `exhausted` means divinate got everything.
the others are `truncated`, `unauthenticated`, `permission_denied`,
`not_found`, `rate_limited`, `unsafe_redirect`, `failed`, and `not_attempted`,
and each of them turns into a gap.

of the response headers, divinate keeps a fixed selection, such as the date
and the rate limit counters. it never stores request headers, which is where
your token is.
