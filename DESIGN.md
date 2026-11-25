# design

this document is for people who want to work on divinate or want to know how
it works inside. if you want to use it, start with the
[readme](README.md) and the pages in [docs/](docs/).

## the idea

a security review or an audit keeps asking the same kind of question: do you
work the way you say you do? are changes reviewed, are findings handled in
time, is the main branch protected? the answers are in the platforms the team
uses every day, but they’re spread over issues, pull requests, ci runs, and
settings pages, and the settings only show what’s true today.

divinate does two things about that. it copies the relevant facts out of the
platform into a directory, with a timestamp, so that you build up a history.
and it lets you write a rule in a small yaml file and check it against those
facts.

the two are kept apart on purpose. the directory only holds what the platform
said. rules and their results aren’t stored in it. that way one collection can
be checked against any number of rules, by you today and by an auditor with
their own rules next year.

## how a run works

```
platform ──requests──▶ transcripts ──derive──▶ entities, statements, relations
                            │                              │
                            └────────── one collection ────┘
                                            │
                       show · ledger · verify · check
```

1. `collect` asks the platform for everything it needs about one repository
   or organisation. each answer is stored as it arrived, in a transcript.
2. the code for that platform goes through the transcripts and derives a
   common model from them: entities, statements, and relations.
3. the transcripts and the model are stored together as one collection.
   collections are only added, never changed.
4. the other commands only read collections. `show` and `ledger` print them,
   `check` applies rules to one, and `verify` repeats step 2 and compares.
   `check` can hand items to a pack, which is a program outside this crate.

step 2 is a pure function. it makes no requests and doesn’t look at the clock,
so it gives the same result every time it runs on the same transcripts. this
is what makes `verify` possible, and it’s the main thing to protect when you
change the code: anything a statement says has to come out of a transcript.
when a change makes the same transcripts produce a different model, bump
`DERIVATION` in `src/record.rs`, so `verify` knows that older collections were
built differently.

## transcripts

a transcript is one question to the platform, such as “the reviews of pull
request 12”, with every request it took and every response that came back.
bodies are kept byte for byte with a checksum. of the headers, a fixed
selection of response headers is kept and no request headers at all, so the
token can’t end up on disk.

a transcript also says how the question ended. `exhausted` means everything
was read. the other endings (`truncated`, `unauthenticated`,
`permission_denied`, `not_found`, `rate_limited`, `unsafe_redirect`, `failed`,
`not_attempted`) mean something is missing, and they’re where gaps come from.

the reader retries server errors and waits out short rate limits. when a rate
limit is too long to wait for, the rest of the run is marked `not_attempted`
and the collection is stored with what it has.

## the model

every platform is translated into the same model, so that `show`, `ledger`,
and `check` don’t need to know which platform they’re looking at.

an **entity** is a thing. there are six classes:

| class | what it is | examples |
|---|---|---|
| scope | a place where things live. scopes nest | organisation, project, repository, branch |
| actor | someone who does things | user, bot, group |
| work item | something that gets opened and eventually closed | ticket, change, finding |
| event | something that happened at a point in time | comment, approval, merge, push, check passed |
| product | something the process puts out | release |
| rule | a requirement that has an identity of its own on the platform | |

the platforms in core fill the first five classes. `rule` is there for
sources that give a requirement its own id. on the three platforms a
requirement is recorded as the state of its branch.

an entity’s id is made of the host, its kind, and the id the platform itself
uses, so it survives a rename. it has a kind in divinate’s words (`change`)
and one in the platform’s (`merge request`).

a **statement** is one fact about one entity: the review policy of a branch,
the state of a ticket, or a list such as the pull requests merged in a
repository during the period. a statement is either a recorded value or a gap
with a reason. it can carry a note when the value is only part of the picture.

a **relation** connects two entities, such as a pull request and the ticket it
closes, and says how divinate knows: the platform says so, there’s a closing
keyword in the description, or it’s only a mention.

## decisions worth knowing

these are the choices that shape the code. most of them exist because the
model has to be honest about what it doesn’t know.

**a list is only recorded when it was read to the end.** if page three of the
pull requests fails, divinate could store the first two pages, but then “no
pull request was merged without review” would be checked against a part of
them and come out wrong. so the whole list becomes a gap, and rules about it
answer `cannot tell`.

**partial answers get a note.** github has two mechanisms for branch
protection, and one of them can only be read by admins. when only the other
is readable, divinate records what it requires and adds a note that there may
be more. a rule that’s already satisfied by the readable part is kept, and one
that isn’t answers `cannot tell`.

**“the platform has none” is an answer.** a scanner that’s switched off
returns an error on github. that’s recorded as an empty list with a note,
since the platform did answer the question.

**events of one item can be partly unread.** reviews and ci results come from
different requests. when the ci results fail, the reviews are still recorded,
and only rules about checks answer `cannot tell` for that item.

**branch settings are samples.** platforms don’t keep a history of their
settings, so each collection has the settings as of its own time. a rule that
needs the settings at the time of a merge uses the first collection after the
merge. when the collection before the merge differs, the settings changed
somewhere in between and the rule answers `cannot tell`.

**times are compared as times.** platforms write timestamps with different
precision and offsets, so they’re parsed before they’re compared.

## platforms

each platform implements the `Source` trait in `src/source/`. a source does
three things: it finds a token, it says which questions to ask for a scope,
and it derives the model from the transcripts.

a source never makes a request itself. all requests go through one reader in
`src/source/reading.rs`, which stores the transcripts, follows pages only on
the platform’s own host, doesn’t follow redirects, and refuses a response
that contains the token. keeping this in one place means a new source can’t
get it wrong.

for the model, every source uses the same two builders: `source/build.rs` for
scopes and their settings, and `source/work.rs` for tickets, changes,
findings, and their events. a new source that uses them produces the same
shapes as the existing ones, and everything downstream works without changes.
[docs/sources.md](docs/sources.md) lists what each platform’s terms map to.

## checking

a process definition has `items` and `steps` for rules about tickets, pull
requests, and findings, and `branches` for rules about settings.
[docs/processes.md](docs/processes.md) is the reference.

`check` is a function of a definition and a collection (plus the earlier
collections, for the branch settings over time). it stores nothing. a summary
over several collections is the same check run on each of them.

each step of each item gets one of five results: `kept`, `broken`, `pending`,
`cannot tell`, or `n/a`. the code is in `src/process/check.rs`. when the
events a step asks for aren’t there, it matters whether the collection could
have contained them: if a gap or a note says it couldn’t, the answer is
`cannot tell`, and `broken` is kept for the cases where the collection is
complete for that question.

## packs

a pack is a program declared in `divinate.yaml`. it gets one json request on
standard input and answers with one json document.
[docs/packs.md](docs/packs.md) describes the protocol, and the code is in
`src/pack.rs` and `src/pack/source.rs`.

packs exist because a rule language that could express everything would be a
programming language. the definition format stays small, and anything that
needs real logic (parsing a description, a calculation over many items) goes
into a pack, in whatever language its author likes.

a pack can judge items in a `check`, and it can be a source. a few choices
keep either from weakening the rest:

- a check pack is shown derived items, never transcripts, so it works on the
  same model on every platform. nothing it answers is stored, and a report
  names the packs that took part and their versions.
- a source pack makes its own requests. this is the one place where core
  doesn’t do the reading, because a pack that had to describe every request
  in advance couldn’t read much. in exchange it hands back every response,
  and core seals them as transcripts, so they’re covered by `verify` like any
  others.
- a source pack derives in a separate request that gets the transcripts and
  nothing else. that keeps the property the built-in sources have: the model
  is a function of the transcripts and can be worked out again later. the
  collection records the pack and its version, and `verify` asks that
  version again when it’s configured.
- what a source pack derives is checked before it’s stored: ids stay in the
  pack’s own namespace, and every statement names transcripts that exist.
- a pack is started with an almost empty environment and gets the variables
  its entry names. a reading that repeats one of those values is refused.

a pack can also ship process definitions, which is how a set of rules for a
framework or a company policy can be handed around as one thing.

## verifying

`verify` needs no network and no token. for every collection it recomputes
the id of each transcript and the checksum of each body, runs the derivation
again, and compares the result with the stored collection. a collection with
a different `DERIVATION` has its files checked and is reported as derived by
other rules.

this shows that the directory is intact and consistent with itself. the
directory isn’t signed, so it doesn’t show where it came from.
[docs/security.md](docs/security.md) describes what that means in practice.
