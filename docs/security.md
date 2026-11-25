# security

divinate runs with your token and stores what it reads on your disk. this page
describes how it treats the token, what ends up in `evidence/`, and how much
weight a verified directory can carry.

## your token

divinate gets a token from `gh`, `glab`, or `az`, or from an environment
variable, and sends it to that platform’s api and nowhere else.

- it only ever reads. there is no command that changes anything on the
  platform, so a read-only token is all it needs.
- the token is never written to disk. request headers aren’t stored, and if a
  response happens to contain the token, divinate refuses to store that
  response.
- it doesn’t follow redirects, and it only fetches the next page of a list
  from the host it’s already talking to.

## what’s in `evidence/`

responses are stored exactly as they arrived, with nothing removed. depending
on what you collected, the directory holds:

- titles and descriptions of tickets and pull requests
- comments and review threads
- the diff of every pull request in the period, which means parts of your
  source code
- account names, which are email addresses on azure devops
- repository and organisation settings as the platform returned them. these
  can include things like a billing email address
- scanner alerts, including where in the code a finding is
- response headers that describe your token, such as the list of scopes
  github reports for it

so treat the directory like the repository it came from. the people who may
see the repository’s issues and security alerts are the people who should see
`evidence/`. have a look through it before you commit it somewhere or send it
to someone.

## what a verified directory tells you

`divinate verify` answers one question: is this directory still what divinate
wrote? it finds files that were changed, removed, or left behind in a copy,
and it finds a collection whose contents no longer match the stored responses.
that makes it the right thing to run after a backup is restored, or when a
colleague sends you their directory and you want to run your own rules on it.

the directory isn’t signed, and the timestamps come from the clock of the
machine that collected. somebody who wants to fake a directory from scratch
can produce one that verifies. for an audit where that matters, the simple
answer is to give the auditor read access and let them run `divinate collect`
themselves. it takes a few minutes, and they get a directory they made with
their own hands.

## packs

a [pack](packs.md) is a program on your machine that divinate starts when a
definition uses it. it runs with your user’s rights, like any other program
you install, so only install packs from people you trust.

divinate limits what it hands to a pack. a pack is started with an almost
empty environment, so the tokens in `GITHUB_TOKEN` and friends aren’t passed
on. it’s shown the items a definition picked (titles, descriptions, labels,
events, account names) and nothing else from `evidence/`, and it can’t add to
or change the directory through divinate.

## reporting a vulnerability

please use the [security policy](https://github.com/cyberwitchery/divinate/security/policy).
