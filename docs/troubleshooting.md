# troubleshooting

## `no credential found`

divinate couldn’t get a token. log in with the platform’s command line tool
(`gh auth login`, `glab auth login`, or `az login`), or set `GITHUB_TOKEN`,
`GITLAB_TOKEN`, or `AZURE_DEVOPS_EXT_PAT`.

## a row is a gap

a row that starts with `⬚` is something divinate couldn’t read. the reason is
printed next to it:

| reason | what to do |
|---|---|
| not authenticated | the token is missing or expired. log in again and collect again |
| permission denied | the token isn’t allowed to read this. use one that is. [sources](sources.md) says what each platform asks for |
| not found, or not visible to this credential | check the spelling of the repository. a private repository you have no access to looks exactly like one that doesn’t exist |
| rate limited | the platform wants you to wait. collect again later. everything after this point in the run is marked `not attempted` |
| reading stopped before the last page | a list broke off partway. collect again |
| failed | a network or server problem. collect again |

collecting again adds a new collection, and the old one with its gap stays
where it is. that’s fine, `show` and `check` use the latest one.

sometimes a gap is simply the right answer: you aren’t an admin, so you can’t
read classic branch protection. you can leave it. rules that need the missing
part answer `cannot tell`, and everything else works.

## a check says `cannot tell`

the output gives the reason for each one. the usual ones:

- the list of tickets or pull requests couldn’t be read, so divinate doesn’t
  know which items there are
- the events of one item couldn’t be read
- the ci results of a pull request couldn’t be read, though its reviews could
- the settings or updates of a branch couldn’t be read
- the branch settings changed between the collections before and after a
  merge, so divinate doesn’t know which ones applied

all but the last come from a gap, and fixing the gap fixes the check. the last
one gets rarer the more often you collect.

## a check finds nothing to check

- the label doesn’t match. upper and lower case matter, so `Security` and
  `security` are different
- the items were opened before the period started. collect with an earlier
  `--from`
- with `when: merged`: nothing was merged in the period

## `the pack "…" is not configured`

a definition or a scope names a [pack](packs.md) that isn’t in
`divinate.yaml`. divinate reads that file from the directory you run it in,
so either run it from the directory that has the file or pass `--config`.
`divinate pack <name>` tells you whether divinate finds the pack and can
start it.

## a pattern gives a yaml error

a pattern that starts with `*`, such as `*.cdx.json`, has to be in quotes:
`asset: '*.cdx.json'`. yaml reads a bare `*` at the start of a value as a
reference to something else in the file.

## a scanner shows `no findings`

look for a note under the row. `the scanner is not set up` means the scanner
is switched off for this repository. without a note the scanner is on and
found nothing in the period.

## collecting takes a long time

divinate asks the platform several questions per ticket and pull request, so
a busy repository takes a while. gitlab.com also makes clients wait when they
ask too much at once, and divinate prints `rate limited; waiting N seconds`
when that happens. you can just let it run. if you’re in a hurry, pass a later
`--from` to collect a shorter period, or `--no-files` to skip the files of
each pull request.

## `verify` fails

`verify` names the file that doesn’t match. something in the directory was
changed, deleted, or lost in a copy. get the directory back from wherever you
keep a copy of it. editing the files by hand won’t help, since every file is
checked against its checksum.

a line that says `derived by other rules` isn’t a failure. that collection was
written by another version of divinate, and its files are intact.

## a tls error such as `UnknownIssuer`

something on your network (often a company proxy) opens tls connections and
re-signs them with its own certificate. divinate only trusts the public
certificate authorities it ships with, so it won’t connect through that. run
`collect` from a network that reaches the platform directly.
