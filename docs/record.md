# reading the record

every `divinate collect` adds one collection to `evidence/`. `divinate show`
prints the latest one, and `divinate ledger` prints all of them side by side.
this page explains what the rows in that output mean, and what else divinate
keeps that the output doesn’t show.

## the three marks

every row starts with one of three marks:

| mark | meaning |
|---|---|
| `■` | divinate asked, and this is what the platform answered |
| `▣` | the same, and the answer differs from the collection before |
| `⬚` | divinate asked and got no answer. the row says why |

a row can have a second line that starts with `note:`. you get a note when the
answer is only part of the picture. the list of repositories in an
organisation, for instance, only holds the repositories your token can see, and
the note tells you so.

## rows about a repository

the output has one block per thing divinate looked at. for a repository (a
project on gitlab and azure devops) the rows are:

| row | what it tells you |
|---|---|
| repository | visibility, default branch, and whether it’s archived or a fork |
| tickets | how many issues were opened in the period |
| changes | how many pull requests were opened in the period |
| merged changes | how many pull requests were merged in the period, whenever they were opened |
| releases | how many releases were published in the period |
| code scanning findings, dependency findings, secret findings | how many alerts each github scanner opened in the period |

when you collect a whole organisation or group, you get a block for it with a
`repositories` row, and a block per repository below that. an azure devops
organisation also has a `projects` row, and each project a `project` row with
its visibility.

## rows about a branch

a block whose name ends in `@main` is a branch. divinate looks at the default
branch, and at every other branch that a pull request of the period was merged
into.

| row | what it tells you |
|---|---|
| updates | how many times the branch was updated in the period: merges, pushes, and force pushes |
| branch protection | whether the platform protects the branch |
| branch rules | the names of the rules or policies that apply to it |
| review policy | how many approvals a pull request needs before it can be merged, and where that requirement comes from |
| required checks | which ci checks have to pass before a merge |

the branch rows are the ones to watch in `divinate ledger`. if someone turns
off required reviews on `main`, the next collection shows `review policy` with
a `▣`.

## tickets, pull requests, findings, and releases

`show` only prints how many there are. the record holds each one. for a
ticket or a pull request that’s its title, description, labels, author, and
whether it’s open. a pull request also has the list of files it touches. a
release has its tag and the names, sizes, and checksums of the files attached
to it.

the record also holds everything that happened to each of them:

| event | on | meaning |
|---|---|---|
| opened | everything | when it was opened, and by whom |
| comment | tickets, changes | a person commented. messages the platform writes itself are left out |
| closed, reopened | everything | it was closed, or opened again |
| dismissed | findings | someone set the alert aside without a fix |
| approval, changes requested | changes | a review, and who gave it |
| approval withdrawn | changes | a reviewer took their approval back, or it was dismissed |
| commit | changes | a commit was added to the pull request |
| check passed, check failed | changes | a ci check finished. the event has the name of the check |
| merge | changes, branches | the pull request was merged |
| published | releases | the release was published, and by whom |
| push, force push | branches | someone updated the branch without a pull request |

divinate also keeps the links between them. a pull request knows which branch
it goes into, and which tickets it closes. a ticket link comes from a closing
keyword in the description (“fixes #27”) or from the link the platform keeps
itself. a pull request that only mentions a ticket is recorded as a mention and
doesn’t count as its fix.

these events are what you write rules about. [process definitions](processes.md)
shows how, and [state and formats](state.md) describes the file if you’d rather
read it with your own tools.

## the period

tickets, pull requests, findings, and releases are read for a period, which is
the last 90 days unless you pass `--from` and `--until`. a ticket is part of a
collection when it was opened in the period, a pull request when it was
opened or merged in it, and a release when it was published in it. an old ticket that’s still open is left out, so pick a
period that starts early enough for the rule you want to check.

branch settings work differently. the platform only tells divinate what the
settings are right now, so each collection holds the settings as of the moment
it ran. that’s the reason to collect on a schedule: the more often you
collect, the better you know what the settings were when a given pull request
was merged. when the settings changed between the two collections around a
merge, a rule about that merge answers `cannot tell`.

## gaps

a row with `⬚` says `gap:` where the answer would be, followed by the reason
and what the platform said. the reasons you’ll see are:

| reason | what happened |
|---|---|
| not authenticated | there was no token, or the platform rejected it |
| permission denied | the token works but isn’t allowed to read this |
| not found, or not visible to this credential | the thing doesn’t exist, or the token can’t see it (platforms often don’t say which) |
| rate limited | the platform told divinate to slow down and the reading could not be finished |
| reading stopped before the last page | a long list broke off partway through |
| refused a redirect | the platform pointed to another host, and divinate only talks to the one you named |
| failed | the network or the server had a problem |
| not attempted | divinate didn’t ask, because something it needed first was missing |

a gap only affects the rows that needed the missing answer. the rest of the
collection is as good as any other, and rules that depend on a gap answer
`cannot tell`. most gaps go away with a token that has more permissions.
[sources](sources.md) lists what each platform asks for, and
[troubleshooting](troubleshooting.md) covers the common cases.

one case looks like a gap and isn’t: a github scanner that’s switched off is
recorded as `no findings` with a note that says the scanner isn’t set up.
