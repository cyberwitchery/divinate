# getting started

this guide takes a GitHub or Azure DevOps repository to its first answers: is
review required, and did every change actually get reviewed?

## install

divinate requires rust 1.95 or newer. from a checkout of this repository:

```sh
cargo install --path .
```

this installs three executables on your `PATH`: `divinate`, and the reference
packs `divinate-pack-github` and `divinate-pack-azure-devops`. packs are the
plug-ins that know how to read each provider.

## initialize the repository

run this from a checkout of the repository you need to answer for:

```sh
divinate init
```

init reads the git `origin`, writes a minimal `divinate.yaml`, and creates the
local `.evidence/` directory. commit `divinate.yaml`: it declares which evidence
the repository collects, and reviewers should see changes to it.

GitHub origins become `github:owner/name`. Azure DevOps origins become
`azure-devops:organization/project/repository`; accepted forms are
`git@ssh.dev.azure.com:v3/organization/project/repository`,
`ssh://git@ssh.dev.azure.com/v3/organization/project/repository`,
`https://dev.azure.com/organization/project/_git/repository`, and the
equivalent `organization.visualstudio.com` HTTPS form. divinate checks that the
checkout still matches this identity every time it collects.

## choose the questions

each question needs specific evidence, and each piece of evidence comes from a
*source*: one collector of one pack. pick the questions you need from
[questions divinate answers](questions.md) and declare their sources:

| question | GitHub collectors | Azure DevOps collectors |
|---|---|---|
| is approval required before merging? | `branch-protection` | `branch-policy` |
| did every change get an approving review? | `repository-mutations` and `pull-request-reviews` | `repository-mutations` and `pull-request-reviews` |
| does the branch require named status checks? | `branch-protection` | — |
| did ci pass for the current commit? | `check-runs` and `commit-statuses` | — |
| does the branch have blocking build validation? | — | `branch-policy` |

### GitHub

```yaml
repository:
  identity: github:example/service
  branch: main

packs:
  cyberwitchery.github:
    executable: divinate-pack-github

sources:
  branch-protection:
    provider:
      pack: cyberwitchery.github
      collector: branch-protection
  branch-changes:
    provider:
      pack: cyberwitchery.github
      collector: repository-mutations
  reviews:
    provider:
      pack: cyberwitchery.github
      collector: pull-request-reviews
  check-runs:
    provider:
      pack: cyberwitchery.github
      collector: check-runs
  commit-statuses:
    provider:
      pack: cyberwitchery.github
      collector: commit-statuses
```

divinate gets a GitHub token from `gh auth token`, or from `GITHUB_TOKEN` if
`gh` is not available. authenticate once with `gh auth login`. reading branch
protection needs more permission than reading a public repository.

### Azure DevOps

```yaml
repository:
  identity: azure-devops:example-org/example-project/example-repository
  branch: develop

packs:
  cyberwitchery.azure-devops:
    executable: divinate-pack-azure-devops

sources:
  branch-policy:
    provider:
      pack: cyberwitchery.azure-devops
      collector: branch-policy
  branch-changes:
    provider:
      pack: cyberwitchery.azure-devops
      collector: repository-mutations
  reviews:
    provider:
      pack: cyberwitchery.azure-devops
      collector: pull-request-reviews
```

divinate gets an Azure DevOps token from `az account get-access-token`, or from
`AZURE_DEVOPS_EXT_PAT`. authenticate once with `az login`.

### rules for `divinate.yaml`

- source names, such as `branch-changes`, are yours to choose. keep them
  stable: they identify the source in history.
- a declared source is enabled. sources are required by default: if a required
  source fails, the whole collection stops and nothing is saved. add
  `required: false` to let collection continue and record the failure instead.
- never put a token or password in `divinate.yaml`. divinate refuses
  credential-like keys, and it keeps an exact copy of the file with the
  evidence. packs never receive credentials either; divinate fetches from the
  provider itself and hands packs only the responses.
- plain executable names are looked up on `PATH`. absolute and
  repository-relative paths also work.

this repository's own [`divinate.yaml`](../divinate.yaml) is a working GitHub
configuration.

## collect and answer

```sh
divinate collect
```

divinate validates `divinate.yaml`, runs each source, keeps everything it read,
answers every question its sources support, and writes the answers to
`.evidence/dossiers/current.md`. the output has this shape; the sources and
counts depend on your configuration:

```text
Collected
  branch-changes                       complete (evidence recorded)
  ...

Evaluation
  supported                2
  insufficient evidence    1
  contradicted             0
  stale                    0
  not automatable          0

dossier: .evidence/dossiers/current.md
```

questions about history, such as "did every change get reviewed?", cover
everything since the repository's first commit by default. GitHub keeps about a
year of activity, so on an older repository part of that period cannot be read
and the answer is **insufficient evidence** for that reason. for an audit or a
questionnaire, answer for the period that was asked about:

```sh
divinate collect --from 2026-07-01T00:00:00Z --until 2026-10-01T00:00:00Z
```

`--until` cannot be later than now. times are rfc 3339.

## read the answers

```sh
divinate status       # summary: results, source health, open gaps
divinate export dd    # the answers as a document: .evidence/views/dd-response.md
```

`.evidence/dossiers/current.md` has the full reasoning for every answer.
[reading an answer](answers.md) explains each part and how to repeat an answer
accurately.

after the next collection, see what changed:

```sh
divinate collect
divinate review       # .evidence/views/review.md
```

## hand the answers over

```sh
divinate verify
```

verify rechecks every answer against the records it came from, offline. give
someone the `.evidence/` directory and they can run the same check without
access to your repository or provider. it contains provider responses byte for
byte, including pull request text, so share it as you would the repository.

## a repository that is already configured

when `divinate.yaml` is committed, nobody needs to run `init` again:

```sh
git clone <repository>
cd <repository>
divinate collect
```

collect creates `.evidence/` if it is missing. the packs and tools named in
`divinate.yaml` must be on `PATH`, and the provider credential must be
available.

## release questions

questions about a release, such as "which dependencies did this release change,
and did they pass policy?", need the built-in `release-sbom` source, a
CycloneDX sbom for each release, and release tags. see
[workflows](workflows.md#release-dependency-evidence).
