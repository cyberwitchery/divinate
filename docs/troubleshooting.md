# troubleshooting

## the answer is insufficient evidence

this is usually a correct answer, not a processing error. it means nothing
contradicted the claim, but something the claim needs was not established. the
answer names the gap; read the `coverage` and `evidence gaps` sections of
`.evidence/dossiers/current.md`, or the `missing` field in
`.evidence/assertions/current.json`.

| gap | what to do |
|---|---|
| no collection attempted the required population | add the source that provides it to `divinate.yaml`; [questions](questions.md) lists the sources each question needs |
| permission denied | give the credential the access it lacked, then collect again |
| part of the period is older than the provider keeps | answer for a period the provider still has records for, or rely on evidence collected earlier and kept in `.evidence/` |
| pagination did not reach the last page, or a collection was interrupted | collect again |
| a change could not be matched to one pull request | inspect that change by hand; the gap names it |
| the repository is declared a mirror | collect from the system of record instead |
| the subject, branch, release, or period did not match | check `repository`, `branch`, and the `--from`/`--until` you used |

do not mark an incomplete collection as complete, widen what a source is trusted
for, or edit `.evidence/` to remove a gap. the gap is the accurate answer until
the evidence exists.

## missing configuration

if a command reports a missing `divinate.yaml`, either restore the repository's
committed configuration or bootstrap a new one:

```sh
divinate init
```

edit the generated YAML before collecting. if YAML exists, `collect` initializes
missing `.evidence/` state automatically. pass the same `--state` path to every
command when state is not `.evidence`.

## repository identity mismatch

every collection compares the configured repository with the checkout's git
origin. check both:

```sh
git -C /path/to/checkout remote get-url origin
sed -n '1,80p' divinate.yaml
```

fix the configuration intentionally or use the correct checkout. do not change
the identity merely to bypass the check.

## release inference fails

`collect` selects a release only when exactly one tag points at `HEAD`. pass
`--release <tag>` when that is not the intended rule.

the previous release must be the unique nearest ancestor. when multiple names or
branches are equally valid, pass `--base-release <tag>`. divinate reports the
candidates it refused to choose between.

## release or sbom mismatch

both release names must resolve to distinct commits. each cyclonedx sbom must
identify the expected repository and release in its metadata component.
normal collection treats the commits already recorded for each release as
expected, so a tag that was moved since it was recorded fails validation.

missing configured SBOMs are not resolved through filename guessing. correct
`sources.release-sbom.config.sbom_path` in `divinate.yaml`; use
`collect --release` and `--base-release` to override release context, not source
paths.

## gate output mismatch

the ordinary diff and policy invocation must emit identical json bytes. a
mismatch means the gate did not evaluate the exact retained delta. check the
`sbom-diff` version and invocation behavior; divinate will not join unequal
outputs.

## github authentication or permission failure

authenticate the current user once with `gh auth login`, or set `GITHUB_TOKEN`
for the Divinate process. do not add the token to `divinate.yaml` or pack
configuration. branch-protection access can require broader repository
permission than public repository reads. `status` reports unauthenticated,
permission-denied, rate-limited, and incomplete acquisitions as gaps rather than
interpreting them as absent protection or checks.

## invalid peer certificate: UnknownIssuer

```text
error: collection failed: required source github-branch-protection failed: collection failed: github request failed before receiving a response: io: invalid peer certificate: UnknownIssuer
```

divinate trusts only the public root certificates built into it, not the
operating system's certificate store. a network that intercepts TLS, such as a
corporate inspection proxy or some sandboxed environments, presents a
certificate divinate does not trust, so every provider request fails. collect
from a network that reaches GitHub or Azure DevOps directly. the failed
collection saved nothing.

## azure devops authentication or permission failure

authenticate Azure CLI with `az login`, or expose a PAT through
`AZURE_DEVOPS_EXT_PAT` for the Divinate process. do not put a PAT in YAML or pack
configuration. repository lookup and branch-policy reads require Azure DevOps
code access. unauthenticated, permission-denied, missing, redirected, and
incomplete responses remain explicit gaps; none means that the branch has no
policies.

## unknown assertion or execution id

`provenance` reads one saved evaluation. pass the label that produced the
assertion:

```sh
divinate provenance --evaluation <label> <assertion-id>
```

execution ids come from collection output or provenance output. `extract` cannot
recover an observation id or assertion id.

## verification failure

do not edit acquisition, execution, invocation, corpus, or blob files by hand.
restore the complete state directory from a known archive and run `divinate
verify` again. a partial copy is a common cause of missing-object failures.
`corpus.json` is not required for projectless `run` state, but every retained
execution transcript must still resolve its executable, input, and output blobs.

## a command cannot see normal environment settings

local tools and packs receive a cleared environment by design. pass non-sensitive
values explicitly with `run --environment name=value`. do not pass credentials;
credential-like names and arguments are refused, and command streams are retained
without redaction.

## evaluation cannot choose a release

pass `--release` explicitly. automatic selection succeeds only when the latest
release in evidence is unambiguous at the evaluation time.

## review cannot choose a predecessor

parameterless review requires the `previous` snapshot created by a second normal
collection. for named or imported historical evaluations, use:

```sh
divinate review --since <older-label> --current <newer-label>
```

## pack failure

run `divinate pack <id>` first. it checks that the configured executable responds
to `describe`, uses protocol version 1, and identifies itself with the configured
id. non-zero status, timeout, invalid json, trailing stdout, and protocol errors
all fail the operation.
