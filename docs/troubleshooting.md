# troubleshooting

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

normal release collection compares the configured repository with the checkout's
git origin. check both:

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
identify the expected repository and release in its metadata component. when
normal collection reuses revisions already recorded for either release as
expected revisions. a moved tag therefore fails provenance validation.

missing configured SBOMs are not resolved through filename guessing. correct
`sources.release-sbom.config.sbom_path` in `divinate.yaml`; use
`collect --release` and `--base-release` to override release context, not source
paths.

## gate output mismatch

the ordinary diff and policy invocation must emit identical json bytes. a
mismatch means the gate did not evaluate the exact retained delta. check the
`sbom-diff` version and invocation behavior; divinate will not join unequal
outputs.

## insufficient evidence

this is usually a valid evaluation result, not a processing error. read the
dossier's `coverage` and `evidence gaps` sections. common causes are:

- no collection attempted the required proposition
- pagination did not reach a terminal page
- permissions hid part of the population
- source retention did not cover the requested interval
- a source contract lost current authority
- the evidence subject, branch, release, or interval did not match

do not turn an incomplete run into a complete one or widen a source's declared
authority to remove the gap.

## github authentication or permission failure

authenticate the current user once with `gh auth login`, or set `GITHUB_TOKEN`
for the Divinate process. do not add the token to `divinate.yaml` or pack
configuration. branch-protection access can require broader repository
permission than public repository reads. `status` reports unauthenticated,
permission-denied, rate-limited, and incomplete acquisitions as gaps rather than
interpreting them as absent protection or checks.

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
