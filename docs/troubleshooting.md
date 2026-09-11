# troubleshooting

## missing configuration

if a command reports a missing `config.json`, initialize state:

```sh
divinate init --repository github:owner/repository --branch main
```

pass the same `--state` path to every command when state is not `.evidence`.

## repository identity mismatch

`collect release` compares the configured repository with the checkout's git
origin. check both:

```sh
git -C /path/to/checkout remote get-url origin
sed -n '1,80p' .evidence/config.json
```

fix the configuration intentionally or use the correct checkout. do not change
the identity merely to bypass the check.

## release or sbom mismatch

both release names must resolve to distinct commits. each cyclonedx sbom must
identify the expected repository and release in its metadata component. when
release movement must be detected, pass the expected commits with
`--base-revision` and `--revision`.

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

## a command cannot see normal environment settings

local tools and packs receive a cleared environment by design. pass non-sensitive
values explicitly with `run --environment name=value`. do not pass credentials;
credential-like names and arguments are refused, and command streams are retained
without redaction.

## evaluation cannot choose a release

pass `--release` explicitly. automatic selection succeeds only when the latest
release in evidence is unambiguous at the evaluation time.

## pack failure

run `divinate pack <id>` first. it checks that the configured executable responds
to `describe`, uses protocol version 1, and identifies itself with the configured
id. non-zero status, timeout, invalid json, trailing stdout, and protocol errors
all fail the operation.
