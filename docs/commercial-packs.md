# commercial packs

Divinate's public pack protocol is also the boundary for maintained commercial
control products. Commercial packs do not receive a privileged API, state-file
access, credentials, or network access.

## boundary

The Apache-2.0 project owns repository identity, provider-aware authenticated
acquisition, exact retained source bytes, transcripts, content addressing,
collection coverage and authority, observation and assertion identity, local
state, deterministic CLI behavior, pack execution, and offline verification.
The GitHub and Azure DevOps reference packs remain usable examples that collect
and evaluate baseline review evidence.

A commercial pack may own maintained control definitions, compatibility
guarantees, provider edge-case interpretation, stable product control IDs,
framework mappings, organization-level presentation, and supported downstream
exports. These are versioned semantics layered on retained OSS evidence. They
must not replace or obscure core evidence mechanics.

Customers pay for maintained assurance semantics, compatibility, mappings, and
support. They do not pay to unlock provenance, provider authentication,
verification, or the ability to implement an equivalent independent pack.

## compatibility metadata

A pack can declare optional compatibility metadata in `describe`:

```json
{
  "compatibility": {
    "core": ">=0.0.1,<0.1.0",
    "control_definition_version": "2026.09.0",
    "providers": ["github", "azure-devops"],
    "source_contracts": ["github-build-validation-history/v1"],
    "control_ids": ["change.build-validation.observed"]
  }
}
```

Core rejects an incompatible version range before collection or evaluation.
Pack invocations already retain the pack version, executable digest, exact
request and response, and input evidence references. Changing the executable,
pack version, or control-definition version therefore produces distinct
reevaluation provenance without rewriting earlier results.

## historical build validation

Core supports two provider-aware named resources for packs:

- `github/build_validation_history` enumerates merged integration revisions,
  Checks API results, and classic commit statuses;
- `azure_devops/build_validation_history` enumerates completed pull requests
  and their provider-native policy evaluation records.

These resources establish exact retained provider responses and complete scoped
enumeration. They do not interpret a control result. Packs remain responsible
for the narrower proposition they derive, including revision, timing, terminal
state, and historical-policy limitations.

GitHub's current APIs cannot reconstruct the historically applicable required
check configuration for every integration. Azure policy evaluation records
identify an evaluation and its configuration revision, but do not provide a
complete history of all branch-policy changes. A pack may therefore establish
observed successful validation before integration, but must not silently claim
that the historically required policy was satisfied.

The maintained control for that weaker proposition is named
`change.build-validation.observed`. The identifier
`change.build-validation.operating` is reserved for a future control that can
establish satisfaction of the requirements applicable at integration time.
