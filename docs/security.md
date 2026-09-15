# security

divinate is a security evidence recorder, not a sandbox or secret store.

## retained data

stdout, stderr, declared inputs, declared outputs, remote response bodies, and
pack protocol data may be retained byte-exact. divinate does not redact these
bytes. never route a command or source that prints credentials through collection.

local execution refuses credential-like arguments and environment names. pack
configuration rejects credential-like keys. acquisition transcripts reject
authorization, cookie, and set-cookie headers rather than storing redacted forms.
these checks reduce obvious mistakes; they are not a general secret detector.

protect `.evidence/` according to the sensitivity of the collected systems and
outputs. review it before committing, sharing, or archiving it.

the historical PR/review resources use the existing core-only provider
credentials. their request plans contain named resources, never URLs or auth
headers. the Rust reference packs receive sanitized retained transcripts only.
PR descriptions and comments in exact response bodies may contain confidential
project information even though credentials are refused. offline verification
and reevaluation do not need authentication.

## project configuration

`divinate.yaml` is a committed declaration, not a secret store. credential-like
keys in source and pack configuration are rejected. there is no local override
file or credential manager in this version; plain executable names resolve
through `PATH` so machine-specific installation paths need not be committed.

normal collection retains an exact content-addressed YAML snapshot. do not put a
secret in YAML on the assumption that only its digest will be retained.

## local commands

`run`, built-in source collection, and pack collection execute programs as the
current user. local commands receive an empty environment plus values explicitly
supplied by the request. this reduces ambient configuration but does not make
execution hermetic.

divinate records executable bytes and their sha-256. that identifies what was
run; it does not attest that the program was trustworthy. only execute tools you
trust, and do not point collection at code from an analyzed project unless that
code is already trusted for execution.

## packs

packs are unsandboxed executables with the invoking user's filesystem and network
permissions. divinate clears their environment, uses a temporary working
directory, omits the state path from requests, drains both streams, and enforces a
timeout. these controls do not remove the pack's operating-system permissions.

core owns evidence identity, command execution, coverage recomputation, validation,
and state writes. a pack supplies source-specific interpretation. installing a
pack therefore grants code execution and trusts its declared claim requirements
and normalization semantics.

## remote acquisitions

source contracts state which proposition a collector can establish and how scope
and pagination prove completeness. their authority is not global. a verified
transcript proves integrity and contract compliance, not remote truth or account
completeness beyond the declared scope.

for GitHub, core runs `gh auth token` as operational credential plumbing and
falls back to `GITHUB_TOKEN`. helper output and the environment value exist only
in core memory. they are not execution evidence, configuration, pack input,
logs, content-addressed blobs, or acquisition transcripts.

GitHub packs can request only named branch-protection, check-run, or
commit-status resources.
core constructs `https://api.github.com` URLs, injects the authorization header,
and retains only allowlisted non-secret response headers. redirects are disabled,
so credentials are never forwarded to another host. packs receive an empty
environment and never receive the credential.

permission denial, missing resources, unauthenticated responses, rate limits,
unsafe redirects, and incomplete pagination remain distinct transcript outcomes.
none is interpreted as an empty protected-branch, check-run, or commit-status
population. retained
GitHub evidence verifies offline without a network connection or credential.

for Azure DevOps, core asks Azure CLI for an in-memory access token and falls
back to the standard `AZURE_DEVOPS_EXT_PAT` environment variable. the helper is
operational plumbing and is not captured as an execution. PAT authentication is
constructed in memory. the raw credential and Authorization value are rejected
if reflected in a response.

Azure DevOps packs can currently request only the named branch-policy resource.
core constructs URLs under the verified organization's
`https://dev.azure.com` path, resolves the repository name to Azure's repository
ID, and fetches policies applying to the configured branch. only pagination and
diagnostic response headers are retained. redirects are disabled. permission
failure remains an evidence gap rather than evidence that no policy exists.
retained Azure evidence verifies without Azure CLI, a PAT, or network access.

## integrity limits

sha-256 addressing and offline verification detect changes to retained bytes and
broken links. they do not establish source truth, executable correctness,
host-clock accuracy, remote attestation, hermetic execution, or completeness
outside a declared authoritative collection scope.
