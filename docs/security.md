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

## local commands

`run`, `collect release`, and pack collection execute programs as the current
user. local commands receive an empty environment plus values explicitly supplied
by the request. this reduces ambient configuration but does not make execution
hermetic.

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

authenticated generic http plans are not supported by pack protocol version 1.
credentials must remain in a core-owned acquisition path that excludes them from
retained transcript data.

## integrity limits

sha-256 addressing and offline verification detect changes to retained bytes and
broken links. they do not establish source truth, executable correctness,
host-clock accuracy, remote attestation, hermetic execution, or completeness
outside a declared authoritative collection scope.
