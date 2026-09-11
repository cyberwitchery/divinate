# concepts

divinate separates retained facts from the claims derived from them.

```text
acquisition and execution transcripts
  -> collection coverage
  -> observations
  -> assertions
  -> views
```

## transcripts

an acquisition transcript records a remote request and response sequence,
including scope, pagination, termination, response digests, and the source
contract used to interpret completeness.

an execution transcript records a local executable digest, arguments, named
inputs and outputs, explicit environment, timestamps, exit status, and byte-exact
stdout and stderr.

transcripts establish what divinate captured. they do not establish that the
source or tool was correct.

## collection coverage

a collection run records an attempt to enumerate a population. its scope is a
proposition, subject, branch where applicable, and half-open time interval. the
outcome distinguishes complete, partial, permission-denied, retention-limited,
interrupted, failed, and not-attempted runs.

an empty complete collection can support an absence claim. an empty response
without complete authoritative collection cannot.

authority is local to a proposition, subject, and interval. there is no global
source ranking. a source contract supplies the rule that lets core decide whether
a captured exchange covers the requested population.

## observations

an observation is a typed interpretation of retained source bytes. it names its
subject, time, producer, evidence class, claim key, adapter, and provenance.

configured intent, observed operation, and observed state are different evidence
classes. a branch rule requiring review does not prove that every change was
reviewed. an approval count does not prove that the review was adequate.

## assertions

an assertion contains a claim, outcome, validity, derivation identity, evidence
uses, coverage decisions, identity joins, reasoning, limitations, and missing
evidence.

outcomes are:

- `supported`: the required evidence and coverage establish the claim.
- `contradicted`: retained evidence contains a counterexample.
- `insufficient_evidence`: the claim was not contradicted, but its requirements
  were not established.
- `stale`: suitable point-in-time evidence exists but is outside its freshness
  window.
- `not_automatable`: the claim requires judgement the retained technical evidence
  cannot supply.

these states are not confidence scores. evaluators apply explicit rules and name
the gap when those rules cannot support a claim.

## time

`observed_at` says when the represented fact was observed. it does not make the
evidence available before capture. historical evaluation includes an observation
only when every transcript needed to justify it existed by the evaluation time.

`evaluate --at` sets that evaluation time. the evaluation interval is independent:
`from` is inclusive and `until` is exclusive.

withdrawing a source contract's current authority affects current interpretation.
it does not rewrite a historical transcript.

## views

dossiers, reviews, and due-diligence responses select and render saved assertions.
they do not collect evidence and contain no independent assertion logic. use the
json assertion set when another system needs the structured result.
