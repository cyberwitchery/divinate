#!/usr/bin/env python3
"""print divinate's saved answers in a compact, faithful form.

usage: answers.py [STATE_DIR] [--evaluation LABEL] [--claim CLAIM_ID]

reads STATE_DIR/assertions/LABEL.json (default: .evidence, current) and prints,
for each answer: the result, the exact claim, the subject and period, and the
counterexamples, gaps, and limitations a faithful report must carry. it only
reads; it never changes divinate state. standard library only.
"""

import argparse
import json
import signal
import sys
from pathlib import Path

RESULTS = {
    "supported": "SUPPORTED",
    "contradicted": "CONTRADICTED",
    "insufficient_evidence": "INSUFFICIENT EVIDENCE",
    "stale": "STALE",
    "not_automatable": "NOT AUTOMATABLE",
}


def subject_text(subject):
    if not isinstance(subject, dict):
        return str(subject)
    text = subject.get("repository", "?")
    if subject.get("branch"):
        text += f" branch {subject['branch']}"
    if subject.get("release"):
        text += f" release {subject['release']}"
    if subject.get("from") or subject.get("until"):
        text += f" period {subject.get('from')} .. {subject.get('until')} (until excluded)"
    return text


def reasons(items, key="reason"):
    return [item.get(key) for item in items or [] if isinstance(item, dict) and item.get(key)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("state", nargs="?", default=".evidence")
    parser.add_argument("--evaluation", default="current")
    parser.add_argument("--claim", help="only this assertion_type")
    args = parser.parse_args()

    path = Path(args.state) / "assertions" / f"{args.evaluation}.json"
    try:
        answers = json.loads(path.read_text())
    except FileNotFoundError:
        sys.exit(f"no saved evaluation at {path}; run `divinate collect` first")

    if args.claim:
        answers = [a for a in answers if a.get("assertion_type") == args.claim]
        if not answers:
            sys.exit(f"no answer for {args.claim} in {path}")

    for answer in answers:
        outcome = answer.get("outcome", "?")
        print(f"[{RESULTS.get(outcome, outcome)}] {answer.get('assertion_type')}  ({answer.get('id')})")
        print(f"  claim:    {answer.get('claim')}")
        print(f"  subject:  {subject_text(answer.get('subject'))}")
        print(f"  answered: {answer.get('evaluated_at')}")
        validity = answer.get("validity") or {}
        if validity.get("fresh_until"):
            print(f"  fresh until: {validity['fresh_until']}")
        for label, values in (
            ("evidence", reasons(answer.get("support"))),
            ("counterexample", reasons(answer.get("contradictions"))),
            ("gap", [
                f"{item.get('requirement')}: {item.get('reason')}"
                for item in answer.get("missing") or []
                if isinstance(item, dict)
            ]),
            ("reasoning", reasons(answer.get("reasoning"), "conclusion")),
            ("limitation", answer.get("limitations") or []),
        ):
            for value in values:
                print(f"  {label}: {value}")
        for decision in answer.get("coverage") or []:
            proposition = (decision.get("requirement") or {}).get("proposition", "?")
            uncovered = decision.get("uncovered_intervals") or []
            line = f"  coverage {proposition}: {decision.get('outcome')}"
            if uncovered:
                spans = ", ".join(f"{i.get('from')} .. {i.get('until')}" for i in uncovered)
                line += f"; uncovered {spans}"
            print(line)
        print()


if __name__ == "__main__":
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    main()
