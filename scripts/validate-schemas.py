#!/usr/bin/env python3
"""validate every shipped artifact against the schema that documents it.

schema/ is part of the product: it is what another implementation reads to
understand the formats. this fails when an artifact and its schema drift apart,
which is otherwise invisible because the tool reads its own files through serde
and never consults the schemas.
"""

import glob
import json
import sys

from jsonschema import Draft202012Validator as Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

STATE = "dossiers/sbom-diff/repeated/.evidence"


def registry() -> Registry:
    """resolve $refs between schema files locally, with no network."""
    return Registry().with_resources(
        (
            path.split("/")[-1],
            Resource(contents=json.load(open(path)), specification=DRAFT202012),
        )
        for path in glob.glob("schema/*.json")
    )


def pairs() -> list[tuple[str, str, bool]]:
    """(schema name, document path, document is a list of instances)"""
    items = [
        ("evidence-corpus", f"{STATE}/corpus.json", False),
        ("legacy-project-config", f"{STATE}/config.json", False),
        ("contract-registry", f"{STATE}/contracts.json", False),
        ("isms-update", f"{STATE}/views/isms-update.json", False),
        ("dd-response", f"{STATE}/views/dd-response.json", False),
    ]
    items += [("dossier", p, False) for p in glob.glob(f"{STATE}/dossiers/*.json")]
    items += [
        ("acquisition-transcript", p, False)
        for p in glob.glob(f"{STATE}/acquisitions/*.json")
    ]
    items += [
        ("execution-transcript", p, False) for p in glob.glob(f"{STATE}/executions/*.json")
    ]
    items += [
        ("pack-invocation", p, False)
        for p in glob.glob(f"{STATE}/pack-invocations/*.json")
    ]
    items += [
        ("derived-assertion", p, True)
        for p in glob.glob(f"{STATE}/assertions/*.json")
        if not p.endswith((".contracts.json", ".configuration.json"))
    ]
    items += [
        ("evaluation-configuration", p, False)
        for p in glob.glob(f"{STATE}/assertions/*.configuration.json")
    ]
    items += [
        ("collection-cycle", p, False)
        for p in glob.glob(f"{STATE}/collection-cycles/*.json")
    ]
    return sorted(items, key=lambda item: (item[0], item[1]))


def main() -> int:
    reg = registry()
    checked = failed = 0
    for name, path, is_list in pairs():
        schema = json.load(open(f"schema/{name}.schema.json"))
        validator = Validator(schema, registry=reg)
        document = json.load(open(path))
        instances = document if is_list else [document]
        errors = [error for one in instances for error in validator.iter_errors(one)]
        checked += 1
        if errors:
            failed += 1
            print(f"FAIL {name}: {path}")
            for error in errors[:5]:
                where = "/".join(map(str, error.path)) or "(root)"
                print(f"       {where}: {error.message}")
    print(f"\n{checked} artifact(s) checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
