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
# requests core sent to the in-tree packs and the stdout each pack wrote back,
# captured by `cargo test --test pack pack_protocol_messages` with
# DIVINATE_PACK_PROTOCOL_CAPTURE set to the directory.
PACK_PROTOCOL = "fixtures/pack-protocol"


def registry() -> Registry:
    """resolve $refs between schema files locally, with no network."""
    return Registry().with_resources(
        (
            path.split("/")[-1],
            Resource(contents=json.load(open(path)), specification=DRAFT202012),
        )
        for path in glob.glob("schema/*.json")
    )


def pack_protocol(directory: str) -> list[tuple[str, str, bool]]:
    """each request, and each response against the result of its request's operation."""
    items = []
    for request in glob.glob(f"{directory}/*.request.json"):
        operation = json.load(open(request))["operation"]
        response = request.removesuffix(".request.json") + ".response.json"
        items.append(("pack-protocol.schema.json", request, False))
        if operation == "collect":
            # every captured collection runs a configured source.
            source = "pack-protocol.schema.json#/$defs/source_collect"
            items.append((source, request, False))
        result = f"pack-response.schema.json#/$defs/{operation}"
        items.append((result, response, False))
    if not items:
        sys.exit(f"no pack protocol messages in {directory}")
    return items


def pairs(captures: list[str]) -> list[tuple[str, str, bool]]:
    """(schema reference, document path, document is a list of instances)"""
    items = [
        ("evidence-corpus", f"{STATE}/corpus.json", False),
        ("contract-registry", f"{STATE}/contracts.json", False),
        ("isms-update", f"{STATE}/views/isms-update.json", False),
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
    items = [(f"{name}.schema.json", path, is_list) for name, path, is_list in items]
    for directory in [PACK_PROTOCOL, *captures]:
        items += pack_protocol(directory)
    return sorted(items, key=lambda item: (item[0], item[1]))


def main(captures: list[str]) -> int:
    """validate the shipped artifacts, plus pack protocol captures in `captures`."""
    reg = registry()
    checked = failed = 0
    for name, path, is_list in pairs(captures):
        validator = Validator({"$ref": name}, registry=reg)
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
    sys.exit(main(sys.argv[1:]))
