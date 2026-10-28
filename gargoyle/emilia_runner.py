"""EMILIA conformance runner for Gargoyle's verifier.

    python -m gargoyle.emilia_runner VECTORS.json

Reads one EMILIA conformance suite file (conformance/vectors/*.json in
https://github.com/emiliaprotocol/emilia-protocol) and prints the result rows
EMILIA's cross-language harness compares, one per vector, in the order the
file lists them: ``[{"id": ..., "valid": true|false}, ...]``.

Two suites are covered, because they are the two Gargoyle implements:

* EP-RECEIPT-v1 (receipts.v1.json): each vector's ``document`` is verified
  under its ``public_key`` by gargoyle.emilia.verify_ep_receipt, which is
  Gargoyle's own code on Gargoyle's RFC 8785 serializer, not a re-run of an
  EMILIA package.
* EP-CANONICALIZATION-v1 (canonicalization.v1.json): the raw ``input_json`` is
  parsed under EMILIA's strict input gate (duplicate member names, unpaired
  surrogates and nesting deeper than 64 are refused, then the I-JSON signing
  profile), and SHA-256 over Gargoyle's canonical bytes must equal the pinned
  ``expected_digest``.

Any other suite, or a vector this runner does not recognise, is a refusal of
the whole run (exit status 2), never a row that says ``false``: a missing
capability must not look like a verdict.

The suite file itself is parsed under the same strict gate EMILIA's runners
apply to the corpus, so a corpus that smuggles a duplicate name or a lone
surrogate past a permissive parser is refused before any vector runs.
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any, Dict, List

from gargoyle.emilia import in_profile, verify_ep_receipt
from gargoyle.envelope import canonical_json

MAX_DEPTH = 64


def _refuse_duplicates(pairs: List[Any]) -> Dict[str, Any]:
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError("duplicate object member name")
        seen.add(key)
    return dict(pairs)


def _has_lone_surrogate(value: Any) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return any(_has_lone_surrogate(k) or _has_lone_surrogate(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_lone_surrogate(v) for v in value)
    return False


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max([_depth(v) for v in value.values()] + [0])
    if isinstance(value, list):
        return 1 + max([_depth(v) for v in value] + [0])
    return 0


def strict_parse(text: str) -> Any:
    """EMILIA's corpus and canonicalization input gate: standard JSON parse,
    then duplicate names, unpaired surrogates and depth over 64 are refused."""
    value = json.loads(text, object_pairs_hook=_refuse_duplicates)
    if _has_lone_surrogate(value) or _depth(value) > MAX_DEPTH:
        raise ValueError("input refused by the EP input profile")
    return value


def run_canonicalization(spec: Any) -> bool:
    """One EP-CANONICALIZATION-v1 vector: True only when the raw input passes
    the gate and the I-JSON profile, and Gargoyle's canonical bytes hash to
    the pinned digest."""
    if not isinstance(spec, dict) or not isinstance(spec.get("input_json"), str):
        return False
    try:
        value = strict_parse(spec["input_json"])
    except (ValueError, RecursionError):
        return False
    if not in_profile(value):
        return False
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return digest == spec.get("expected_digest")


def run_vector(vector: Dict[str, Any]) -> Dict[str, Any]:
    """The typed result row for one vector of a covered suite; raises
    ValueError for a vector of any other shape."""
    if "document" in vector:
        try:
            return {"valid": bool(verify_ep_receipt(vector["document"], vector.get("public_key"))["valid"])}
        except Exception:  # the verifier never raises; this is the last guard
            return {"valid": False}
    if "canonicalization" in vector:
        return {"valid": run_canonicalization(vector["canonicalization"])}
    raise ValueError("vector %r is not an EP-RECEIPT-v1 or EP-CANONICALIZATION-v1 case" % vector.get("id"))


def run_file(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        corpus = strict_parse(handle.read())
    vectors = corpus.get("vectors") if isinstance(corpus, dict) else None
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("conformance corpus must contain a non-empty vectors array")
    rows = []
    for vector in vectors:
        if not isinstance(vector, dict) or not isinstance(vector.get("id"), str) or not vector["id"]:
            raise ValueError("malformed vector")
        rows.append({"id": vector["id"], **run_vector(vector)})
    return rows


def main(argv: List[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m gargoyle.emilia_runner VECTORS.json", file=sys.stderr)
        return 2
    try:
        rows = run_file(argv[0])
    except (OSError, ValueError, RecursionError) as exc:
        print("gargoyle.emilia_runner: refused: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
