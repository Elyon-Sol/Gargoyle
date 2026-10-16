"""The reference policy the tests issue and check receipts under.

Gargoyle has no default manifest: a deployment names its policy. The tests
name this one, tests/fixtures/manifest.json, and derive the published record
(the live pin a remote target fetches) from its pin, so no record file is
kept in the repository."""

import json
from pathlib import Path

from gargoyle.policy import ManifestPolicy

MANIFEST_PATH = str(Path(__file__).parent / "fixtures" / "manifest.json")


def reference_policy() -> ManifestPolicy:
    return ManifestPolicy(MANIFEST_PATH)


def reference_pin() -> dict:
    return reference_policy().pin()


def reference_record_bytes() -> bytes:
    """What a publisher would serve for the reference policy: its pin as
    JSON. A target anchors on the SHA-256 of exactly these bytes."""
    return json.dumps(reference_pin(), indent=2).encode("utf-8") + b"\n"
