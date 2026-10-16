"""The reference policy the tests issue and check receipts under.

Gargoyle has no default policy: a deployment names its rules file. The
tests name tests/fixtures/rules.json (every tool allowed, nothing held) and
derive the published record a remote target would fetch from its pin, so no
record file is kept in the repository."""

import json
from pathlib import Path

from gargoyle.rules import RulesPolicy

RULES_PATH = str(Path(__file__).parent / "fixtures" / "rules.json")


def reference_policy() -> RulesPolicy:
    return RulesPolicy(RULES_PATH)


def reference_pin() -> dict:
    return reference_policy().pin()


def reference_record_bytes() -> bytes:
    """What a publisher would serve for the reference policy: its pin as JSON."""
    return json.dumps(reference_pin(), indent=2).encode("utf-8") + b"\n"
