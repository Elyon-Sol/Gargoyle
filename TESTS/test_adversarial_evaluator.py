import pytest

from IMPLEMENTATION.evaluator import evaluate, load_manifest, manifest_sha256


SHA = manifest_sha256()

CASES = [
    {"name": "ap_missing_key", "ctx": {"OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "op_missing_key", "ctx": {"AP": ["identity", "role"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_null", "ctx": {"AP": None, "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_wrong_type_string", "ctx": {"AP": "identity,role", "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_wrong_type_int", "ctx": {"AP": 42, "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_wrong_type_dict", "ctx": {"AP": {"identity": True, "role": True}, "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_nested_unhashable", "ctx": {"AP": [["identity"], ["role"]], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "op_wrong_type_string", "ctx": {"AP": ["identity", "role"], "OP": "session,request", "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_empty_set", "ctx": {"AP": [], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "op_empty_set", "ctx": {"AP": ["identity", "role"], "OP": [], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_partial_authority", "ctx": {"AP": ["role"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "op_partial_coverage", "ctx": {"AP": ["identity", "role"], "OP": ["session"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_lookalike_unicode", "ctx": {"AP": ["identity", "rol\u0435"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_case_mismatch", "ctx": {"AP": ["Identity", "Role"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_whitespace_padding", "ctx": {"AP": ["identity ", " role"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_duplicate_collapse", "ctx": {"AP": ["identity", "identity", "identity"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "ap_superset_extra_authority", "ctx": {"AP": ["identity", "role", "admin", "root"], "OP": ["session", "request", "extra"], "expected_manifest_version": "1.0", "expected_manifest_sha256": SHA}, "expected": "ELIGIBLE"},
    {"name": "manifest_sha256_missing", "ctx": {"AP": ["identity", "role"], "OP": ["session", "request"], "expected_manifest_version": "1.0"}, "expected": "REFUSE"},
    {"name": "manifest_version_drift", "ctx": {"AP": ["identity", "role"], "OP": ["session", "request"], "expected_manifest_version": "2.0", "expected_manifest_sha256": SHA}, "expected": "REFUSE"},
    {"name": "manifest_version_missing_in_ctx", "ctx": {"AP": ["identity", "role"], "OP": ["session", "request"]}, "expected": "REFUSE"},
    {"name": "manifest_version_type_mismatch", "ctx": {"AP": ["identity", "role"], "OP": ["session", "request"], "expected_manifest_version": 1.0}, "expected": "REFUSE"},
    {"name": "manifest_version_whitespace", "ctx": {"AP": ["identity", "role"], "OP": ["session", "request"], "expected_manifest_version": "1.0 "}, "expected": "REFUSE"},
    {"name": "empty_context", "ctx": {}, "expected": "REFUSE"},
]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_adversarial_evaluator_cases(case):
    manifest = load_manifest()

    try:
        result = evaluate(case["ctx"], manifest)
    except Exception:
        result = "REFUSE"

    assert result == case["expected"]
