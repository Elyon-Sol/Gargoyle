"""python -m gargoyle.emilia_runner: EMILIA's two covered suites produce the
rows EMILIA's harness expects, and anything else is a refusal, not a row."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from gargoyle import emilia_runner

FIX = Path(__file__).parent / "fixtures" / "emilia"


def _run(*args):
    return subprocess.run([sys.executable, "-m", "gargoyle.emilia_runner", *args], capture_output=True, text=True)


@pytest.mark.parametrize("suite,count", [("receipts.v1.json", 14), ("canonicalization.v1.json", 35)])
def test_covered_suites_emit_one_expected_row_per_vector_in_order(suite, count):
    vectors = json.loads((FIX / suite).read_text(encoding="utf-8"))["vectors"]
    proc = _run(str(FIX / suite))
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout)
    assert [r["id"] for r in rows] == [v["id"] for v in vectors] and len(rows) == count
    for row, vector in zip(rows, vectors):
        assert set(row) == {"id", "valid"} and row["valid"] == vector["expect"]["valid"], (vector["id"], vector.get("description"))


def test_an_uncovered_suite_is_refused_not_reported_false(tmp_path):
    corpus = {"vectors": [{"id": "x", "expect": {"valid": True}, "signoff": {}}]}
    path = tmp_path / "signoffs.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    proc = _run(str(path))
    assert proc.returncode == 2 and proc.stdout == "" and "EP-RECEIPT-v1" in proc.stderr


def test_the_corpus_itself_passes_the_strict_gate(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text('{"vectors": [], "vectors": [{"id": "a", "expect": {"valid": true}, "canonicalization": {}}]}', encoding="utf-8")
    assert _run(str(path)).returncode == 2
    path.write_text('{"vectors": []}', encoding="utf-8")
    assert _run(str(path)).returncode == 2
    assert _run().returncode == 2 and _run("a", "b").returncode == 2
    assert _run(str(tmp_path / "missing.json")).returncode == 2


def test_canonicalization_gate_refuses_what_emilia_refuses():
    assert emilia_runner.run_canonicalization({"input_json": '{"a":1}', "expected_digest": __import__("hashlib").sha256(b'{"a":1}').hexdigest()})
    assert not emilia_runner.run_canonicalization({"input_json": '{"a":1,"a":2}', "expected_digest": "x"})
    assert not emilia_runner.run_canonicalization({"input_json": '"\\ud800"', "expected_digest": "x"})
    assert not emilia_runner.run_canonicalization({"input_json": "[" * 65 + "]" * 65, "expected_digest": "x"})
    assert not emilia_runner.run_canonicalization({"input_json": '{"a":1.5}', "expected_digest": "x"})
    assert not emilia_runner.run_canonicalization({"input_json": "not json", "expected_digest": "x"})
    assert not emilia_runner.run_canonicalization("not a spec")
