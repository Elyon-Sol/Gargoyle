"""The TypeScript implementation (ts/) must agree with this one byte for
byte. Its own suite recomputes the conformance vectors; this test runs it
when Node and its dependencies are present, and is skipped otherwise (CI
runs both unconditionally)."""

import shutil
import subprocess
from pathlib import Path

import pytest

TS = Path(__file__).resolve().parent.parent / "ts"


@pytest.mark.skipif(shutil.which("npm") is None or not (TS / "node_modules").exists(),
                    reason="Node toolchain or ts/node_modules not available")
def test_typescript_suite_passes_against_the_vectors():
    proc = subprocess.run(["npm", "test", "--silent"], cwd=str(TS), capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
    assert "# fail 0" in proc.stdout, proc.stdout[-2000:]
