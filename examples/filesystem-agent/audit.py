"""Audit one honored call offline: paste the receipt and execution receipt
the middleware returned (and the grant, for a flagged call) and the public
keys, and verify_chain says what happened, with no service running.

    python audit.py receipt.json execution.json [grant.json]

Reads issuer and approver public keys from middleware.env, the executor's
from the `executor public key` line setup.py printed (EXECUTOR_PUBLIC_KEY_HEX).
"""

import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gargoyle.execution import verify_chain

HERE = Path(__file__).resolve().parent


def env_file(path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    cfg = env_file(HERE / "middleware.env")
    key = lambda hexstr: Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexstr))
    receipt, execution = json.load(open(argv[1])), json.load(open(argv[2]))
    grant = json.load(open(argv[3])) if len(argv) > 3 else None
    executor_hex = os.environ.get("EXECUTOR_PUBLIC_KEY_HEX")
    if not executor_hex:
        print("set EXECUTOR_PUBLIC_KEY_HEX (printed by setup.py)", file=sys.stderr)
        return 2
    result = verify_chain(
        receipt, execution,
        issuer_public_keys={cfg["GARGOYLE_MCP_GATE_KEY_ID"]: key(cfg["GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX"])},
        executor_public_keys={execution.get("executor_key_id", ""): key(executor_hex)},
        grant=grant,
        approver_public_keys={cfg["GARGOYLE_MCP_APPROVER_KEY_ID"]: key(cfg["GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX"])},
    )
    for step, outcome in result["steps"]:
        print("%-14s %s" % (step, outcome))
    print("chain:", result["reason"])
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
