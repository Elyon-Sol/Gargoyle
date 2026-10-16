# Gargoyle

Signed, single-use, argument-bound receipts and human-approval holds for agent tool calls.

Status: pre-release, extracted from Elyon-Sol. The wire format (receipt,
signature and hash regions, verification order, replay semantics, grants,
published records, test vectors) is specified in `SPEC.md`. The design
directive and the remaining work are in `HANDOFF.md`.

    pip install -e ".[dev]"
    python -m pytest
