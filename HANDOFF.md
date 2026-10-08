# Gargoyle - design directive and handoff (2026-10-08)

Gargoyle is the stripped-down successor of Elyon-Sol (/elyon/Elyon-Sol, HEAD f73f806,
clean, 3 commits ahead of origin/main, NOT pushed). This directory is a staging copy,
not a git repository. Owner: Justin LaPorte, sole copyright holder of the source
(all commits from the owner's two accounts), so any license may be chosen.

## Positioning (decided)
"Receipts and holds for agent tool calls": a signed, single-use, argument-bound
authorization receipt for an MCP/HTTP tool call, with a human-held key required
for flagged calls. The allow/deny DECISION comes from a real policy engine (OPA,
Cedar, or the integrator's code); Gargoyle issues, verifies and consumes receipts.
NOT a governance substrate, NOT a policy language, no canon, no ledger.

## What is staged here (runs: 253 passed with the repo's .venv)
IMPLEMENTATION/: envelope, verifier, replay_cache, approval, approver_trust,
  approver_cli, pending_store, impact, mcp_server, executor_sdk, transport,
  evaluator, published_source, published_record_source, key_record_source,
  reference_target (16 modules, ~4.2k lines)
TESTS/: 23 files (~5.2k lines); TESTS/conftest.py is REWRITTEN here without the
  gate module (pep.py) - the original autouse fixture monkeypatched pep.
CANON/canon.lock, EVIDENCE/published_hashes.json, MANIFEST/manifest.json: kept
  only because envelope.reassert() and mcp_server read them by hard-coded path.
Run: PYTHONPATH=. ELYON_ALLOW_PRIVATE_TARGETS=1 /elyon/Elyon-Sol/.venv/bin/python -m pytest TESTS/ -q

## Left behind (deliberately)
pep.py (the HTTP gate), request_validator, authz_sidecar, governance_wiring,
issuance_log, envelope_inspector, publisher, root_record_source, replay/receipt.py,
CANON/*.md/pdf, STATE.md + archive, EVIDENCE/verification_ledger* + proofs,
docs/ (all), POE/, deploy/, site/, scripts/, CLAUDE.md, the GR rules.
Tests dropped: every file importing pep, authz_sidecar, publisher, root_record_source,
replay, issuance_log, envelope_inspector, governance_wiring, request_validator.

## Work remaining, in order
1. Rename: package name `gargoyle` (PyPI `gargoyle` is taken by a dead 2015 Disqus
   Django feature-flag lib; pick a distribution name such as gargoyle-receipts).
   GitHub Elyon-Sol/Gargoyle is free. Create a FRESH repo (no GitHub fork; the old
   history carries two rotated-but-exposed signing keys, VL-108/VL-146).
2. Replace evaluator.py's subset check with a decision interface:
   decide(call) -> (ELIGIBLE|REFUSE, reason) supplied by the integrator / policy
   engine. Keep ONLY the manifest/policy hash pinning so a receipt self-invalidates
   when the policy it was issued under changes. Drop AC^3/T^26/CCS vocabulary.
3. Bind caller identity: today AP/OP are caller-asserted strings and nothing at the
   gate ties them to who sent the request. The receipt must carry an authenticated
   principal (mTLS peer, bearer subject, or integrator-supplied id) and the verifier
   must check it.
4. Remove the hard-coded CANON/canon.lock and EVIDENCE/published_hashes.json paths
   from envelope.reassert() and mcp_server; pin the policy hash and the issuer key
   id only. Delete CANON/ and EVIDENCE/ from the tree once done.
5. Write the wire spec as a standalone document (envelope fields, canonical JSON
   rules, signature coverage, replay semantics, grant format) so the format is not
   defined by one Python file.
6. Collapse reference_target + executor_sdk into one "consumer" module; keep
   mcp_server as the primary integration surface.
7. Choose the license (permissive recommended for adoption), add README, pyproject.
8. Re-run the suite after each step; the 253 tests are the regression floor.

## Known weaknesses carried over (fix or document)
- Replay cache scope and restart behavior are per-store; the shared (Redis) variant
  is opt-in.
- "Currently valid" depends on knobs with non-default wiring (expiry, clock skew).
- Approver trust records are operator-controlled; separation of duties is
  organizational unless the trust record lives outside the issuer's control.
