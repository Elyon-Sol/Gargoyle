# Gargoyle - design directive and handoff (2026-10-08)

Gargoyle is the stripped-down successor of Elyon-Sol (/elyon/Elyon-Sol, HEAD f73f806,
clean, 3 commits ahead of origin/main, NOT pushed). This directory is the Gargoyle
git repository (fresh history). Owner: Justin LaPorte, sole copyright holder of the source
(all commits from the owner's two accounts), so any license may be chosen.

## Positioning (decided)
"Receipts and holds for agent tool calls": a signed, single-use, argument-bound
authorization receipt for an MCP/HTTP tool call, with a human-held key required
for flagged calls. The allow/deny DECISION comes from a real policy engine (OPA,
Cedar, or the integrator's code); Gargoyle issues, verifies and consumes receipts.
NOT a governance substrate, NOT a policy language, no canon, no ledger.

## What is staged here (runs: 253 passed with the repo's .venv)
gargoyle/ (was IMPLEMENTATION/): envelope, verifier, replay_cache, approval, approver_trust,
  approver_cli, pending_store, impact, mcp_server, executor_sdk, transport,
  evaluator, published_source, published_record_source, key_record_source,
  reference_target (16 modules, ~4.2k lines)
tests/ (was TESTS/): 23 files (~5.2k lines); tests/conftest.py is REWRITTEN here without the
  gate module (pep.py) - the original autouse fixture monkeypatched pep.
CANON/canon.lock, EVIDENCE/published_hashes.json, MANIFEST/manifest.json: kept
  only because envelope.reassert() and mcp_server read them by hard-coded path.
Run: pip install -e ".[dev]" && python -m pytest

## Left behind (deliberately)
pep.py (the HTTP gate), request_validator, authz_sidecar, governance_wiring,
issuance_log, envelope_inspector, publisher, root_record_source, replay/receipt.py,
CANON/*.md/pdf, STATE.md + archive, EVIDENCE/verification_ledger* + proofs,
docs/ (all), POE/, deploy/, site/, scripts/, CLAUDE.md, the GR rules.
Tests dropped: every file importing pep, authz_sidecar, publisher, root_record_source,
replay, issuance_log, envelope_inspector, governance_wiring, request_validator.

## Work remaining, in order
1. DONE (2026-10-08). Package `gargoyle` (dir gargoyle/, tests in tests/),
   distribution `gargoyle-receipts` (free on PyPI; `gargoyle` itself is a dead 2015
   Disqus Django lib, and its import name would collide if both were installed).
   Renamed: env vars ELYON_* -> GARGOYLE_*, header X-Elyon-Sol-Envelope ->
   X-Gargoyle-Envelope, MCP meta keys elyon-sol/* -> gargoyle/*, key-record format
   string -> gargoyle-key-record. evaluator_sha256 in EVIDENCE/published_hashes.json
   recomputed (the file's bytes changed). pyproject.toml replaces requirements*.txt;
   `pip install -e ".[dev]"` then `python -m pytest` (253 pass, no PYTHONPATH needed).
   Fresh git repo, two commits, no Elyon-Sol history. Remote: Elyon-Sol/Gargoyle,
   created PRIVATE; visibility is decided with the license at step 7.
   NOT done: docstrings still cite Elyon-Sol paths, VL entries and canon sections;
   rewrite them alongside steps 2-4, which change the code they describe.
2. DONE (2026-10-08). gargoyle/policy.py defines the interface: Decision(outcome,
   reason, requires_approval) and Policy with pin() -> {policy_id, policy_sha256}
   and decide(target_url, interaction). The old subset check survives only as
   ManifestPolicy, the reference policy (plain names: authority_covered,
   coverage_covered, manifest_pin_matches; reasons AUTHORITY_MISSING etc.).
   gargoyle/issuer.py issue() replaces the deleted gate's decide-and-sign: every
   receipt gets a decision_id and a not_after (default 300 s, no unbounded receipts);
   a policy that raises or returns junk is a refusal. Receipts pin ONE policy block
   {policy_id, policy_sha256}; the evaluator-file hash, manifest hash, per-condition
   booleans and the canon pin are gone (canon removal pulled forward from step 4).
   reassert(): bad decision_sha256 -> INVALIDATED, pin differs -> RE-EVALUATE-REQUIRED,
   else REASSERTED. Published record shape is now {policy_id, policy_sha256}.
   Receipt format version: "gargoyle/1". Suite: 249 pass.
   Open from this step: the MCP server's interaction_for() still rebuilds AP/OP from
   the manifest, so the consumer side is tied to ManifestPolicy - fix with step 3,
   which replaces AP/OP binding with tool + args + principal. requires_approval is not
   in the signed receipt, so a target cannot tell a held call from a free one.
3. Bind caller identity: today AP/OP are caller-asserted strings and nothing at the
   gate ties them to who sent the request. The receipt must carry an authenticated
   principal (mTLS peer, bearer subject, or integrator-supplied id) and the verifier
   must check it.
4. Remove the remaining hard-coded paths: the default MANIFEST/manifest.json behind
   ManifestPolicy() and envelope.live_pin(), and EVIDENCE/published_hashes.json in
   mcp_server. Then delete EVIDENCE/ (CANON/ is already gone).
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
