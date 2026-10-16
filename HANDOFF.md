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
  only because envelope.reassert() and mcp_server read them by hard-coded path
  (all three gone by step 4).
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
   Follow-up (same day): docstrings/comments rewritten without Elyon-Sol provenance
   (comment-only, guarded by /elyon/gargoyle-tools/docguard.py); brand strings in code
   renamed (record format gargoyle-published-record, Redis prefixes gargoyle:*); the MCP
   server now refuses a receipt without decision_id (it was executable and replayable).
   Suite: 251 pass.
   Open from this step: the MCP server's interaction_for() still rebuilds AP/OP from
   the manifest, so the consumer side is tied to ManifestPolicy - fixed at step 3.
   requires_approval is not in the signed receipt, so a target cannot tell a held
   call from a free one - STILL OPEN (see below).
3. DONE (2026-10-16). The receipt binds what a target can observe and nothing else:
   request_context is now {tool, args_sha256, principal}. `tool` is the operation
   name, `args_sha256` is SHA-256 over canonical_json(args) (so key order never
   matters and the receipt stays small), `principal` is the authenticated identity
   of the caller: the issuer records the one it authenticated (mTLS peer, bearer
   subject, integrator-supplied id; build_envelope refuses an empty or non-string
   one, issue() turns that into ISSUE_UNBINDABLE_CALL), and the verifier compares it
   with the identity the TARGET authenticated for the presenting party. The live call
   verify_envelope() takes is exactly {tool, args, principal}; a mismatch on the
   principal, or an unauthenticated caller (None/""/non-string on either side), is
   REF_VERIFY_PRINCIPAL_MISMATCH, checked before tool/args ("who" before "what").
   Gone from the receipt: AP, OP, context, expected_manifest_*, interaction_type.
   They remain policy INPUTS: issue() still passes the whole interaction mapping to
   policy.decide(), so ManifestPolicy keeps reading its claims from it; the receipt
   records only the call and the policy pin. Consumers: the MCP server's
   interaction_for() is replaced by call_for(tool, args, principal) with the
   principal from GARGOYLE_MCP_PRINCIPAL (a stdio server has one client, the process
   that spawned it, and that identity is established by whoever wired it up; no
   principal -> unconfigured, every call refused); the manifest coupling is gone from
   mcp_server. The reference target authenticates the caller itself: an injectable
   principal_resolver(request, config) (for an mTLS peer or a token subject), else
   the single value of the header named by GARGOYLE_PRINCIPAL_HEADER, which a trusted
   front proxy must set and must strip from client input; absent/empty/duplicated
   header or no source at all -> REF_TARGET_NO_PRINCIPAL before anything else. The
   body is exactly {"tool", "args"}; a principal (or anything else) in the body is
   unbound data and refused. ExecutorGate.check(envelope, call) is unchanged in
   shape. Tests: tests/adversarial/test_fix_interaction_type_binding.py deleted
   (interaction_type is no longer a receipt field); tests/adversarial/
   test_principal_binding.py added; the other fixtures rewritten to the new call
   shape. Suite: 288 pass (the floor from here).
   Known limits, by design: the principal is only as good as the issuer's and the
   target's own authentication; Gargoyle compares, it does not authenticate. A
   deployment where the principal header is reachable by the client has no
   principal binding at all.
4. DONE (2026-10-16). No path is read that a deployer did not name. ManifestPolicy(path),
   load_manifest(path) and manifest_sha256(path) require the path (an empty one is a
   ValueError); policy.evaluate() requires a policy. envelope.live_pin() and reassert()
   take a record_source or a policy and raise ValueError with neither; verify_envelope()
   gained a `policy=` keyword for a target that holds the policy in-process and raises
   ValueError when given neither that nor a record_source (a verifier with no live pin
   is misconfigured, and that must not look like a verdict either way). mcp_server:
   GARGOYLE_MCP_RECORD_PATH is required, no default record file. reference_target: in
   signed-record mode GARGOYLE_SIGNED_RECORD_URL is required instead of being guessed
   from the publisher URL. MANIFEST/manifest.json moved to tests/fixtures/manifest.json;
   EVIDENCE/ deleted; the repo root now holds only gargoyle/, tests/, pyproject.toml,
   README.md, LICENSE, HANDOFF.md. tests/reference.py supplies the tests' reference
   policy (reference_policy(), reference_pin()) and the record bytes a publisher would
   serve for it (reference_record_bytes()), so no published record is committed.
   Suite: 293 pass.
5. Write the wire spec as a standalone document (envelope fields, canonical JSON
   rules, signature coverage, replay semantics, grant format) so the format is not
   defined by one Python file.
6. Collapse reference_target + executor_sdk into one "consumer" module; keep
   mcp_server as the primary integration surface.
7. Choose the license (permissive recommended for adoption), add README, pyproject.
8. Re-run the suite after each step; the suite at the last DONE step is the
   regression floor (293 at step 4).

## Known weaknesses carried over (fix or document)
- requires_approval is not in the signed receipt, so a target cannot tell a held
  call from a free one; it trusts the issuer to hold. Carried from step 2.
- verify_envelope() with no trusted keys (no pinned_public_keys, no key-record view)
  accepts any receipt whose decision_sha256 verifies, and anyone can compute that
  hash. Only the signed path authenticates the issuer. Consider making trusted keys
  mandatory (refuse when none are configured) - a code change, not yet made.
- Test names still carry old labels (_a1/_a2/_a3, _p01, _REVERT_CATCHER,
  test_three_model_forge_refused_on_signed_path); docstrings are clean. Rename freely.
- executor_sdk.Decision (honored, reason) shares its name with policy.Decision.
- Replay cache scope and restart behavior are per-store; the shared (Redis) variant
  is opt-in.
- "Currently valid" depends on knobs with non-default wiring (expiry, clock skew).
- Approver trust records are operator-controlled; separation of duties is
  organizational unless the trust record lives outside the issuer's control.
