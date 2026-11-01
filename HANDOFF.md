# Gargoyle - design directive and handoff (2026-10-08)

> Historical record. This is the directive the repository was started from on
> 2026-10-08 and the log of the first eight days against it. Paths, counts and
> "not pushed" notes describe that moment, not the repository today; for the
> current state read README.md and ROADMAP.md.

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
docs/ (all), POE/, deploy/, scripts/, CLAUDE.md, the GR rules.
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
5. DONE (2026-10-16). SPEC.md at the repo root: terms, encodings (canonical JSON,
   SHA-256 hex, Ed25519 hex signatures, raw keys hex/base64, offset-bearing timestamps),
   the receipt field table with hashed/signed columns, the decision_sha256 and
   issuer-signature regions, the ordered verification procedure with every refusal
   code, replay semantics (decision_id single use, retention to not_after + skew,
   store scope), the grant format and its ordered checks, the anchored and signed
   published records, the key record, deterministic test vectors (seed =
   sha256(label)), transport (HTTP header, MCP _meta, 403 body) and versioning.
   tests/fixtures/wire_vectors.json holds the complete vector objects and
   tests/test_wire_spec.py recomputes them from the seeds, verifies them with the
   reference implementation, checks the excluded-key sets and region bytes, asserts
   SPEC.md quotes every vector verbatim, and asserts every REF_* code the package
   defines is named in SPEC.md. The spec is written as authoritative: where it and the
   code disagree, the code is the bug. Suite: 298 pass.
6. DONE (2026-10-16). gargoyle/consumer.py replaces executor_sdk.py and
   reference_target.py (both deleted). Consumer (was ExecutorGate) is the one check
   every executor runs: exactly one pin source (record dict, anchored record_bytes, or
   record_source(last_seen_serial) -> {"record","reason"}), issuer-key trust
   (pinned_public_keys, key_record_view, or key_record_source(last_seen_serial) ->
   {"trust_view","reason","serial"}; no trust at all is a ValueError), replay cache,
   clock skew, and a HighWater holding the highest record / key-record serial seen so
   a rolled-back record is refused; sources are called on every check, a source
   that raises or returns nothing refuses with its reason and never falls back to a
   static value. Verdict(honored, reason) replaces executor_sdk.Decision (the name
   clash with policy.Decision is gone). The reference target lives in the same
   module (build_reference_target_app, config_from_env, principal_from_header, the
   module-level `app`; run `uvicorn gargoyle.consumer:app`): per request it resolves
   config, authenticates the caller, reads body and header, then builds a Consumer
   from the config with the injected fetchers wrapped as sources and the app-shared
   replay cache and HighWater, and runs it on the thread pool. mcp_server builds one
   Consumer in ServerState from its config (anchored record bytes, pinned key) and
   gate_tool_call delegates to it; the duplicated verify/claim sequence is gone and
   mcp_server stays the primary integration surface. REF_TARGET_* codes and
   ENVELOPE_HEADER now live in consumer.py. tests/test_consumer.py added (construction
   rules, honor/replay, decision_id, skew retention, anchored bytes, record-source
   serial threading and rollback, key-record-source precedence and fail-closed, shared
   state across consumers); the reference-target, MCP and principal tests repointed.
   Suite: 316 pass.
7. DONE (2026-10-16). License: Apache-2.0 (permissive, with the patent grant; the
   owner's choice of "permissive", Apache over MIT for the patent clause). LICENSE is
   the canonical text (sha256 cfc7749b...3d30) plus a NOTICE naming the owner;
   pyproject: license = "Apache-2.0", license-files LICENSE + NOTICE, classifiers,
   keywords, project URLs (repo, SPEC.md, issues); a wheel builds and carries both
   license files and License-Expression: Apache-2.0. README rewritten: what a receipt
   gives (binding, principal, single use, expiry, currency, holds), install, issuing,
   checking with Consumer, the two shipped consumers and their env, approval holds,
   the module table, what Gargoyle does not do, license. The MCP server stays the
   primary integration surface. Visibility: PUBLIC since 2026-10-16, after a scan of
   every blob in every ref (221 blobs, 10 commits) found no private keys, tokens,
   credentials or sensitive files; the only long hex literals are the spec's public
   test-vector values and SHA-256 file hashes in historical evidence blobs.
   Suite: 316 pass.
8. Re-run the suite after each step; the suite at the last DONE step is the
   regression floor (316 at step 7). All eight steps are done;
   what remains is the list below.

## Known weaknesses carried over: resolved (2026-10-16)
- requires_approval is now inside the receipt (hashed and signed) with a signed
  approval_request_id; the consumer refuses a flagged receipt without a grant that a
  trusted approver signed for that decision and hold, claims the grant single-use,
  and only then claims the receipt. The human-held key is required at execution.
- verify_envelope() has no unsigned path: without pinned keys or a key-record view it
  raises; an empty map trusts nobody. Every test runs on the signed path.
- Test names carry no Elyon-Sol labels.
- executor_sdk.Decision is gone (step 6).

## Limits by design (documented in SPEC.md and README.md, not defects)
- Replay-cache and pending-set scope are the scope of the guarantee: per process
  unless a shared store is configured; a multi-instance deployment must share one.
- "Currently valid" depends on expiry and clock skew as configured; skew widens
  every time check symmetrically and must be non-negative.
- Approver trust is as good as its source: a key record the issuer's operator
  controls makes separation of duties organizational. Publish approver roles from a
  root the issuer cannot reach.
- Gargoyle compares principals; it authenticates nobody. The XFCC and header
  sources are only as trustworthy as the proxy that sets and sanitizes them.
- A caller that never asks for a receipt is stopped only by a target that refuses
  unattested calls.

## The 2026-10-08 paragraph, clause by clause (2026-10-16)
"Drop the canon, the ledger apparatus and the superscripted vocabulary." Done at
staging and steps 1-4; nothing of them remains in the repo.
"Keep the envelope, verifier, replay cache and approval-grant flow" Kept, in
gargoyle/{envelope,verifier,replay_cache,approval,approver_trust,approver_cli,
pending_store}.py.
"as a small MCP middleware" gargoyle/mcp_server.py fronts any stdio MCP server
(`python -m gargoyle.mcp_server -- <upstream command>`): initialize, tools/list and
everything else relayed; tools/call forwarded only once a receipt (and grant) is
honored, with Gargoyle's _meta stripped; refusals answered locally. The demo
executor remains the no-upstream mode. "small": the package is ~3.8k lines, not a few
hundred; that estimate was wrong and is the one clause not met.
"a signed, single-use, argument-bound receipt for a tool call" The receipt binds
tool, args_sha256, principal and target, carries a signed decision_id and
not_after, and is claimed once (SPEC.md sections 3-7).
"with a human-held key required for flagged calls" The flag is signed into the
receipt and the consumer demands the approver's grant at execution (SPEC.md 8.1);
gargoyle-approver signs it from the receipt on a machine the issuer cannot reach.
"where the actual allow or deny decision comes from a real policy engine"
gargoyle/opa.py: OpaPolicy asks OPA's data API and pins the exact module set OPA
holds, so a policy edit invalidates outstanding receipts; the Policy protocol
takes any other engine. ManifestPolicy is a test fixture.
"and the caller is authenticated by the transport" The reference target's default
principal source is the client certificate the TLS-terminating proxy verified
(Envoy's X-Forwarded-Client-Cert: URI SAN, else Subject); a proxy-set identity
header is the explicit alternative; an injected resolver covers anything else. The
MCP server's principal is the one process that spawned it, configured out of band.
"Position it as receipts and holds for agent tool calls, not as a governance
substrate." README, pyproject description, SPEC.md section 1.
"a few hundred lines and a weekend of positioning" Not met (see above).
"the first version of this project that answers a question somebody is asking"
Open. Nothing outside has used it; the repo is public so that can now happen.
Suite: 358 pass.

## After the directive (2026-10-16)
Further work is tracked in ROADMAP.md. Step 1 (execution receipts and the
offline chain) is done; the suite count of record moves there.
