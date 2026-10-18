# Gargoyle roadmap (2026-10-16)

Where this comes from: a comparison of Gargoyle against the products and
drafts that overlap it most (ActionProxy, Vestige, the MCP "work contract"
discussion #3215, OAuth Transaction Tokens and its agent drafts, the MCP
gateways with Cedar/OPA policy, HumanLayer). Scored on Gargoyle's own 17
properties the nearest is ActionProxy at about 62%; scored the other way,
five things beat Gargoyle: execution receipts, an audit log, standards
alignment, approval UX, and a second-language implementation. Two things
nobody else has: a receipt that dies when the policy it was decided under
changes, and a human approval that is a separately keyed signature verified
at execution rather than a button in an orchestrator.

The goal is not more functionality. It is depth on three properties: the
policy pin, the keyed grant, and (new) the execution chain. The sentence to
earn: one signed artifact proves that a specific policy version authorized a
specific call for a specific principal, that a human's key released it, and
that exactly that call ran once, verifiable offline, by anyone, in two
languages.

## Steps, in order

1. **Execution receipts.** After the side effect, the executor signs
   {decision_id, decision_sha256, policy pin, target, request_context,
   outputs_sha256, executed_at}. Verifiable offline against the
   authorization receipt (and grant), so authorization and execution chain to
   one decision_id and the pin inside says which policy version allowed what
   actually ran. Closes the gap to #3215 and Vestige and deepens the pin.
   Spec section and vectors.
2. **TypeScript verifier and consumer**, validated against the conformance
   vectors. Most MCP servers are TypeScript; this is the adoption lever and
   the test of whether SPEC.md is complete.
3. **JWS encoding and delegation fields**, together (one format bump).
   Receipts as JWS/EdDSA so any JWT library verifies them; principal plus
   on_behalf_of, mirroring the actor/principal fields of the Transaction
   Tokens for Agents draft; a transaction token or bearer subject accepted as
   the issuer-side principal source. Encoding and inputs only, not OAuth
   semantics.

**Stop here and look outward.** If after steps 1-3 nobody has opened an
issue, run the vectors, or wired the middleware into a server, the next
work is positioning and outreach, not step 4. Elyon-Sol spent a year
verifying itself for no external user; that is the failure mode to avoid.

4. **m-of-n grants.** A flagged receipt names a threshold; the consumer
   requires that many distinct approver keys. (DONE, see Status.)
5. **Evidence log.** An append-only hash chain of receipts, verdicts and
   execution receipts, exportable and checkable offline. A log, a few
   hundred lines; never rules about how it may be amended.
6. **Approval transport.** A webhook that posts the flagged receipt to
   Slack or an approval product, the key staying on the approver's device.
   Integrate, do not build. (The browser console below covers the "a button,
   not a terminal" half of this without a third party.) (DONE, see Status.)

## Not on the roadmap

- Rebuilding a canon, a ledger apparatus or governance rules.
- Becoming a policy engine or a gateway; both markets are crowded and
  gateways already own breadth.

## Status

- Step 1: DONE (2026-10-16). gargoyle/execution.py (build, sign, verify,
  verify_chain), Consumer.attest, the HTTP target's `execution` field and the
  MCP `_meta["gargoyle/execution"]`, SPEC.md section 13, executor vector in
  tests/fixtures/wire_vectors.json, verifier.verify_provenance factored out
  for offline use.
- Step 2: DONE (2026-10-16). ts/: canonical JSON (byte-compatible with the
  reference serializer, including ensure_ascii escaping), Ed25519 over Node's
  crypto, receipt build/sign, verifyProvenance, verifyEnvelope, grants,
  execution receipts, verifyChain, Consumer with single-use claims and attest.
  ts/test recomputes every conformance vector from the seed labels and
  compares byte for byte; tests/test_typescript_conformance.py runs that suite
  from pytest when Node is present; .github/workflows/ci.yml runs both suites.
  Not ported yet: the published-record and key-record readers (SPEC.md 9-10).
  The spec proved complete enough to implement from, with one addition worth
  making at step 3: a note on float formatting differences between producers.
- Step 3: DONE (2026-10-16). Format bumped to gargoyle/2 (verifiers refuse other
  versions: REF_VERIFY_VERSION_UNSUPPORTED). request_context.on_behalf_of, optional,
  hashed and signed, bound when the target knows the delegation. gargoyle/jws.py:
  compact JWS/EdDSA with the signed receipt under "gargoyle" and iss/jti/aud/exp/iat
  mirroring it; decode_receipt refuses alg != EdDSA, unknown kid, bad signature,
  expiry, audience, and claims that disagree with the receipt. gargoyle/identity.py:
  principal_from_token maps act.sub / sub (RFC 8693), agentic_ctx.actor /
  .principal (Transaction Tokens for Agents), or sub alone, into principal and
  on_behalf_of. Vectors regenerated (delegated, flagged receipt; JWS form); the
  TypeScript port recomputes the JWS byte for byte. SPEC.md: sections 1, 2 (float
  note), 3, 6, 11, 12 and new 14.

- Step 6: DONE (2026-10-18). gargoyle/notify.py: GARGOYLE_HOLD_WEBHOOK_URL posts a
  notice of every new hold (Slack incoming-webhook shape: `text` plus the structured
  hold and the receipt, with a link to /approve from GARGOYLE_APPROVE_URL); posted in
  a thread, failures logged and ignored, the grant still only from the approver's
  key. 80 lines. All six roadmap steps are done.
- Entra client login live (2026-10-18, later): Claude Desktop on Windows through
  `gargoyle login` against the real tenant (two app registrations, docs/entra-setup.md).
  The hold on the issuer, the receipt and the audit rows all name
  the workstation account (a real tenant user); the approved write chain-verified. Found and fixed on the way:
  MSAL inherited the REQUESTS_CA_BUNDLE that pins the issuer's private CA (per-request
  public-roots override, 0.5.2), and a format bump had orphaned the gargoyle/2 audit rows
  (historical verification, 0.5.3: the same 14-row log went from 8 failed to 0 failed
  with no rewrite). Open: approver login with Entra.
- Entra client login (2026-10-18): gargoyle/entra_login.py and `gargoyle login`.
  Device-code sign-in through MSAL (optional extra `entra`), token cache in a private
  file, EntraTokenSource refreshing silently before each issuer call; middleware.env and
  mcp-config.json switch from the init token to the user's token and the principal
  becomes their UPN. `gargoyle init --entra-tenant/--entra-audience`; the issuer trusts
  the tenant's keys and the pinned init key together, so approvers keep working. No
  usable token is REF_TARGET_LOGIN_REQUIRED. Tested with a faked MSAL; a live run needs
  the tenant's two app registrations (guide 4.6). Next: approver login with Entra and
  approver key ids as UPNs.
- Published (2026-10-18): gargoyle-receipts 0.4.0.dev0 on PyPI by trusted publishing
  (.github/workflows/publish.yml, runs on a GitHub release or by hand). Dependencies are
  floors, not pins. A clean venv installs and imports it; `pip install gargoyle-receipts`
  is the install line everywhere now.
- Standards (2026-10-18): canonical JSON moved to RFC 8785 (JCS), format gargoyle/3,
  after finding three 2026 Internet-Drafts in the same space that all use JCS: Acta
  signed receipts (MCP access decisions), EP authorization receipts (human pre-execution
  signoff, m-of-n, WebAuthn, Merkle log) and XAIP receipts (signed execution records).
  Python implements JCS itself (ECMAScript number formatting included, RFC examples as
  tests); TypeScript and the console emit members by hand because JSON.stringify moves
  integer-like keys first. Vectors regenerated; SPEC section 16 maps every field to the
  three drafts and states what the chain here adds (one decision id across decision,
  release and execution, with the policy version inside) and what they have that
  Gargoyle layers rather than defines (WebAuthn keys, transparency log, DIDs).
- Step 4: DONE (2026-10-18). A hold's terms live in the receipt: optional `approval`
  member {required, approvers}, hashed and signed, so a caller cannot lower the
  threshold or swap in a different approver set. Decision gained approvals_required
  and approvers; rules say `"approvals": 2, "approvers": [...]` on a hold and OPA
  results may carry approvals_required / approvers. approval.verify_grants judges a
  grant set (distinct approvers, eligibility, count; REF_APPROVAL_INSUFFICIENT,
  _DUPLICATE_APPROVER, _APPROVER_NOT_ELIGIBLE); Consumer.check and verify_chain take
  one grant or a list and claim every grant id. The issuing service collects grants
  per hold and releases the set when complete; /pending shows progress; the browser
  console shows "1 of 2 approvals", disables the button for a key that already
  signed or is not eligible, and the approver CLI prints how many more are needed.
  Middleware waits for the whole set. `gargoyle init --approvers N` writes N approver
  keys (comma-separated lists in both env files, approver-2.env, approver-web-2.json).
  SPEC.md sections 3, 8.0, 8.1, 8.2 and 11.1 (threshold vector, two grants); the
  TypeScript port verifies it byte for byte (verifyGrants). Roles beyond a key-id
  list are deliberately not in the receipt: a key record maps ids to people.
- Step 5: DONE (2026-10-18). gargoyle/evidence.py: the middleware's audit log
  became an evidence log, `gargoyle-evidence/1`, one hash-chained entry per decision
  with kind honored or refused, the verdict, and the receipt, grant and execution
  receipt where they exist (a declined or lapsed hold keeps its flagged receipt).
  verify_log checks hashes, links, every honored chain and the refused receipts'
  provenance offline and reports per entry plus the tail hash; `gargoyle audit
  --log` prints it. Stated limit: truncation at the tail is caught only by comparing
  tail hashes between audits. 229 lines; nothing about amending it. Step 4 (m-of-n)
  and 6 (transport) remain.

**Gate reached.** Steps 1-3 are done. The next work is outreach and measurement,
not step 4: publish the Python and npm packages, post the spec and vectors where
the MCP discussion (#3215) and the OAuth agent-token drafts are being read, and
wire the middleware into one real MCP server. Steps 4-6 wait for a signal from
outside.

- Deployable example (2026-10-16): examples/filesystem-agent. To make an
  unmodified MCP client usable, the middleware gained self-issue mode
  (GARGOYLE_MCP_ISSUER_URL + client token: obtain the receipt, wait for the
  grant) and gargoyle/issuer_service.py became the HTTP issuing service
  (/issue, /pending, /grants, /record, /keys, OPA-backed); gargoyle-approver
  gained --issuer to fetch holds and post grants. The verification model did
  not change: the middleware still pins the issuer's and approver's keys.
- No-engine path (2026-10-16): gargoyle/rules.py (RulesPolicy from a JSON file;
  first match wins; globs on tool, principal, on_behalf_of and string args; pin =
  file hash) and gargoyle/cli.py (`gargoyle init | issuer | approve | audit`). Holds
  now carry the full arguments so the reviewer reads what they release, shown only
  when they hash to the receipt. Verified end to end against the real filesystem
  MCP server with no OPA and no containers. This is the shape a small IT practice
  can run for a client: one rules file, one issuer process, one approver terminal.
- Pruning pass (2026-10-16), before anyone outside reads the repo: the manifest
  policy and impact module (a test fixture by then) removed in favour of the rules
  file; the byte-anchored record mode and the transport module removed, leaving
  the file pin and the signed record; the HTTP reference target and its
  principal resolvers removed, leaving the MCP middleware as the one shipped
  consumer. 23 modules / 5,250 lines became 20 / 4,300; 50 environment variables became 33; six configuration
  choices became three. Nothing the spec guarantees changed.
- Browser approval console (2026-10-16): gargoyle/static/approve.{html,js},
  served by the issuer at /approve. The page lists holds with their full
  arguments, re-hashes them against the receipt, and signs the grant in the
  browser with WebCrypto Ed25519 from approver-web.json (written by init); the key
  never reaches the issuer. POST /decline drops a hold and the middleware answers
  REF_TARGET_APPROVAL_DECLINED at once. GARGOYLE_MCP_AUDIT_LOG writes every honored
  chain as a JSON line; `gargoyle audit --log` verifies the file. init gained
  --issuer-url, --client-python and --client-config-dir so a Linux issuer host can
  write config for a Windows client. tests/test_console_js.py proves the page's
  JavaScript signs byte for byte what the reference signs.
  docs/guide-hyperv-ubuntu-apache.md is the single-instance build guide.
  Added for the PoC: gargoyle/fs_server.py (a Python filesystem MCP server, so a
  Windows client needs only Python; `init --upstream python-fs`) and
  `gargoyle issuer --ssl-certfile/--ssl-keyfile` to serve TLS without a proxy.
- First cross-machine PoC (2026-10-18): Windows 11 host running Claude Code
  (Microsoft Store Python 3.13), this VirtualBox Ubuntu VM as the issuer with TLS on
  its host-only address, approvals in Edge via /approve. Free listing and reads, a
  held write and a held rename approved in the browser, a delete refused by policy,
  and `gargoyle audit --log` verifying all five honored calls, CHAIN_VERIFIED. Claude
  Code itself refused to shell-write around the gate when the issuer was unreachable.
  Friction found and fixed on the way: the package required Python 3.14 (now 3.12+,
  CI matrix 3.12/3.13/3.14) and that exposed a missing typing import that 3.14's
  deferred annotations had hidden; PowerShell 5.1 writes JSON with a BOM (setup
  script now writes without one); a CA certificate without keyUsage is refused by
  the OpenSSL inside Windows Python though browsers accept it (guide fixed); the
  middleware now logs why an issuer was unreachable instead of only the refusal
  code. Claude Code also prompts for each MCP tool on its own; that is the client's
  permission layer, orthogonal to the gate.
- Claude Desktop PoC (2026-10-18): the same middleware entry dropped into Claude
  Desktop (Microsoft Store build) worked with no code change. Desktop listed the
  gated folder, a held write (todo.md) was approved in the browser, a delete was
  refused and Desktop said so plainly, offering an empty overwrite instead, which
  would itself have come to the approver as a card. `gargoyle audit` then showed
  the two Desktop chains beside the five Claude Code ones: 7 entries, 0 failed,
  all CHAIN_VERIFIED, one trail for both clients. Only snag: the Store build keeps
  claude_desktop_config.json under the package's LocalCache\Roaming\Claude folder,
  not %APPDATA% (guide updated). Observation for step 5: the audit trail holds only
  executed chains; a refusal leaves no execution receipt, so refusals are visible in
  the middleware audit log and issuer log but not in `gargoyle audit`. The evidence
  log should record refusals and declines as first-class entries.
- Encoding bug found by the Desktop run of step 5 (2026-10-18): the middleware
  read stdin in text mode, so on Windows it decoded Desktop's UTF-8 as cp1252. An
  em dash in notes.md came back as three characters and one undefined byte as a
  lone surrogate, which the issuer accepted into a hold and then could not
  serialize: /pending answered 500, the approval page showed nothing, the client
  waited out its timeout. Fixed on both ends: both stdio servers and the upstream
  pipe are UTF-8 regardless of locale (utf8_stdio), and /issue refuses arguments
  that are not UTF-8 text (REF_ISSUER_ARGS_NOT_TEXT) rather than holding them.
  The assistant itself flagged the mojibake in its reply, which is how it was
  caught.
- Evidence log live (2026-10-18): after the fix, Claude Desktop on Windows ran
  listing, reads, a held write approved in the browser and a refused delete;
  `gargoyle audit --log` on the client: 9 entries (7 honored, 2 refused), 0 failed,
  chain EVIDENCE_VERIFIED, with the timed-out write from the encoding incident
  sitting in the chain as a refused entry carrying its flagged receipt. Refused rows
  now print the executor's reason beside the check outcome.
- Enterprise identity (2026-10-16): identity tokens may be RS256 or ES256 from a
  provider's JWKS (keys_from_jwks, entra_keys; GARGOYLE_ENTRA_TENANT on the issuer);
  Entra's preferred_username/upn is the principal; groups and app roles are policy
  inputs and rules match them (`groups`, `roles`). Still to build for an Entra
  rollout: a `gargoyle login` that acquires the middleware's token from Entra by
  device-code flow (MSAL) instead of the init-minted token, and approver roles in
  the receipt (step 4) so a finance hold needs a finance approver.
