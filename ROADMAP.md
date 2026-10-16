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
   requires that many distinct approver keys.
5. **Evidence log.** An append-only hash chain of receipts, verdicts and
   execution receipts, exportable and checkable offline. A log, a few
   hundred lines; never rules about how it may be amended.
6. **Approval transport.** A webhook that posts the flagged receipt to
   Slack or an approval product, the key staying on the approver's device.
   Integrate, do not build.

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

**Gate reached.** Steps 1-3 are done. The next work is outreach and measurement,
not step 4: publish the Python and npm packages, post the spec and vectors where
the MCP discussion (#3215) and the OAuth agent-token drafts are being read, and
wire the middleware into one real MCP server. Steps 4-6 wait for a signal from
outside.
