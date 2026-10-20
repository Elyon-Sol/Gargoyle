# Gargoyle and the EMILIA Protocol (2026-10-20)

EMILIA (draft-schrock-ep-authorization-receipts, github.com/emiliaprotocol/
emilia-protocol, Apache-2.0) is the nearest peer in docs/comparison-2026-10-20.md:
an approver-held key signs the hash of an Authorization Context that commits
to an action hash and a policy hash, consumption is one-time, receipts verify
offline against pinned keys and a signed log checkpoint, with JavaScript,
Python and Go verifiers and a 340-vector conformance suite. This note records
what happened when EMILIA's vectors were run against Gargoyle and Gargoyle's
artifacts were exported into EMILIA's profiles and run through EMILIA's own
verifiers (commit 3f712d2 of their repository, their runners unmodified).

## Results

| Direction | What ran | Result |
|---|---|---|
| EMILIA vectors, Gargoyle verifier | EP-RECEIPT-v1, 14 vectors, through gargoyle.emilia.verify_ep_receipt (Gargoyle's RFC 8785 canonical form + Ed25519 + EMILIA's Merkle-v2 rule) | 14/14 agree; canonical bytes identical on every payload |
| EMILIA vectors, Gargoyle canonical form | EP-CANONICALIZATION-v1, 35 vectors (NFC, surrogates, duplicate names, depth, I-JSON profile) | 35/35 agree |
| Gargoyle export, EMILIA verifiers | A Gargoyle receipt and an execution receipt wrapped as EP-RECEIPT-v1 under the issuer and executor keys; a tampered copy | JS and Python runners: valid, valid, refused |
| Gargoyle export, EMILIA verifiers | A full Gargoyle chain (flagged receipt, grant, execution receipt) as an EP-AUTHORIZATION-RECEIPT-v1 Trust Receipt with a Class B signoff over the context hash, single-leaf Merkle-v2 log proof signed by the issuer key; plus three negatives | JS and Python runners: valid; grant-signature-reused refused; tampered args refused; approver equals initiator refused |
| LIVE export, EMILIA verifiers (2026-10-20 23:11 UTC) | `gargoyle emilia` run on the author's own Windows workstation (gargoyle-receipts 0.19.0.dev0; the author's Entra tenant, separate requester and approver accounts; no outside client has run Gargoyle yet) over its 60-entry evidence log: one write_file approved in the browser console by the Entra-enrolled approver, the grant carrying the dual-signed `emilia` member; 17 earlier approvals skipped (grants predate the member); executor-signed checkpoint, tree size 1 | JS and Python runners: valid; copies with the initiator, args hash, checkpoint root or signoff signature altered: refused by both |

Both EMILIA runners (`conformance/runners/run-js.mjs`, `run_py.py`) produced
the expected verdict on all seven synthetic vectors and on the live workstation export
(sha256 067d55b73317a5dd0e37ace02d4a5992c6d279274e446fe67cdeb28058fbe0d0, kept
outside the repository because it names the author's accounts and paths; a redacted,
re-signed copy is in docs/interop-emilia/). The Go lane was not run
(no Go toolchain on this machine).

## What maps cleanly

- Canonical form: Gargoyle's RFC 8785 serializer and EMILIA's canonicalizer
  produce the same bytes. EMILIA additionally restricts signed material to
  strings, booleans, null and safe integers; every Gargoyle artifact is inside
  that profile already (hashes and timestamps are strings).
- Keys: both sides are Ed25519. EMILIA pins public keys as base64url SPKI DER
  where Gargoyle uses raw hex; a one-line conversion.
- Policy pin: EMILIA's `policy_hash` in the signed context is Gargoyle's
  `policy_sha256`. The two pin checks are the same check.
- Action: Gargoyle's bound call (tool, args hash, principal, on_behalf_of,
  target) becomes the EMILIA Action Object, with the native decision id and
  decision hash carried in a `gargoyle` member so the two artifacts name one
  action.
- Ceremony identity: Gargoyle's `decision_id` is EMILIA's
  `authorization_instance` and `consumption.nonce`; per-context nonces derive
  from the random `approval_request_id`.
- Execution: `committed_at` is the Gargoyle execution receipt's
  `executed_at`, inside the context window.
- Log proof: a single-leaf EP-MERKLE-v2 tree whose checkpoint the issuer key
  signs is accepted by EMILIA's degenerate empty-path rule.

## The gap, and how it was closed the same day

An EMILIA approver signs the 32-byte SHA-256 of the canonical Authorization
Context. A Gargoyle approver signs the canonical grant. The bytes differ, so a
stored Gargoyle grant signature cannot be presented as an EMILIA signoff;
EMILIA's verifier refuses it, correctly (the test
`gargoyle_grant_signature_reused_as_signoff` keeps that on record).

Closed by a second signature from the same browser key. When the console
approves a receipt hold it also builds the EMILIA Authorization Context for
that hold (approve.js `emiliaContext`, byte-identical to
`gargoyle.emilia.authorization_context`; tests/test_console_js.py proves it
under Node) and signs the context hash. The pair travels inside the grant as
its optional `emilia` member (SPEC 8.4), covered by the grant signature, so it
reaches the issuer's hold store, the witness and the gate's evidence log with
no new plumbing. The issuer checks the member against the hold before storing
the grant: the context must be exactly the derived one (only `approver_index`
and `expires_at` are the console's, and `expires_at` may not outlive the
receipt or the grant) and the signature must verify under the approver's
enrolled key. A grant without the member, from the CLI approver or an older
console, is accepted as before.

`gargoyle emilia --log audit.jsonl --out DIR` then exports every honored,
approved call whose grants all carry a signoff as EMILIA Trust Receipts, in
the file format EMILIA's conformance runners read, with the signoffs the
approvers actually made, under one Merkle tree (EP-MERKLE-v2, positional
inclusion paths) whose checkpoint this gate's executor key signs. The approver
key pinned for each receipt is chosen from the id's current and past keys
(public-keys.json and approvers.json), as `gargoyle audit` does. EMILIA's
JavaScript and Python runners accept a three-receipt export with multi-leaf
paths (tests/test_emilia_interop.py, with GARGOYLE_EMILIA_REPO set).

The reverse (treating an EMILIA signoff as a Gargoyle grant) would need
Gargoyle's grant to sign the context digest instead, which is a wire-format
change and is not proposed.

## What EMILIA has that Gargoyle does not carry across

Class A signoffs (WebAuthn platform authenticators with user verification; the
Gargoyle console key is a non-extractable WebCrypto key, Class B in EMILIA's
custody vocabulary), a signed Approver Directory with inclusion proofs
(Gargoyle's approver registry is a plain file), m-of-n with ordered-chain
proofs, portable revocation statements, and formal models. Gargoyle's state
binding, proven revert and issuer-witness reconciliation have no EMILIA
counterpart and travel only in the `gargoyle` member of the Action Object.

## Files

- gargoyle/emilia.py: verify_ep_receipt, ep_receipt, action_object,
  authorization_context, context_hash_for, signoff, trust_receipt,
  verify_embedded_signoff, trust_receipts_from_entries (Merkle tree),
  verification_for.
- gargoyle/static/approve.js: emiliaAction, emiliaContext, emiliaSignoff;
  approve.html signs the member on every receipt approval.
- gargoyle/cli.py: `gargoyle emilia`.
- tests/fixtures/emilia/: EMILIA's receipts.v1.json and canonicalization.v1.json
  (Apache-2.0, attributed), run on every test run.
- tests/test_emilia_interop.py: the vectors against Gargoyle; the exports'
  internal consistency; and, with GARGOYLE_EMILIA_REPO set to a checkout,
  EMILIA's own Python runner on the exports.
