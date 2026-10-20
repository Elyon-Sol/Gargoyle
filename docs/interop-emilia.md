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

Both EMILIA runners (`conformance/runners/run-js.mjs`, `run_py.py`) produced
the expected verdict on all seven exported vectors. The Go lane was not run
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

## The one gap

An EMILIA approver signs the 32-byte SHA-256 of the canonical Authorization
Context. A Gargoyle approver signs the canonical grant (decision hash,
approval request id, grant id, expiry, key id). The bytes differ, so a stored
Gargoyle grant signature cannot be presented as an EMILIA signoff; EMILIA's
verifier refuses it, correctly. The Trust Receipt export therefore verifies
only when the approver has signed the context hash, which no Gargoyle console
does today.

Closing it is small and costs Gargoyle nothing it has: when the console shows
a hold, it also computes the EMILIA context for that hold
(gargoyle.emilia.authorization_context) and signs its hash with the same
browser key, returning both signatures with the grant. The issuer stores the
second signature beside the grant. Exports then carry a signoff the approver
actually made, and `gargoyle audit` can emit EMILIA Trust Receipts for every
honored flagged call that any of EMILIA's verifiers will accept. Gargoyle's
own verification is unchanged; the second signature is export material. The
reverse (treating an EMILIA signoff as a Gargoyle grant) would need Gargoyle's
grant to sign the context digest instead, which is a wire-format change and
is not proposed.

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
  approver_key_entry.
- tests/fixtures/emilia/: EMILIA's receipts.v1.json and canonicalization.v1.json
  (Apache-2.0, attributed), run on every test run.
- tests/test_emilia_interop.py: the vectors against Gargoyle; the exports'
  internal consistency; and, with GARGOYLE_EMILIA_REPO set to a checkout,
  EMILIA's own Python runner on the exports.
