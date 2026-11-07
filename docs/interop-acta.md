# Gargoyle and Acta signed receipts (2026-11-06)

Acta (draft-farley-acta-signed-receipts-03, Tom Farley, ScopeBlind; Apache-2.0
reference verifier `@veritasacta/verify`) is the receipt format closest to
Gargoyle's: an Ed25519 signature over the RFC 8785 canonical form of a
decision payload, a `policy_digest`, a `previousReceiptHash` chain, keys
resolved through `/.well-known/acta-keys.json`. Its appendix names eleven
implementations, and github.com/ScopeBlind/agent-governance-testvectors
holds the vectors several of them are checked against. This note records
what happened when those vectors were run against Gargoyle's verifier, and
when Gargoyle's witness was exported as an Acta chain and checked the way
an Acta verifier would.

## Results

| Direction | What ran | Result |
|---|---|---|
| Acta vectors, Gargoyle verifier | `verifier-vectors/key-window` (6 cases), `chain-link` (27: alone, after a supplied predecessor, as a sequence), `signing-input` (4), `revocation` (2, scored under -04, which defines no revocation) through `gargoyle.acta.verify_receipt` / `verify_sequence` | 39/39 reach the published verdict; every named code and key status matches |
| Acta vectors, Gargoyle verifier | `verifier-vectors/timeliness` (a chain of two and a proposed commitment) | both receipts and the link verify; the commitment's `terminal_hash` is our section 6.7 computation of the genesis receipt |
| Acta negatives, Gargoyle verifier | `negative/embedded-key`: a receipt carrying its own public key, in the Acta envelope and in the APS shape | never valid: `key_not_found` with a warning that the embedded member was ignored; the APS shape is `unknown_format` |
| Acta policy digest | Section 6.8 over the suite's Cedar policy | equals the `policy_digest` in `expected/chain.jsonl`, which their harness computes independently |
| Gargoyle export, Gargoyle verifier | An issuer run under the rules policy (allow, hold then release, refuse by rule, hold then decline) exported from its witness: six receipts, one chain, a signed commitment | every receipt valid under the issuer's own `/.well-known/acta-keys.json`; the sequence holds (1 chain, 0 breaks); the policy bundle served at `/.well-known/acta-policies/<hex>.json` recomputes to the receipts' digest; a tampered receipt is `signature_invalid` and breaks the link after it; a shortened set fails the commitment as `truncated` |
| Gargoyle export, Acta's reference verifier | `tests/test_acta.py::test_export_verifies_under_an_outside_acta_verifier`, which runs the command in `GARGOYLE_ACTA_VERIFY` over the export with our JWK Set | not yet run: the verifier is an npm package this build host does not install unattended. Run it with `GARGOYLE_ACTA_VERIFY="npx --yes @veritasacta/verify@0.11.0" python -m pytest tests/test_acta.py -k outside` and record the result here |

The vectors are copied unmodified into `tests/fixtures/acta/` (commit
5c749de5 of their repository, 2026-11-04) and run in CI. The `scripts/`
generators are not copied; nothing from the vector repository executes here.

## What maps cleanly

- Canonical form and signature: both sides sign the RFC 8785 bytes with
  Ed25519 and write the signature in lowercase hex. Acta signs the payload
  member alone (section 6.6); the export does exactly that.
- Keys: Acta resolves `kid` through a JWK Set at a well-known path. The
  issuer now serves one, carrying its Ed25519 key as `OKP`/`Ed25519`; the
  verifier reads `valid_from` / `valid_until` as the half-open window the
  vectors test (section 9.2).
- Policy pin: Acta's `policy_digest` is section 6.8 over a manifest of
  policy files. Gargoyle's rules policy pins the SHA-256 of its file's
  bytes, which is what a manifest entry wants, so the digest is computable
  from the pin alone (engine `gargoyle.rules/1`, one file named
  `rules.json`) for every witness entry that recorded a pin, and the issuer
  publishes the bundle for the pin in force.
- Chain: `previousReceiptHash` is SHA-256 over the whole previous receipt,
  signature included (section 6.7); the export links every receipt to the
  one before it in witness order.
- Decisions: `allow`, `deny` and `require_approval` carry the issuer's
  three outcomes, and the human's release or decline is a second receipt on
  the same hold (`approval_granted`, `approval_declined`), which is how the
  draft says a held action's terminal outcome is recorded.

## What does not map, and what the export does about it

- Acta has no single-use receipt and no policy currency. An Acta `allow`
  does not die when the policy changes; a Gargoyle receipt does (SPEC
  section 6). The export therefore does not re-encode Gargoyle receipts as
  Acta receipts. It states the issuer's decisions in Acta's vocabulary and
  points at the native artifacts: each payload's `gargoyle` member names the
  witness entry (sequence and hash), the `decision_id`, `decision_sha256`,
  `args_sha256`, `approval_request_id` and `target_url`. The native receipt,
  grant and execution receipt remain the evidence.
- Acta payloads must not carry arguments or identities (section 9.3). The
  export carries neither: the argument hash and the hold id, not the path
  or the principal.
- Acta's chain cannot show its tail is complete, and section 9.7 asks for
  an issuer-signed commitment outside the chain. The witness is that
  record: issuer-signed entries, a head published at `/health`, and every
  exported receipt naming its entry. The export also writes a
  `gargoyle:chain-commitment` receipt (count, terminal hash, witness head)
  that an Acta verifier can check in the same envelope shape.
- Executions are not decisions (section 9.8). The export carries no
  execution receipts; those are the executor's statement and belong to the
  evidence log, which the XAIP export (next) will carry.

## What changed in Gargoyle to make this possible

The witness entry for an issued, refused or planned call now records the
policy pin it was decided under (`gargoyle-witness/2`). Before this the pin
lived only in the receipt the client holds; an issuer-side export could not
name the policy, and an audit could not compare the client's receipt pin
with the issuer's record. Version 1 entries verify beside version 2 ones in
one file. The freeze clause of SPEC section 12 names version 2.

## Running it

    gargoyle acta export --witness /opt/gargoyle/deploy/witness.jsonl --out acta-2026-11 --env /opt/gargoyle/deploy/issuer.env
    gargoyle acta verify --replay-chain acta-2026-11/receipts.jsonl --jwks https://<issuer>/.well-known/acta-keys.json
    gargoyle acta verify acta-2026-11/commitment.json --jwks acta-2026-11/acta-keys.json

The export refuses a witness that does not verify under the issuer key. It
writes `receipts.jsonl`, `commitment.json`, `acta-keys.json` (a copy of the
JWK Set, for offline checks; the live anchor is the issuer's URL), the
policy bundle for the rules file in force, and `EXPORT.json` with the
counts and the witness head.

## Limits

- Envelope shape only. The flat shape of earlier revisions and the APS
  `decision_receipt` shape are reported as `unknown_format`.
- EdDSA and ES256 are verified; ML-DSA-65 is reported as
  `unsupported_algorithm` (undecidable), not rejected.
- Commitment mode (section 6, Merkle-committed fields) is not implemented;
  a `committed_fields_root` member is covered by the signature and
  otherwise ignored, as the draft requires of a verifier that does not opt
  in.
- Archival mode only (section 9.1): a receipt's age is reported, never
  judged. The timeliness suite's proposed commitment rule is not applied.
- The policy bundle is served for the pin in force. A past pin's digest
  still verifies (it is in the witness and the receipts); its bundle is the
  operator's backup of that rules file.
