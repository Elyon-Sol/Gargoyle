# Gargoyle wire specification

Format version: `gargoyle/3` (pre-release; see section 12).
This document defines the byte-level formats Gargoyle produces and checks:
the receipt, its hash and signature regions, the verification procedure,
replay semantics, the approval grant, the execution receipt and the offline
chain, and the two published records a target consumes. Where this document and the reference implementation in
`gargoyle/` disagree, the implementation is the bug: `tests/test_wire_spec.py`
recomputes every vector in section 11 from the seeds given there and checks
that this file quotes them verbatim.

## 1. Terms

- **Issuer**: the service that asks a policy about a call and, on ELIGIBLE,
  signs a receipt for it (`gargoyle.issuer`).
- **Policy**: anything that answers allow/deny and exposes a **pin**,
  `{policy_id, policy_sha256}`, identifying its logic and configuration.
  Gargoyle never decides; it records which policy did.
- **Target** (or executor, consumer): the party that runs the tool call and
  must refuse it without a valid receipt (`gargoyle.verifier` is the pure
  check, `gargoyle.consumer` packages it with the live pin, key trust and
  the replay claim, `gargoyle.mcp_server` and the reference target in
  `gargoyle.consumer` are the two shipped consumers).
- **Principal**: the authenticated identity of the party making the call
  (the agent). The issuer records the principal it authenticated; the
  target compares it with the principal it authenticated itself. Gargoyle
  compares principals; it does not authenticate them.
- **On behalf of**: the party the principal acts for (a user), when the
  issuer's identity input says so (section 12). The issuer's assertion,
  bound into the decision; a target compares it only when it knows the
  delegation itself.
- **Receipt** (historically "envelope"): one signed, single-use, argument-bound
  authorization for one call at one target by one principal.
- **Grant**: a human approver's signed release of a held (requires_approval)
  receipt.
- **Execution receipt**: the executor's signed statement that the
  authorized call ran, and what it produced (section 13).

## 2. Encodings

**Canonical JSON.** Every hash and signature in this specification is
computed over the UTF-8 bytes of the RFC 8785 canonical form (JSON
Canonicalization Scheme, JCS) of an object:

- object members sorted by the UTF-16 code units of their names,
  recursively;
- no whitespace: `,` between members and `:` between name and value;
- strings escaped only where JSON requires it: `\"`, `\\`, `\b`, `\f`,
  `\n`, `\r`, `\t`, other control characters as `\u00XX` with lowercase
  hex; every other character, non-ASCII included, is literal UTF-8;
- `true`, `false`, `null` lowercase; numbers as ECMAScript
  `Number::toString` (`1` not `1.0`, `1e+21`, `1e-7`, `0.000001`).

This is exactly what `JSON.stringify` produces for a key-sorted object in
JavaScript, and what the reference implementation's `canonical_json`
produces in Python. The same scheme is used by the Acta signed receipts and
EP authorization receipts drafts (section 16), so a receipt's bytes can be
recomputed by any JCS library. Integers are exact up to 2^53 in every
implementation; producers should prefer strings and integers in arguments.
`gargoyle/2` used Python's `ensure_ascii` escaping and code-point key order
instead; verifiers of this version refuse it.

**Hashes** are SHA-256, written as 64 lowercase hexadecimal characters.

**Signatures** are Ed25519 (RFC 8032, pure, no prehash) over the canonical
JSON bytes of the signed region. The 64-byte signature is written as 128
lowercase hexadecimal characters.

**Public keys** are the 32 raw Ed25519 bytes: hexadecimal in environment
configuration (`*_PUBLIC_KEY_HEX`), standard base64 in key records
(section 10).

**Timestamps** are ISO-8601 with an explicit UTC offset
(`2026-10-16T12:05:00+00:00`; a trailing `Z` is accepted on records). A
timestamp without an offset is malformed and fails closed wherever it is
compared.

## 3. The receipt

A receipt is a JSON object with these members. "Hashed" means inside the
`decision_sha256` region (section 4); "Signed" means inside the issuer
signature region (section 5).

| Field | Type | Hashed | Signed | Meaning |
|---|---|---|---|---|
| `envelope_version` | string | yes | yes | `"gargoyle/3"` |
| `decision` | string | yes | yes | `"ELIGIBLE"`; a receipt is only ever issued for an eligible call |
| `requires_approval` | boolean | yes | yes | the policy flagged the call for a human; the receipt is honored only with a grant (section 8) |
| `target_url` | string | yes | yes | the target the call is addressed to; compared as an exact string, no normalization |
| `policy.policy_id` | string | yes | yes | the policy's logic and version, e.g. `opa:payments/3` |
| `policy.policy_sha256` | 64 hex | yes | yes | the policy configuration the decision ran on |
| `request_context.tool` | string | yes | yes | the operation name (MCP tool, route, function); non-empty |
| `request_context.args_sha256` | 64 hex | yes | yes | `sha256(canonical_json(args))` |
| `request_context.principal` | string | yes | yes | the authenticated caller; non-empty |
| `request_context.on_behalf_of` | string | yes | yes | optional: the party the caller acts for; non-empty when present |
| `request_context.state_sha256` | 64 hex | yes | yes | optional: the hash of the executor's description of the target's state before the call (section 6.1); the receipt is honored only in that state |
| `approval.required` | integer | yes | yes | optional, flagged receipts only: how many distinct approvers must sign (absent: 1) |
| `approval.approvers` | array of string | yes | yes | optional, with `approval.required`: the approver key ids that count, sorted, unique, at least `required` of them (absent: any trusted approver) |
| `timestamp_utc` | timestamp | no | no | when the receipt was built; informational only |
| `decision_sha256` | 64 hex | - | yes | section 4 |
| `issuer_key_id` | string | no | yes | names the issuer key in the target's trust material |
| `not_after` | timestamp | no | yes | expiry; the issuer always sets one (default 300 s) |
| `decision_id` | string | no | yes | the single-use id; unique per issuance (the issuer uses a UUID4) |
| `approval_request_id` | string | no | yes | present iff `requires_approval` is true: the hold a grant must name; unique per issuance |
| `issuer_signature` | 128 hex | no | - | section 5 |

`request_context` contains exactly the three required members listed, plus
`on_behalf_of` when the issuer recorded a delegation. Nothing the policy was
shown beyond the call (the caller's claims, a manifest pin, an
interaction type) is in the receipt; the policy pin stands for all of it.
`args` themselves are not in the receipt; the target hashes the arguments it
is about to run and compares.

A receipt is **unusable** (refused `REF_VERIFY_ENVELOPE_ABSENT`) unless it is
an object carrying `policy`, `request_context` (an object with all three
required members, and a non-empty `on_behalf_of` if that key is present),
`decision_sha256`, `target_url` and a boolean `requires_approval`, and, when
that is true, a non-empty string `approval_request_id`. An `approval`
member, when present, must sit on a flagged receipt and be an object with
exactly `required` (an integer, at least 1, not a boolean) and optionally
`approvers` (a non-empty array of unique non-empty strings, no fewer than
`required`), else the receipt is unusable. A receipt whose
`envelope_version` is not the one the verifier implements is refused
`REF_VERIFY_VERSION_UNSUPPORTED` before anything else is read.

## 4. decision_sha256

```
hash_region   = receipt minus {decision_sha256, timestamp_utc, issuer_key_id,
                               issuer_signature, not_after, decision_id,
                               approval_request_id}
decision_sha256 = sha256(canonical_json(hash_region))
```

The excluded members are exactly those that vary between issuances of the
same decision, so a signed receipt's `decision_sha256` equals the unsigned
one, and a grant (section 8) that names a `decision_sha256` names the
decision, not one issuance of it.

```
args_sha256 = sha256(canonical_json(args))
```

`args` may be any JSON value, including `null`, `{}` and `[]`, which hash
differently from one another.

## 5. Issuer signature

```
signed_region    = receipt minus {issuer_signature, timestamp_utc}
issuer_signature = hex(ed25519_sign(issuer_private_key,
                                    utf8(canonical_json(signed_region))))
```

The signature therefore covers `not_after`, `decision_id`,
`approval_request_id` and `requires_approval`: a captured receipt cannot
have its lifetime extended, its replay id swapped, or its hold removed.
`timestamp_utc` carries no security weight and may change freely.

## 6. Verification

A target decides whether to act on `call = {tool, args, principal}` at
`target_url` given a presented `receipt`. `principal` is the identity the
target authenticated for the presenting party; it is never taken from the
request body or from the receipt. The checks run in this order and the first
failure is the result.

Before any check, the target must hold a live policy pin (a fetched
published record, section 9, or the policy object itself) and trusted
issuer keys (a pinned key map or a key record view, section 10). Lacking
either is a configuration error, not a verdict; the reference verifier
raises. There is no unsigned mode: a verifier without trusted keys could
only check a hash anyone can compute, so it is not offered.

1. **Structure.** The receipt is usable (section 3). Else
   `REF_VERIFY_ENVELOPE_ABSENT`.
2. **Provenance.**
   - `issuer_key_id` and `issuer_signature` are strings, else
     `REF_VERIFY_SIGNATURE_INVALID`.
   - With a pinned map: the key id is present, else
     `REF_VERIFY_SIGNATURE_UNKNOWN_KEY` (an empty map trusts nobody).
   - With a key record view (which, when present, is the only key source):
     the key is listed (`REF_VERIFY_KEY_UNKNOWN`), not revoked
     (`REF_VERIFY_KEY_REVOKED`), has role `issuer` or no role
     (`REF_VERIFY_KEY_ROLE_NOT_ISSUER`), and
     `not_before - skew <= now < not_after + skew`
     (`REF_VERIFY_KEY_OUT_OF_WINDOW`).
   - The signature verifies over the signed region (section 5), else
     `REF_VERIFY_SIGNATURE_INVALID`.
   - Expiry: `now < not_after + skew`, with an absent `not_after` accepted
     and a malformed or offset-less one refused:
     `REF_VERIFY_SIGNATURE_EXPIRED`.
3. **Currency and integrity** (`reassert`).
   - `decision_sha256` recomputes (section 4), else
     `REF_VERIFY_REASSERT_INVALIDATED`.
   - `policy.policy_id` and `policy.policy_sha256` equal the live pin, else
     `REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED`. A receipt issued under a
     policy that has since changed is never honored; the call must be
     decided again.
4. **Binding.**
   - `call` is an object whose keys are `tool`, `args`, `principal` and
     optionally `on_behalf_of` and `state_sha256`; else
     `REF_VERIFY_BINDING_MISMATCH`. Any other member is unbound data.
   - Both principals are non-empty strings and equal, else
     `REF_VERIFY_PRINCIPAL_MISMATCH`. An unauthenticated caller never
     matches, whatever the receipt names. This runs before the tool and
     argument checks: the wrong holder is the finding.
   - If `call` carries `on_behalf_of`, it is a non-empty string equal to
     the receipt's, else `REF_VERIFY_PRINCIPAL_MISMATCH`. A target that does
     not know the delegation omits it and the receipt's assertion stands; a
     live claim of delegation the receipt does not record is a mismatch.
   - `target_url` equal as strings; `request_context.tool` equal to
     `call.tool` as strings; `request_context.args_sha256` equal to
     `sha256(canonical_json(call.args))`. Else `REF_VERIFY_BINDING_MISMATCH`.
   - If the receipt carries `request_context.state_sha256`, `call.state_sha256`
     is present and equal, else `REF_VERIFY_STATE_MISMATCH`: the executor
     describes the target's state again at execution and the call runs only
     in the state the receipt bound. A live `state_sha256` the receipt does
     not carry is ignored; it was not part of the decision.

### 6.1 State binding

An executor may describe the state of the target a call will change before
it asks for a receipt, so that the decision, and a human's release of it,
apply to that state alone. The description is the executor's own statement
(as the execution receipt is):

```
{"ref": <what was examined, e.g. a file path>,
 "sha256": <hex of the target's bytes> | null when it does not exist,
 "size": <byte count> | null}
state_sha256 = sha256(canonical_json(description))
```

A description may also carry `summary`, a sentence for the approver in
the target's own terms, and `irreversible`, true when no later call can
restore the state (a sent message); neither is hashed, both are shown.
The issuer records `state_sha256` in the receipt's `request_context`,
hashed and signed, when the request carries a description; the reference
issuing service accepts it as `state` beside `args` and shows it to the
approver, with the proposed content rendered as a change against it. At
execution the executor recomputes the hash and refuses on any difference
(step 4 above); after execution it records the state again in the
execution receipt (section 13). What this proves: the human approved a
change to exactly the state they were shown, and the change ran in that
state. What it does not prove: that the executor described the state
truthfully, which rests on the executor as everything it reports does.
On success the result is `REASSERTED_AND_BOUND`. The verifier is pure; the
replay claim (section 7) and, for a flagged receipt, the grant check
(section 8) are the executing party's next steps.

`skew` is a non-negative tolerance for clock divergence (default 0) that
widens every time check symmetrically. A negative value is a configuration
error and raises.

A `Consumer` refuses to be built without issuer-key trust, and the verifier
refuses to run without it.

## 7. Replay semantics

A receipt is honored at most once. The unit of single use is
`decision_id`, which is signed (section 5) and therefore cannot be altered
without failing step 2.

- A receipt that reaches the execution step without a non-empty string
  `decision_id` is refused `REF_TARGET_NO_DECISION_ID`: single use cannot be
  enforced for it, and "no id, so skip the check" is forbidden.
- After verification succeeds and before the side effect, the executor
  claims `decision_id` atomically in a replay store: `check_and_claim`
  returns true exactly once per id. A second claim is refused
  `REF_VERIFY_REPLAY`.
- A claim is retained until `not_after + skew`, the same instant the
  verifier stops honoring the receipt, so an id cannot be claimed again
  inside the skew window. A receipt with no parseable `not_after` is
  retained for the life of the store.
- The store's scope is the scope of the guarantee. A per-process store
  honors a receipt once per process; a deployment with more than one
  executor process or replica must share one store (the reference
  `RedisReplayStore` uses `SET key 1 NX EX ttl`). A store that cannot
  answer is a refusal, never an action.

Expiry bounds the useful life of a captured receipt or a leaked issuer key
without anyone having to detect the leak; single use bounds it to one call.

## 8. The approval grant

When the policy's decision carries `requires_approval`, the issuer sets the
receipt's `requires_approval` to true and gives it a signed
`approval_request_id`. The decision may also state terms: how many
distinct approvers must sign and which approver key ids count; the issuer
records them in the receipt's `approval` member (section 3), hashed and
signed, so the threshold is the issuer's word and a caller cannot lower
it. Absent terms mean one grant from any trusted approver. The target will
not honor such a receipt without the grants, so the issuer may hand it out
at once (or hold it, section 8.2). A human approver, with their own key on
their own device, signs a grant:

| Field | Type | Signed | Meaning |
|---|---|---|---|
| `grant_version` | string | yes | `"1.0"` |
| `decision_sha256` | 64 hex | yes | the decision released (section 4); covers target, call and policy pin |
| `approval_request_id` | string | yes | the specific hold being released |
| `grant_id` | string | yes | mandatory, unique; the single-use key for grants |
| `not_after` | timestamp | yes | mandatory expiry |
| `approver_key_id` | string | yes | names the approver key |
| `approver_signature` | 128 hex | - | `ed25519_sign(approver_key, canonical_json(grant minus approver_signature))` |

Verification (`verify_grant`), first failure wins:

1. structure: an object with all seven members, else `REF_APPROVAL_MALFORMED`;
2. `grant_id` a non-empty string, else `REF_APPROVAL_MISSING_GRANT_ID`;
3. `approver_key_id != issuer key id`, else `REF_APPROVAL_SOD` (checked
   before the signature: an issuer-signed approval is not oversight even
   when well-formed);
4. the approver key is in the approver map, else `REF_APPROVAL_KEY_UNKNOWN`;
5. the signature verifies, else `REF_APPROVAL_SIGNATURE_INVALID`;
6. `decision_sha256` equals the held decision's, else
   `REF_APPROVAL_BINDING_MISMATCH`;
7. `approval_request_id` equals the hold's, else
   `REF_APPROVAL_REQUEST_MISMATCH`;
8. `not_after` present and `now < not_after + skew`, else
   `REF_APPROVAL_EXPIRED`.

### 8.0 The grant set

`verify_grants` judges one grant or a list of them against the receipt's
terms (`approval.required`, default 1; `approval.approvers`, default any
trusted key). Each grant is checked with `verify_grant` as above, the
receipt supplying `decision_sha256`, `approval_request_id` and
`issuer_key_id`; the first failing grant's reason is the answer. Then, in
order: a key that signed twice is `REF_APPROVAL_DUPLICATE_APPROVER`; a key
the receipt's `approvers` list does not name is
`REF_APPROVAL_APPROVER_NOT_ELIGIBLE`; fewer distinct approvers than
`required` (an empty list included) is `REF_APPROVAL_INSUFFICIENT`;
otherwise `GRANTS_SUFFICIENT`. Grants beyond the threshold are accepted and
counted; the set that verified is what the caller claims.

### 8.1 At the target

The grants are presented alongside the receipt (section 12), one or a
list. After the receipt verifies (section 6) and has a `decision_id`, a
consumer that finds `requires_approval` true:

1. refuses `REF_TARGET_APPROVAL_REQUIRED` if no grant was presented;
2. refuses `REF_TARGET_NO_APPROVER_TRUST` if it trusts no approver key. The
   approver map comes from the key record's `approver`-role keys when a key
   record is in use (unrevoked, in window, and never the issuer's key id),
   else from a pinned approver map;
3. runs `verify_grants` (section 8.0) against the receipt's own terms,
   refusing with its reason;
4. claims every counted grant's `grant_id` in the replay store under its
   own namespace, retained until that grant's `not_after + skew` (refuse
   `REF_APPROVAL_REPLAY`);
5. then claims `decision_id` as in section 7.

The grants are checked and claimed before the receipt is claimed, so a
refused set leaves the receipt unspent. Because `requires_approval`,
`approval_request_id` and `approval` are inside the issuer's signature, a
caller cannot strip the hold from a flagged receipt or lower its
threshold.

### 8.2 At the issuer (optional)

An issuer that prefers not to release a flagged receipt until the grants
exist records the hold in a pending set keyed by `approval_request_id`,
collects grants against it (refusing a repeated approver and an ineligible
one with the section 8.0 codes), and releases the set once `required`
distinct eligible approvers have signed; a grant for an unknown, expired or
differently bound hold is `REF_APPROVAL_REQUEST_UNKNOWN`. This is defense
in depth; the target's check in 8.1 does not depend on it.

The approver map should come from a signed key record (section 10) where
the key's role is exactly `approver`; a key-id comparison alone cannot stop
an issuer-controlled key published under another id.

### 8.3 Enrolled approvers (reference issuing service)

The reference issuing service also lets an approver enroll a key under an
identity-provider identity: an authenticated token whose `roles` (or
`groups`) claim marks the holder as an approver may bind its own subject
(the UPN) to a public key (`POST /approvers/enroll`); the UPN is then the
approver key id, the service publishes the map (`GET /approvers`), the
reference middleware merges it over its static approver keys when it
checks a grant, and a threshold's `approval.approvers` may name UPNs. The
service's operator is thereby the authority for who may approve, which is
weaker than a root-signed key record and appropriate where one
administrator runs both the service and the tenant. Separation of duties
is unchanged: an enrolled key is never the issuer's key, and the private
half is generated and held in the approver's browser. An enrollment
without the role is `REF_ISSUER_NOT_AN_APPROVER`. The enrollment record
keeps the directory's immutable object id and tenant id beside the UPN
when the token carried them. An approver may revoke their own key
(`POST /approvers/revoke`); the operator revokes any approver on the
service's host. A revoked key leaves the published map at once, so new
grants under it are refused by the service and by every consumer that
takes approver keys from it, and stays on file, marked with when and by
whom, so evidence from before the revocation still verifies.

What the service shows is scoped by the same notion of approver (the role
or group in the token, a configured approver key id, or an enrolled UPN):
an approver sees every hold with its arguments and the whole witness log
(section 15.1); any other identity sees only holds on its own calls, may
cancel only those, and is answered `REF_ISSUER_FORBIDDEN` for anything
else. Held arguments are often the contents of a file.

The console an approver signs with is served by the issuing service
(`GET /approve`, `GET /approve.js`), and that is a trust limit of the
reference service, not of the format. The approver's browser key is
non-extractable and never leaves the browser, but the page that asks it
to sign is the operator's: an operator who alters the served script can
have an approver's key sign a release for a hold the approver did not
see, and the resulting grant verifies everywhere, because it is the
approver's signature over the hash of a real decision. Separation of
duties still holds (the issuer key cannot sign a grant), and the witness
records the grant under the approver's id, so the forgery needs the
operator and is charged to the approver; no verifier detects it. The
mitigations are those for any signing page: a console installed locally
or served by a party the issuer's operator does not control, or a pin of
the console's hash in the record that the approver's browser checks
before loading the script. Neither is built. Until one is, an approver
trusts the issuer's operator with their signature.

The reference service caps the holds one principal may have waiting at
once (`GARGOYLE_MAX_OPEN_HOLDS`, default 20, counting held receipts and
held plans that are neither expired nor released). A held call or plan
over the cap is answered `REF_ISSUER_TOO_MANY_HOLDS` and nothing is
stored; free calls are unaffected, and a decline, a release or an expiry
frees a slot. The cap keeps one runaway client from filling every
approver's queue and the hold store. It is a service limit, not part of
the receipt.

## 9. The published policy record

A consumer learns the live policy pin either from a record file it was
given out of band (the JSON object `{policy_id, policy_sha256}`, read at
startup; the MCP middleware's `GARGOYLE_MCP_RECORD_PATH`) or, on another
host, from a published record it fetches and verifies against a pinned
publisher public key:

**Signed form** (`gargoyle-published-record`):

| Field | Type | Meaning |
|---|---|---|
| `format` | string | `"gargoyle-published-record"` |
| `version` | any | record schema version |
| `publisher_key_id` | string | names the pinned publisher key |
| `serial` | integer | monotonic; a lower serial than one already seen is a rollback |
| `issued_at` | timestamp | |
| `not_after` | timestamp | freshness bound |
| `policy_id`, `policy_sha256` | strings | the pin |
| `publisher_signature` | 128 hex | `ed25519_sign(publisher_key, canonical_json(record minus publisher_signature))` |

Order: structure and known key id (`REF_VERIFY_PUBLISHED_RECORD_INVALID`),
signature (`_INVALID`), then `now < not_after + skew` and
`serial >= last_seen_serial` (`REF_VERIFY_PUBLISHED_RECORD_STALE`). A
transport failure is `_INVALID`. The signature is checked before freshness,
so nothing in an unsigned record is believed.

## 10. The key record

A root-signed list of issuer and approver keys, so keys can be rotated and
revoked by publishing one record instead of re-pinning every target. The
root public key is pinned out of band and never fetched with the record.

| Field | Type | Meaning |
|---|---|---|
| `format` | string | `"gargoyle-key-record"` |
| `version` | any | record schema version |
| `root_key_id` | string | names the pinned root |
| `serial` | integer | monotonic, as in section 9 |
| `issued_at`, `not_after` | timestamps | |
| `keys` | array | one entry per key, below |
| `publisher_signature` | 128 hex | `ed25519_sign(root_key, canonical_json(record minus publisher_signature))` |

Key entry: `key_id` (string), `public_key` (base64 of the 32 raw bytes),
`not_before`, `not_after` (timestamps), `revoked` (boolean), optional
`role` (`"issuer"` or `"approver"`), optional `revoked_at`, `reason`.

Order: structure, root selection and signature
(`REF_VERIFY_KEY_RECORD_INVALID`), then `now < not_after + skew` and the
serial (`REF_VERIFY_KEY_RECORD_STALE`), then every entry parsed into the
trust view (`_INVALID` on bad key material or an offset-less window). When
a root status view is supplied it governs listed roots: `REF_VERIFY_ROOT_REVOKED`,
`REF_VERIFY_ROOT_RETIRED` (records issued at or after retirement),
`REF_VERIFY_ROOT_OUT_OF_WINDOW` (both `now` and `issued_at` must fall in the
root's own window).

`REF_VERIFY_ROOT_RECORD_INVALID` and `REF_VERIFY_ROOT_RECORD_STALE` are
reserved for a reader of a root record (the document that would supply the
root status view); no such reader ships in this package yet.

Per-key status (unknown, revoked, role, window) is decided by the consumer:
the verifier for issuer keys (section 6 step 2), `resolve_approver_keys`
for approver keys (only role `approver`, unrevoked, in window, and not the
issuer's key id).

## 11. Test vectors

Keys are derived deterministically for reproducibility: the Ed25519 seed is
`sha256(label)` for the labels below. These keys are for conformance
checking only.

| | Label | Public key (hex) |
|---|---|---|
| issuer | `gargoyle-spec-issuer` | `341860057bb6512b9050394d5e52912c16fbd22634fa1ee6ba1fa7697006c91f` |
| approver | `gargoyle-spec-approver` | `7ae5829f4a4439acbd8e292219526b196568afd3f2f8f3bae83e2e00976647d1` |

Call: `{"tool": "transfer_funds", "args": {"amount": 250, "to": "acct-9"}, "principal": "agent-7", "on_behalf_of": "user-42"}`
at `https://tools.example.com/target`, policy pin
`{"policy_id": "opa:payments/3", "policy_sha256": "aaaa...a" (64 a's)}`,
flagged (`requires_approval` true), built at `2026-10-16T12:00:00+00:00`,
signed under key id `issuer-2026-10` with `not_after`
`2026-10-16T12:05:00+00:00`, `decision_id`
`5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d` and `approval_request_id` `req-0001`.

```
args_sha256      = e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7
decision_sha256  = ba4b9b4cbd2155ef600dc7eab2f6f1781e12cfa7b9dff989b37b6640ba3ce5b2
issuer_signature = 15e44ed8a513c969dd411b3e8b4289a17b5911cefd9afc3b21f0991b2947ba78e7b696fcd68a08cd75f680653ae598186d19b809c6aeb5760bc863a5d92e3d01
```

Hash region bytes (section 4):

```
{"decision":"ELIGIBLE","envelope_version":"gargoyle/3","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"requires_approval":true,"target_url":"https://tools.example.com/target"}
```

Signed region bytes (section 5):

```
{"approval_request_id":"req-0001","decision":"ELIGIBLE","decision_id":"5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d","decision_sha256":"ba4b9b4cbd2155ef600dc7eab2f6f1781e12cfa7b9dff989b37b6640ba3ce5b2","envelope_version":"gargoyle/3","issuer_key_id":"issuer-2026-10","not_after":"2026-10-16T12:05:00+00:00","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"requires_approval":true,"target_url":"https://tools.example.com/target"}
```

Grant releasing that decision for hold `req-0001`, `grant_id` `grant-0001`,
`not_after` `2026-10-16T12:10:00+00:00`, under key id `approver-alice`:

```
approver_signature = 1cfc8699ebfaa135ff854a04a1db6b9a07d8adbb471535fac154a9d8a800400827df94a20898f21a340042adae2bfa4496b992a546df25ffb612b4c11b811308
```

Execution receipt (section 13) for that call, signed under key id
`executor-2026-10` at `2026-10-16T12:01:00+00:00`, with outputs
`{"status": "ok", "transfer_id": "tx-42"}`:

| | Label | Public key (hex) |
|---|---|---|
| executor | `gargoyle-spec-executor` | `39e2607fb14d5ce3b64b60f4828da01a17f56d9824d8d783afe601f5b51b6313` |

```
outputs_sha256     = a6cb76237119491aa9d6b1976bf763cb08d72f07dda4becf8bb32c0c4ee5914c
executor_signature = d45d58713917dceb9d4477f7fe880a681c6c8ead165cc18b1c43c9348ab05bbdf4e7cd8591bdd542baf9181262a10e8c223e2e96e856fcb676148c44e3d35007
```

Execution signed region bytes:

```
{"decision_id":"5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d","decision_sha256":"ba4b9b4cbd2155ef600dc7eab2f6f1781e12cfa7b9dff989b37b6640ba3ce5b2","executed_at":"2026-10-16T12:01:00+00:00","execution_version":"gargoyle-execution/1","executor_key_id":"executor-2026-10","outputs_sha256":"a6cb76237119491aa9d6b1976bf763cb08d72f07dda4becf8bb32c0c4ee5914c","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"target_url":"https://tools.example.com/target"}
```

JWS form (section 14) of the same signed receipt: the header segment is
`eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3Vlci0yMDI2LTEwIiwidHlwIjoiSldUIn0` (`{"alg":"EdDSA","kid":"issuer-2026-10","typ":"JWT"}`); the full token
is the `jws` member of the fixture.

### 11.1 Threshold vector

The same call and policy pin, flagged with terms
`{"required": 2, "approvers": ["approver-alice", "approver-bob"]}`, built
at the same timestamp, signed under `issuer-2026-10` with the same
`not_after`, `decision_id` `7c8d1e2f-0a1b-4c2d-8e3f-4a5b6c7d8e9f` and
`approval_request_id` `req-0002`. The second approver's seed label is
`gargoyle-spec-approver-2`, public key
`6fc61147c2d3347101b0f875039433acda66d949090a2d382dfe170cebdd2e5d`.

```
decision_sha256  = 105cc4bbadf94f228cd8c75a5f73534fb0ae9b9ffa35ca2e611759efb2162964
issuer_signature = ab1bd1dc7850ab4e2b30c1feb91be3afbbbf1388080b73311f5cfd19f1e5353c786e1067e9b216e26a9e1d43fb6a629d87497b861d976e4a7f5e0e21abd3390f
```

Hash region bytes (the `approval` member sorts first):

```
{"approval":{"approvers":["approver-alice","approver-bob"],"required":2},"decision":"ELIGIBLE","envelope_version":"gargoyle/3","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"requires_approval":true,"target_url":"https://tools.example.com/target"}
```

Two grants for hold `req-0002`, `not_after` `2026-10-16T12:10:00+00:00`:
`grant-0002-a` under `approver-alice` and `grant-0002-b` under
`approver-bob`:

```
approver_signature (alice) = 61c5ee3c017fda8b04721260828002502d51cd2b483b37eb62fc9e5406ee3134330de000af55e8828eeeaefed65cc4a74e5157dc39ada9a1300d6cc8c54a1109
approver_signature (bob)   = 1204fa86cefd7e24dfed1b7f08f88dd45601a1e59c44a62697c6c222547e187a52c76c7dc073355479f38c1371d375836c0f4026b7898078cda2ae5ca3851604
```

Either grant alone is `REF_APPROVAL_INSUFFICIENT`; both together release
the receipt, and the execution receipt signed under `executor-2026-10` at
`2026-10-16T12:01:00+00:00` with the same outputs has

```
executor_signature = e51236163da24a354148a255b98589b2d1f642a57185929b1f3ad3ba295ff4079e06c16266551f82c1f62d12f1c37a7a7b94a3f6663781dc978720cebf2e0304
```

The complete objects are the `threshold` member of
`tests/fixtures/wire_vectors.json`.

## 12. Transport and versioning

- HTTP: an issuer hands a receipt to a caller as JSON, conventionally in
  the `X-Gargoyle-Envelope` header, or as the JWS of section 14. An HTTP
  consumer is not specified; the MCP middleware is the shipped consumer. A
  consumer with no configuration refuses every call
  (`REF_TARGET_NOT_CONFIGURED`).
- MCP: the receipt rides in `tools/call` `params._meta["gargoyle/envelope"]`
  and a grant in `params._meta["gargoyle/grant"]`; the response `_meta`
  carries `gargoyle/executed` (boolean) and `gargoyle/reason`. A stdio
  server serves one principal, configured out of band. As middleware in
  front of another stdio server it relays every other method unchanged and
  forwards a `tools/call` only after honoring it, with both `gargoyle/*`
  keys removed from `params._meta`.
- Redis key prefixes used by the reference stores: `gargoyle:replay:` and
  `gargoyle:pending:`; grant ids are claimed in the replay store as
  `grant:<grant_id>`.
- Identity input at the issuer: an issuing service that receives the
  caller's identity as a token (an OAuth bearer JWT, a Transaction Token,
  an RFC 8693 delegation token) maps it to the two receipt fields with
  `gargoyle.identity`: `act.sub` is the principal and `sub` the party acted
  for; else `agentic_ctx.actor` / `agentic_ctx.principal` (Transaction
  Tokens for Agents); else `preferred_username` or `upn` (OIDC providers
  such as Entra ID, whose `sub` is opaque); else `sub`. `groups` and
  `roles` claims are passed to the policy as inputs and never enter the
  receipt. The token must be signed EdDSA, RS256 or ES256 by a key the
  service trusts, with the algorithm fixed by the key's type (a header
  cannot choose), unexpired, and for the service's audience when one is
  configured.
- `envelope_version` names this format. Any change to a field set, a hash
  or signature region, or the verification order is a new version;
  verifiers do not accept a version they do not implement
  (`REF_VERIFY_VERSION_UNSUPPORTED`). `gargoyle/3` moved canonical JSON to
  RFC 8785 and added the `approval` member. Evidence outlives a format
  change: an audit (`verify_chain`, `verify_log`, `verify_provenance` with
  `historical`) verifies a receipt of an earlier version, with its grants
  and execution receipt, under the canonical form that version was signed
  with (`gargoyle/2`: the pre-RFC 8785 form). Admission never does; a
  target honors only the current version. The TypeScript port verifies the
  current version only. `gargoyle/2` added `on_behalf_of`, the
  version check and the JWS form to `gargoyle/1`; nothing issued under
  `gargoyle/1` is honored. The format is pre-release and may still change
  before the first release.

**Remote transport.** The reference middleware also runs as a Streamable
HTTP MCP server (`gargoyle remote`) in front of a local or remote MCP
server. There the executor identifies the caller by a capability URL
segment the operator minted for one person, mapped to an identity token
the issuer trusts for that principal; the hosted MCP client cannot carry
the person's own token. The operator thereby vouches for the mapping, as
for an API key, and the receipt's `principal` is that person. All
sessions of one gate process share one replay store (section 7), so a
receipt is single-use across them.

**Identity at the client.** A middleware may present a per-user token
obtained from an identity provider (the reference `gargoyle login` uses
Entra ID's device-code flow and refreshes from the provider's cache). The
issuer treats it as any other identity input of this section; a middleware
in that mode with no usable token refuses locally with
`REF_TARGET_LOGIN_REQUIRED` and never falls back to a shared credential.

## 13. The execution receipt and the offline chain

After the side effect, an executor that holds a signing key issues an
execution receipt: its statement that the authorized call ran, chained to
the authorization receipt it honored.

| Field | Type | Signed | Meaning |
|---|---|---|---|
| `execution_version` | string | yes | `"gargoyle-execution/1"` |
| `decision_id` | string | yes | copied from the authorization receipt |
| `decision_sha256` | 64 hex | yes | copied; the decision this run fulfilled |
| `policy` | object | yes | copied; which policy version allowed this run |
| `target_url` | string | yes | copied |
| `request_context` | object | yes | copied: tool, args_sha256, principal, and on_behalf_of / state_sha256 when present |
| `outputs_sha256` | 64 hex | yes | `sha256(canonical_json(outputs))` |
| `pre_state_sha256` | 64 hex | yes | present iff the receipt carried `request_context.state_sha256`, and equal to it (section 6.1) |
| `post_state_sha256` | 64 hex | yes | optional: the executor's description of the target's state after the run, hashed as in section 6.1 |
| `executed_at` | timestamp | yes | when it ran; evidence, so inside the signature |
| `executor_key_id` | string | yes | names the executor key |
| `executor_signature` | 128 hex | - | `ed25519_sign(executor_key, canonical_json(receipt minus executor_signature))` |

The five copied fields are taken from the honored receipt byte for byte
(compared as canonical JSON), so the execution receipt names exactly what
was authorized and carries the policy pin inside its own signature.

**Verification** (`verify_execution_receipt`), first failure wins:
structure and version (`REF_EXEC_MALFORMED`); a trusted executor key
(`REF_EXEC_KEY_UNKNOWN`); the signature (`REF_EXEC_SIGNATURE_INVALID`);
every copied field equal to the authorization receipt's
(`REF_EXEC_BINDING_MISMATCH`); and, when the outputs are supplied, their
hash (`REF_EXEC_OUTPUTS_MISMATCH`).

**The chain** (`verify_chain`) audits one call offline with no live state:
the issuer's, approver's and executor's public keys and the three artifacts
are all it needs. With `now` set to the execution receipt's `executed_at`,
because what matters is that the authorization was valid when the call
ran, it checks in order:

1. the authorization receipt's structure, issuer signature and expiry
   (section 6 steps 1 and 2; `verify_provenance`);
2. if `requires_approval` is true, a grant that a trusted approver signed
   for that `decision_sha256` and `approval_request_id` (section 8; no grant
   is `REF_EXEC_GRANT_MISSING`);
3. the execution receipt (above).

The result lists each step's outcome, so an auditor sees where a chain
breaks. Currency (section 6 step 3) is not re-checked: the pin inside the
execution receipt records which policy version was live when the executor
honored the call, and that is the historical fact an audit wants.

What the chain does not prove: that the side effect happened as the outputs
claim (the executor is trusted for that, as for everything else it runs),
and that no second execution receipt exists for the same `decision_id`
(single use is enforced by the replay store at execution time; proving it
afterwards is an evidence log's job).

**Transport.** The reference HTTP target answers an honored call with
`{"honored": true, "reason": ..., "outputs": ..., "execution": <receipt>}`
when it holds an executor key (`GARGOYLE_EXECUTOR_KEY_ID` /
`GARGOYLE_EXECUTOR_KEY_HEX`), and without `execution` otherwise. The MCP
server puts the receipt in the response `_meta["gargoyle/execution"]`
(`GARGOYLE_MCP_EXECUTOR_KEY_ID` / `_HEX`); the outputs it attests to are
the tool result minus `_meta`.

## 14. JWS encoding

A receipt may travel as a JWS in compact serialization (RFC 7515) with
EdDSA (RFC 8037), so that any JWT library verifies it:

```
header  = {"alg":"EdDSA","kid":<issuer_key_id>,"typ":"JWT"}
payload = {"iss":<issuer_key_id>,"jti":<decision_id>,"aud":<target_url>,
           "exp":<not_after as epoch seconds>,"iat":<timestamp_utc as epoch seconds>,
           "gargoyle":<the signed receipt, section 3, issuer_signature included>}
token   = b64url(canonical_json(header)) "." b64url(canonical_json(payload))
          "." b64url(ed25519_sign(issuer_key, ascii(b64url(header) "." b64url(payload))))
```

Both signatures are the issuer's. A JWT library checks the outer one and
enforces `exp` and `aud` on its own; a Gargoyle verifier decodes the token
(`decode_receipt`), checks the outer signature with the key named by `kid`,
refuses any `alg` but `EdDSA` (`REF_JWS_ALG_UNSUPPORTED`), an unknown `kid`
(`REF_JWS_KEY_UNKNOWN`), a bad signature (`REF_JWS_SIGNATURE_INVALID`), a
malformed token (`REF_JWS_MALFORMED`), an expired `exp` (`REF_JWS_EXPIRED`),
an `aud` other than its own (`REF_JWS_AUDIENCE_MISMATCH`), and registered
claims that disagree with the wrapped receipt (`REF_JWS_PAYLOAD_MISMATCH`),
then hands the inner receipt to the ordinary procedure of section 6. The
inner canonical signature is what binds the decision; the outer one exists
for the libraries that cannot compute canonical JSON.

The same encoding is accepted as the issuer's identity input (section
12), there also under RS256 (RSASSA-PKCS1-v1_5 with SHA-256) and ES256
(ECDSA P-256, signature as r||s), with the keys loaded from a JWKS
document (RSA, EC P-256 and OKP Ed25519 entries by `kid`); a token with no
usable subject is `REF_IDENTITY_NO_SUBJECT`. A directory's signing keys
are shared by all its tenants, so where a tenant is configured a token
under the directory's keys must carry that tenant's id in `tid` (and in
`iss`, when present); one that carries another tenant's, or none, is
`REF_IDENTITY_WRONG_TENANT`. Tokens under a key the operator pinned name
no tenant and are not held to one. An audience is required whenever a
directory is trusted; a service configured without one refuses to start.
Receipts stay EdDSA only.

## 15. The evidence log

An execution receipt proves one honored call. It cannot show a refusal,
and a pile of receipts cannot show that none is missing. The evidence log
is the executor's own record of every decision, in order, each entry
hashed over the one before:

```
entry = {
  "evidence_version": "gargoyle-evidence/4",
  "seq":          <1, 2, 3 ...; dense>,
  "prev_sha256":  <entry_sha256 of seq-1; 64 "0" for seq 1>,
  "at":           <ISO 8601 UTC, when the executor decided>,
  "kind":         "honored" | "refused",
  "tool":         <tool name>,
  "args_sha256":  <section 4 argument hash>,
  "principal":    <the principal the executor serves>,
  "reason":       <the verdict code>,
  "receipt":      <section 3 receipt, or null>,
  "grant":        <section 8 grant, or null>,
  "execution":    <section 13 execution receipt, or null>,
  "client":       <the MCP client that made the call, "name version" from
                   its initialize handshake, or null; version 3 and later>,
  "ref":          <what the adapter examined for a state-bound call (a file
                   path, "mailRule:<id>"), or null; version 4 and later>,
  "entry_sha256": sha256(canonical_json(entry without entry_sha256))
}
```

One entry per line, canonical JSON (section 2) for the hash, any JSON for
the line. A `refused` entry carries no receipt when the policy refused
(nothing was issued) and carries the flagged receipt when a human declined
the hold or let it lapse; its `grant` and `execution` are null. An
`honored` entry carries the receipt, the grant if the receipt was flagged,
and the execution receipt.

**Verification** (`evidence.verify_log`), offline, with the issuer's,
approver's and executor's public keys, for each entry in file order:

1. the entry has exactly the fields above with the stated types, else
   `REF_EVIDENCE_MALFORMED` (a `{receipt, grant, execution}` line from a
   writer older than this section is `REF_EVIDENCE_UNCHAINED`);
2. `entry_sha256` recomputes, else `REF_EVIDENCE_HASH_MISMATCH`;
3. `seq` is the previous entry's plus one and `prev_sha256` is the
   previous entry's hash (the first entry: 1 and 64 zeros), else
   `REF_EVIDENCE_CHAIN_BROKEN`;
4. `honored`: receipt and execution are present, the section 13 chain
   verifies, and the receipt's `request_context` names the entry's
   `tool`, `args_sha256` and `principal`, else `REF_EVIDENCE_RECEIPT_MISSING`
   or the chain's own refusal;
5. `refused` with a receipt: the receipt has issuer provenance (section 6
   steps 1 and 2) judged at the entry's `at`, else that refusal;
   otherwise `ENTRY_VERIFIED`.

Verification continues after a failed entry, taking the file's own `seq`
and hash as the new expectation, so one bad entry is reported once rather
than failing every later one. The result names each entry's outcome, the
count of honored and refused entries, and the last `entry_sha256` (the
tail). The whole file is `EVIDENCE_VERIFIED` when every entry is.

`gargoyle-evidence/3` entries have no `ref` member;
`gargoyle-evidence/2` entries have no `client` member;
`gargoyle-evidence/1` entries hashed under the `gargoyle/2` canonical form;
a verifier recomputes each entry's hash under its own `evidence_version`,
so one log may span the change and still verify end to end.

What the chain proves: no entry was edited, removed or inserted after the
fact, and each honored one is a verified receipt chain. What it does not
prove: that the file is complete at its end. Truncation leaves a valid
shorter chain; an auditor who records the tail hash at each audit detects
it at the next. There is no mechanism for amending the log, because it is
not amended. The executor writes it (`GARGOYLE_MCP_AUDIT_LOG`) and
`gargoyle audit --log` verifies it.

### 15.1 The witness log and reconciliation

The evidence log is the executor's own statement, and the executor is a
workstation its user administers, holding the executor key. The reference
issuing service therefore keeps a second record on the operator's server:
one entry per decision it took, each hashed over the one before and signed
with the issuer key, so a client can neither forge nor edit it.

```
entry = {
  "witness_version": "gargoyle-witness/1",
  "seq": n, "prev_sha256": ..., "at": ...,
  "event": "started" | "issued" | "refused" | "granted" | "declined" | "plan" | "plan_granted",
  ... (issued: principal, tool, decision_id, decision_sha256, approval_request_id,
       args_sha256, held, covered; granted: approval_request_id, approver,
       collected, required, hold_kind; declined: approval_request_id, by;
       plan: principal, plan_id, steps, held),
  "entry_sha256":    sha256(canonical_json(entry minus entry_sha256, issuer_key_id, issuer_signature)),
  "issuer_key_id":   ..., "issuer_signature": ed25519 over canonical_json(entry minus issuer_signature)
}
```

Reconciliation (`gargoyle audit --witness`) verifies both chains and
compares them by `decision_id`. Findings, never resolved silently:

- `PREDATES_WITNESS`: the entry is older than the witness's first `started`
  entry, so the witness can vouch for it neither way; reported as
  information, not a failure;
- `UNWITNESSED_RECEIPT`: evidence honors a decision the issuer never issued,
  or one whose hash or principal differs (a forged or foreign receipt);
- `UNWITNESSED_RELEASE`: a held call was honored but the issuer saw no grant
  for its hold, or for the plan the release names (a bypass of the
  approval, or evidence signed around it);
- `MISSING_EVIDENCE`: the issuer issued a receipt to this principal and the
  client recorded nothing (dropped or suppressed evidence);
- `EVIDENCE_BEFORE_ISSUE`: the client's entry predates the issuance.

Tree check (`gargoyle audit --check-tree DIR`): every file under `DIR`
that the evidence has a post-state for (the `ref` and the execution
receipt's `post_state_sha256`) must hash to that state now, else
`CHANGED_OUTSIDE_GATE`; a file the gate never touched is counted, not
judged. No plaintext is needed: the hashes in the evidence suffice.

What this establishes and what it does not. On a workstation its user
administers, the gate constrains the assistant, not the user; a change
made around the gate is not prevented. With the witness and the tree
check it is detected: evidence that disagrees with the issuer, and files
that disagree with the evidence, are findings a reviewer sees.

## 16. Relation to other receipt formats

Three Internet-Drafts of 2026 describe pieces of what this specification
chains together. None is a standard yet; this section maps vocabulary so an
implementer of one can read a Gargoyle receipt, and names what each lacks
that the chain here supplies. All three and Gargoyle use RFC 8785 for the
signed bytes (section 2) and Ed25519 signatures in lowercase hex.

| Gargoyle | Acta signed receipts (draft-farley-acta-signed-receipts) | EP authorization receipts (draft-schrock-ep-authorization-receipts) | XAIP receipts (draft-xkumakichi-xaip-receipts) |
|---|---|---|---|
| receipt (section 3) | `payload` of type `protectmcp:decision` | Authorization Context | - |
| `request_context.tool` | `tool_name` | `action_type` | `toolName` |
| `request_context.args_sha256` | none (`payload_digest` is optional and unspecified; arguments MUST NOT be included) | `action_hash` over the Action Object (parameters included) | `taskHash` |
| `request_context.principal` / `on_behalf_of` | `session_id` (opaque) | `initiator`, `agent_binding.agent_id` | `agentDid`, `callerDid` |
| `policy.policy_id`, `policy.policy_sha256` | `policy_digest` (`sha256:<hex>`, optional) | `policy_id`, `policy_hash` | - |
| `decision` | `decision` (`allow`/`deny`/`rate_limit`) | - | `success` (post hoc) |
| `requires_approval`, `approval.required`, `approval.approvers` | - | `required_approvals`, `approver`, `approver_index` (one Context per approver) | - |
| `decision_id` (single use, section 7) | none (`nonce` MAY be added; no semantics) | `nonce`, `ConsumeOnce` | - |
| `not_after` | none (verifier freshness window RECOMMENDED 24 h) | `expires_at` | freshness window |
| `issuer_key_id`, `issuer_signature` | `signature.kid`, `signature.sig` | log checkpoint signature | `signature` (executor) |
| grant (section 8) | - | Signoff (`context_hash`, `signature`, `approver_key_id`, WebAuthn optional) | `callerSignature` (co-signature, not approval) |
| execution receipt (section 13) | post-execution receipt (`tool_duration_ms`) | `consumption.committed_at` | the receipt itself (`resultHash`, `latencyMs`, `failureType`) |
| evidence log (section 15) | `previousReceiptHash` chain (informal) | Merkle `log_proof` with signed checkpoint | - |

What the chain here says that none of the three says alone: one
`decision_id` ties the policy decision, the human release and the
execution, and the policy pin inside all three names the policy version
that was live (section 6, currency). Acta has no approval and no single
use; EP has no execution record and binds the human to a hash of the whole
action rather than to a receipt; XAIP has no authorization and no policy.
What they have that this does not: Acta's Merkle commitment mode for
selective disclosure, EP's WebAuthn-bound approver keys and Merkle-logged
receipts with a signed checkpoint, XAIP's DID identities. An
implementation that needs those should layer them above this
specification: a grant's `approver_signature` may be produced by a
WebAuthn authenticator, and the evidence log's entries may be committed to
a transparency log, without changing any byte defined here.

## 17. Scoped grants (plans)

A card per held call is right for a mailbox rule and wrong for the
twentieth step of a reconciliation. A plan lets a human approve a bounded
scope once while every call inside it stays bound and single-use.

```
plan = {
  "plan_version":        "gargoyle-plan/1",
  "plan_id":             <unique per plan>,
  "approval_request_id": <the hold a grant must name>,
  "target_url":          <section 3>,
  "principal":           <the caller the plan is for>,
  "policy":              <the pin the steps were judged under>,
  "steps":               [{"tool": <name>, "args_sha256": <section 4 hash>}
                          | {"tool": <name>, "match": {<argument>: <glob>}} ...],
  "approval":            {"required": n, "approvers": [...]}?   (section 3),
  "note":                <the caller's stated purpose, shown to the approver>,
  "not_after":           <expiry>,
  "plan_sha256":         sha256(canonical_json(plan minus plan_sha256, issuer_key_id, issuer_signature)),
  "issuer_key_id":       ..., "issuer_signature": ed25519 over canonical_json(plan minus issuer_signature)
}
```

**Issuing.** The issuer judges every step under the policy as a call
(a step with exact arguments on those arguments; a pattern step with its
patterns as the argument values, so a broad pattern fails a narrow
rule). Any step refused refuses the plan (`REF_PLAN_STEP_REFUSED`); a
step whose decision is not plannable refuses it
(`REF_PLAN_STEP_NOT_PLANNABLE`; the reference rules file says `"plan":
false` on a hold to keep a tool individual, and sends should be). The
plan is held when any step would be; its approval terms are the strictest
over the steps. A grant for a plan is a section 8 grant whose
`decision_sha256` is `plan_sha256` and whose `approval_request_id` is the
plan's.

**Release.** A flagged receipt may be released, instead of by grants of
its own, by a release record `{"plan", "grants", "step", "args"}`. The
verifier (`verify_plan_release`) checks: the plan verifies (structure,
issuer signature, hash, expiry: `REF_PLAN_MALFORMED`, `REF_PLAN_KEY_UNKNOWN`,
`REF_PLAN_SIGNATURE_INVALID`, `REF_PLAN_EXPIRED`); the plan names the
receipt's principal, target and policy pin (`REF_PLAN_BINDING_MISMATCH`);
the named step exists and matches the call's tool and arguments, and the
arguments hash to the receipt's `args_sha256` (`REF_PLAN_NO_MATCHING_STEP`);
the grants release the plan under its terms (a grant's own refusal, or
`REF_PLAN_GRANTS`). The consumer then claims `plan_id:step` in the replay
store (`REF_PLAN_STEP_CONSUMED` on reuse) and the receipt's `decision_id`
as always. The record carries the arguments so an auditor can re-run the
match offline; `verify_chain` accepts a release record in place of grants.

**What a plan trades.** The approver sees scope, not content: tools,
patterns, count, expiry, the note. State binding still runs at the
executor (section 6.1) but the human did not see the state. That is the
reason plans are a policy choice per tool, and why the evidence names the
plan and step behind every released call. The reference issuing service
opens no per-call hold for a call the executor reports as covered by an
approved plan; a false report costs nothing, since the executor refuses
without a valid release. The TypeScript port verifies per-call chains and
does not yet verify plan releases.

