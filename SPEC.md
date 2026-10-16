# Gargoyle wire specification

Format version: `gargoyle/1` (pre-release; see section 12).
This document defines the byte-level formats Gargoyle produces and checks:
the receipt, its hash and signature regions, the verification procedure,
replay semantics, the approval grant, and the two published records a
target consumes. Where this document and the reference implementation in
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
- **Principal**: the authenticated identity of the party on whose behalf the
  call is made. The issuer records the principal it authenticated; the
  target compares it with the principal it authenticated itself. Gargoyle
  compares principals; it does not authenticate them.
- **Receipt** (historically "envelope"): one signed, single-use, argument-bound
  authorization for one call at one target by one principal.
- **Grant**: a human approver's signed release of a held (requires_approval)
  receipt.

## 2. Encodings

**Canonical JSON.** Every hash and signature in this specification is
computed over the UTF-8 bytes of the canonical JSON of an object:

- object keys sorted by Unicode code point, recursively;
- no whitespace: separators are `,` between members and `:` between key and
  value;
- all non-ASCII characters escaped as `\uXXXX` (`ensure_ascii`), so the bytes
  are pure ASCII;
- `true`, `false`, `null` lowercase; integers without exponent or leading
  zeros; floats as the shortest round-tripping decimal.

Producers should keep arguments to strings, integers, booleans, null, arrays
and objects. Floats are permitted but two producers may render the same
float differently; a target that hashes different bytes refuses the binding.

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
| `envelope_version` | string | yes | yes | `"gargoyle/1"` |
| `decision` | string | yes | yes | `"ELIGIBLE"`; a receipt is only ever issued for an eligible call |
| `target_url` | string | yes | yes | the target the call is addressed to; compared as an exact string, no normalization |
| `policy.policy_id` | string | yes | yes | the policy's logic and version, e.g. `opa:payments/3` |
| `policy.policy_sha256` | 64 hex | yes | yes | the policy configuration the decision ran on |
| `request_context.tool` | string | yes | yes | the operation name (MCP tool, route, function); non-empty |
| `request_context.args_sha256` | 64 hex | yes | yes | `sha256(canonical_json(args))` |
| `request_context.principal` | string | yes | yes | the authenticated caller; non-empty |
| `timestamp_utc` | timestamp | no | no | when the receipt was built; informational only |
| `decision_sha256` | 64 hex | - | yes | section 4 |
| `issuer_key_id` | string | no | yes | names the issuer key in the target's trust material |
| `not_after` | timestamp | no | yes | expiry; the issuer always sets one (default 300 s) |
| `decision_id` | string | no | yes | the single-use id; unique per issuance (the issuer uses a UUID4) |
| `issuer_signature` | 128 hex | no | - | section 5 |

`request_context` contains exactly the three members listed. Nothing the
policy was shown beyond the call (the caller's claims, a manifest pin, an
interaction type) is in the receipt; the policy pin stands for all of it.
`args` themselves are not in the receipt; the target hashes the arguments it
is about to run and compares.

A receipt is **unusable** (refused `REF_VERIFY_ENVELOPE_ABSENT`) unless it is
an object carrying `policy`, `request_context` (an object with all three
members), `decision_sha256` and `target_url`.

## 4. decision_sha256

```
hash_region   = receipt minus {decision_sha256, timestamp_utc, issuer_key_id,
                               issuer_signature, not_after, decision_id}
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

The signature therefore covers `not_after` and `decision_id`: a captured
receipt cannot have its lifetime extended or its replay id swapped.
`timestamp_utc` carries no security weight and may change freely.

## 6. Verification

A target decides whether to act on `call = {tool, args, principal}` at
`target_url` given a presented `receipt`. `principal` is the identity the
target authenticated for the presenting party; it is never taken from the
request body or from the receipt. The checks run in this order and the first
failure is the result.

Before any check, the target must hold a live policy pin: either a fetched
published record (section 9) or the policy object itself. Having neither is
a configuration error, not a verdict; the reference verifier raises.

1. **Structure.** The receipt is usable (section 3). Else
   `REF_VERIFY_ENVELOPE_ABSENT`.
2. **Provenance.** Runs whenever the target has trusted issuer keys (a
   pinned map or a key record view; deployed targets always do).
   - `issuer_key_id` and `issuer_signature` are strings, else
     `REF_VERIFY_SIGNATURE_INVALID`.
   - With a pinned map: the key id is present, else
     `REF_VERIFY_SIGNATURE_UNKNOWN_KEY`.
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
   - `call` is an object whose keys are exactly `tool`, `args`, `principal`;
     else `REF_VERIFY_BINDING_MISMATCH`. Any extra member is unbound data.
   - Both principals are non-empty strings and equal, else
     `REF_VERIFY_PRINCIPAL_MISMATCH`. An unauthenticated caller never
     matches, whatever the receipt names. This runs before the tool and
     argument checks: the wrong holder is the finding.
   - `target_url` equal as strings; `request_context.tool` equal to
     `call.tool` as strings; `request_context.args_sha256` equal to
     `sha256(canonical_json(call.args))`. Else `REF_VERIFY_BINDING_MISMATCH`.

On success the result is `REASSERTED_AND_BOUND`. The verifier is pure; the
replay claim (section 7) is the executing party's next step.

`skew` is a non-negative tolerance for clock divergence (default 0) that
widens every time check symmetrically. A negative value is a configuration
error and raises.

**Unsigned mode.** A verifier given no trusted keys skips step 2 and accepts
any receipt whose hash recomputes, which anyone can produce. It exists to
show what a target sees without key material; a deployed target must pin
issuer keys. A `Consumer` refuses to be built without them.

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

When the policy's decision carries `requires_approval`, the issuer holds the
receipt and records an `approval_request_id` bound to its
`decision_sha256`. A human approver, with their own key on their own
device, signs a grant:

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

Single use is the holder's job, after verification: claim `grant_id` in a
replay store (refuse `REF_APPROVAL_REPLAY`) and consume
`approval_request_id` from the pending set by compare-and-delete against
`decision_sha256` (refuse `REF_APPROVAL_REQUEST_UNKNOWN` when unknown,
expired or bound to another decision). The approver map should come from a
signed key record (section 10) where the key's role is exactly `approver`;
a key-id comparison alone cannot stop an issuer-controlled key published
under another id.

## 9. The published policy record

A target on another host learns the live policy pin from a published
record, never from its own disk.

**Anchored form.** The record is the JSON object `{policy_id, policy_sha256}`
(any whitespace). The target pins `sha256(record_bytes)` out of band and
refuses bytes that do not hash to it (`REF_TARGET_ANCHOR_MISMATCH`). This
form has no time dimension: every reissue needs a new anchor on every
target.

**Signed form** (`gargoyle-published-record`), verified against a pinned
publisher public key instead of an anchor:

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

Call: `{"tool": "transfer_funds", "args": {"amount": 250, "to": "acct-9"}, "principal": "agent-7"}`
at `https://tools.example.com/target`, policy pin
`{"policy_id": "opa:payments/3", "policy_sha256": "aaaa...a" (64 a's)}`,
built at `2026-10-16T12:00:00+00:00`, signed under key id `issuer-2026-10`
with `not_after` `2026-10-16T12:05:00+00:00` and `decision_id`
`5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d`.

```
args_sha256      = e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7
decision_sha256  = 9ca3811ce3307aa21bfea4346f051850a35f6f639d5059467f418e4b7c6a6a40
issuer_signature = c51c20b0b335a0d71426b356230938a331c9c69609e1e8e7f9b7173a1acd0facf930bdbbf8795196afee54bb6c79b1fc286f4957a38c35a467bc8ad79d807401
```

Hash region bytes (section 4):

```
{"decision":"ELIGIBLE","envelope_version":"gargoyle/1","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","principal":"agent-7","tool":"transfer_funds"},"target_url":"https://tools.example.com/target"}
```

Signed region bytes (section 5):

```
{"decision":"ELIGIBLE","decision_id":"5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d","decision_sha256":"9ca3811ce3307aa21bfea4346f051850a35f6f639d5059467f418e4b7c6a6a40","envelope_version":"gargoyle/1","issuer_key_id":"issuer-2026-10","not_after":"2026-10-16T12:05:00+00:00","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","principal":"agent-7","tool":"transfer_funds"},"target_url":"https://tools.example.com/target"}
```

Grant releasing that decision for hold `req-0001`, `grant_id` `grant-0001`,
`not_after` `2026-10-16T12:10:00+00:00`, under key id `approver-alice`:

```
approver_signature = 39a1decfc5118b4b71e592d56108163da57963b915ffe22296c8faa03ba007d304f12a89a87cd26e082b17f2b40c546f243db6fe6d119f759d0bf4e69f8c6600
```

The complete objects are in `tests/fixtures/wire_vectors.json`.

## 12. Transport and versioning

- HTTP: the receipt travels as JSON in the `X-Gargoyle-Envelope` request
  header. Two copies of the header are ambiguous and count as no receipt.
  The reference target's body is exactly `{"tool", "args"}`; the principal
  comes from the target's own authentication (an injected resolver, or a
  header a trusted front proxy sets and strips from client input). The
  target refuses every call while its out-of-band configuration is missing
  (`REF_TARGET_NOT_CONFIGURED`) and any call for which it authenticated
  nobody (`REF_TARGET_NO_PRINCIPAL`), both before the receipt is read.
  Refusals are HTTP 403 with body `{"detail": {"honored": false, "reason": <code>}}`;
  an honored call answers 200 with `{"honored": true, "reason": "REASSERTED_AND_BOUND"}`.
- MCP: the receipt rides in `tools/call` `params._meta["gargoyle/envelope"]`;
  the response `_meta` carries `gargoyle/executed` (boolean) and
  `gargoyle/reason`. A stdio server serves one principal, configured out of
  band.
- Redis key prefixes used by the reference stores: `gargoyle:replay:` and
  `gargoyle:pending:`.
- `envelope_version` names this format. Any change to a field set, a hash
  or signature region, or the verification order is a new version;
  verifiers do not accept a version they do not implement. `gargoyle/1` is
  pre-release and may still change before the first release.
