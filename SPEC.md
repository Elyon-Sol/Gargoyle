# Gargoyle wire specification

Format version: `gargoyle/2` (pre-release; see section 12).
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
float differently (Python writes `1.0`, JavaScript writes `1`; Python writes
`1e+16`, JavaScript `10000000000000000`), and a target that hashes different
bytes refuses the binding. Integers are safe up to 2^53 in every
implementation. Object keys are sorted by code point in Python and by UTF-16
code unit in JavaScript; the two agree for every key without characters
outside the Basic Multilingual Plane, which is to say every key anyone
should use.

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
| `envelope_version` | string | yes | yes | `"gargoyle/2"` |
| `decision` | string | yes | yes | `"ELIGIBLE"`; a receipt is only ever issued for an eligible call |
| `requires_approval` | boolean | yes | yes | the policy flagged the call for a human; the receipt is honored only with a grant (section 8) |
| `target_url` | string | yes | yes | the target the call is addressed to; compared as an exact string, no normalization |
| `policy.policy_id` | string | yes | yes | the policy's logic and version, e.g. `opa:payments/3` |
| `policy.policy_sha256` | 64 hex | yes | yes | the policy configuration the decision ran on |
| `request_context.tool` | string | yes | yes | the operation name (MCP tool, route, function); non-empty |
| `request_context.args_sha256` | 64 hex | yes | yes | `sha256(canonical_json(args))` |
| `request_context.principal` | string | yes | yes | the authenticated caller; non-empty |
| `request_context.on_behalf_of` | string | yes | yes | optional: the party the caller acts for; non-empty when present |
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
that is true, a non-empty string `approval_request_id`. A receipt whose
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
     optionally `on_behalf_of`; else `REF_VERIFY_BINDING_MISMATCH`. Any
     other member is unbound data.
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
`approval_request_id`. The target will not honor such a receipt without a
grant, so the issuer may hand it out at once (or hold it, section 8.2). A
human approver, with their own key on their own device, signs a grant:

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

### 8.1 At the target

The grant is presented alongside the receipt (section 12). After the
receipt verifies (section 6) and has a `decision_id`, a consumer that finds
`requires_approval` true:

1. refuses `REF_TARGET_APPROVAL_REQUIRED` if no grant was presented;
2. refuses `REF_TARGET_NO_APPROVER_TRUST` if it trusts no approver key. The
   approver map comes from the key record's `approver`-role keys when a key
   record is in use (unrevoked, in window, and never the issuer's key id),
   else from a pinned approver map;
3. runs `verify_grant` with the receipt's own `decision_sha256` and
   `approval_request_id` as the expected values and the receipt's
   `issuer_key_id` as the separation-of-duties id, refusing with its
   reason;
4. claims `grant_id` in the replay store under its own namespace, retained
   until the grant's `not_after + skew` (refuse `REF_APPROVAL_REPLAY`);
5. then claims `decision_id` as in section 7.

The grant is checked and claimed before the receipt is claimed, so a
refused grant leaves the receipt unspent. Because `requires_approval` and
`approval_request_id` are inside the issuer's signature, a caller cannot
strip the hold from a flagged receipt.

### 8.2 At the issuer (optional)

An issuer that prefers not to release a flagged receipt until the grant
exists records the hold in a pending set keyed by `approval_request_id` and
consumes it by compare-and-delete against `decision_sha256` when the grant
arrives (refuse `REF_APPROVAL_REQUEST_UNKNOWN` when unknown, expired or
bound to another decision). This is defense in depth; the target's check
in 8.1 does not depend on it.

The approver map should come from a signed key record (section 10) where
the key's role is exactly `approver`; a key-id comparison alone cannot stop
an issuer-controlled key published under another id.

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

Call: `{"tool": "transfer_funds", "args": {"amount": 250, "to": "acct-9"}, "principal": "agent-7", "on_behalf_of": "user-42"}`
at `https://tools.example.com/target`, policy pin
`{"policy_id": "opa:payments/3", "policy_sha256": "aaaa...a" (64 a's)}`,
flagged (`requires_approval` true), built at `2026-10-16T12:00:00+00:00`,
signed under key id `issuer-2026-10` with `not_after`
`2026-10-16T12:05:00+00:00`, `decision_id`
`5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d` and `approval_request_id` `req-0001`.

```
args_sha256      = e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7
decision_sha256  = 6186ac4baead392be19c380c691a3d9194210c4abee8d0fc717789e0bab4a8c4
issuer_signature = 6850a23730113a14cdef04d973526edefec88fb8172640b142a91b25dd779f2d85cc68e2930cc7850942aa02a73185f3b1e01a43a08e52f8030e13d307654502
```

Hash region bytes (section 4):

```
{"decision":"ELIGIBLE","envelope_version":"gargoyle/2","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"requires_approval":true,"target_url":"https://tools.example.com/target"}
```

Signed region bytes (section 5):

```
{"approval_request_id":"req-0001","decision":"ELIGIBLE","decision_id":"5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d","decision_sha256":"6186ac4baead392be19c380c691a3d9194210c4abee8d0fc717789e0bab4a8c4","envelope_version":"gargoyle/2","issuer_key_id":"issuer-2026-10","not_after":"2026-10-16T12:05:00+00:00","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"requires_approval":true,"target_url":"https://tools.example.com/target"}
```

Grant releasing that decision for hold `req-0001`, `grant_id` `grant-0001`,
`not_after` `2026-10-16T12:10:00+00:00`, under key id `approver-alice`:

```
approver_signature = 8116b67b02bbf96448a1998af6740a388b5fb6be183beb6f88f69fc123416ea1ca2d512db0a68cccd295fec18d731527dd30d0190b61fa4113d588d03292da04
```

Execution receipt (section 13) for that call, signed under key id
`executor-2026-10` at `2026-10-16T12:01:00+00:00`, with outputs
`{"status": "ok", "transfer_id": "tx-42"}`:

| | Label | Public key (hex) |
|---|---|---|
| executor | `gargoyle-spec-executor` | `39e2607fb14d5ce3b64b60f4828da01a17f56d9824d8d783afe601f5b51b6313` |

```
outputs_sha256     = a6cb76237119491aa9d6b1976bf763cb08d72f07dda4becf8bb32c0c4ee5914c
executor_signature = de7575a5f3bbecf644b5cf6f30a03d19c6d8225759ab8e4cd8c488b86145cdcf54c4aefe390d705822c5e168ee926ce92d864bf6a176abf682ff403d7454cd04
```

Execution signed region bytes:

```
{"decision_id":"5b6b0c7e-6f1e-4d5b-9c3a-1e2f3a4b5c6d","decision_sha256":"6186ac4baead392be19c380c691a3d9194210c4abee8d0fc717789e0bab4a8c4","executed_at":"2026-10-16T12:01:00+00:00","execution_version":"gargoyle-execution/1","executor_key_id":"executor-2026-10","outputs_sha256":"a6cb76237119491aa9d6b1976bf763cb08d72f07dda4becf8bb32c0c4ee5914c","policy":{"policy_id":"opa:payments/3","policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"request_context":{"args_sha256":"e2363d59384e0a154faccbcc375337c59cc9c5fefa843519e0d5d311cf32bab7","on_behalf_of":"user-42","principal":"agent-7","tool":"transfer_funds"},"target_url":"https://tools.example.com/target"}
```

JWS form (section 14) of the same signed receipt: the header segment is
`eyJhbGciOiJFZERTQSIsImtpZCI6Imlzc3Vlci0yMDI2LTEwIiwidHlwIjoiSldUIn0` (`{"alg":"EdDSA","kid":"issuer-2026-10","typ":"JWT"}`); the full token
is the `jws` member of the fixture.

The complete objects are in `tests/fixtures/wire_vectors.json`.

## 12. Transport and versioning

- HTTP: the receipt travels as JSON in the `X-Gargoyle-Envelope` request
  header and a grant, when one is needed, in `X-Gargoyle-Grant`. Two copies
  of either header are ambiguous and count as absent.
  The reference target's body is exactly `{"tool", "args"}`; the principal
  comes from the target's own authentication: by default the client
  certificate the TLS-terminating proxy verified, read from the last element
  of `X-Forwarded-Client-Cert` (its `URI` SAN, else its `Subject`), or a
  proxy-set identity header, or an injected resolver. In every mode the
  proxy must strip any client-supplied copy of the header. The
  target refuses every call while its out-of-band configuration is missing
  (`REF_TARGET_NOT_CONFIGURED`) and any call for which it authenticated
  nobody (`REF_TARGET_NO_PRINCIPAL`), both before the receipt is read.
  Refusals are HTTP 403 with body `{"detail": {"honored": false, "reason": <code>}}`;
  an honored call answers 200 with `{"honored": true, "reason": "REASSERTED_AND_BOUND"}`.
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
  Tokens for Agents); else `sub` alone. The token must be EdDSA-signed by a
  key the service trusts, unexpired, and for the service's audience when one
  is configured.
- `envelope_version` names this format. Any change to a field set, a hash
  or signature region, or the verification order is a new version;
  verifiers do not accept a version they do not implement
  (`REF_VERIFY_VERSION_UNSUPPORTED`). `gargoyle/2` added `on_behalf_of`, the
  version check and the JWS form to `gargoyle/1`; nothing issued under
  `gargoyle/1` is honored. The format is pre-release and may still change
  before the first release.

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
| `request_context` | object | yes | copied: tool, args_sha256, principal |
| `outputs_sha256` | 64 hex | yes | `sha256(canonical_json(outputs))` |
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

The same encoding, read with the same rules, is accepted as the issuer's
identity input (section 12); a token with no usable subject is
`REF_IDENTITY_NO_SUBJECT`.
