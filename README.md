# Gargoyle

Signed, single-use, argument-bound receipts and human-approval holds for
agent tool calls.

An agent asks for permission to run a tool. Something you already trust
decides (OPA, Cedar, your own code). Gargoyle turns that decision into a
**receipt**: an Ed25519-signed record that names the tool, a hash of its
arguments, the principal the decision was made for, the target it may be
presented to, and the policy that decided. The target checks the receipt
before it acts, and honors it once. When the policy says a call needs a
human, the receipt is held until an approver signs a **grant** for exactly
that decision with a key the issuing service does not have.

Gargoyle does not decide whether a call is allowed. It makes an allow
decision portable, verifiable, bound to one call by one caller, and
spendable once.

Status: pre-release (`0.1.0.dev0`). The wire format is `gargoyle/1` and may
still change before the first release; it is specified in [SPEC.md](SPEC.md).

## What a receipt gives you

- **Binding.** A receipt for `transfer_funds` with `{"amount": 250}` is
  refused for `{"amount": 250000}`, for `delete_database`, and at any
  target but the one it names.
- **A principal.** The receipt carries the identity the issuer
  authenticated; the target compares it with the identity it authenticated.
  A receipt obtained by one agent cannot be spent by another.
- **Single use.** Every receipt carries a signed `decision_id`; an executor
  claims it exactly once. A replayed receipt is refused.
- **Expiry.** Every receipt carries a signed `not_after` (default 300 s). A
  captured receipt, or a leaked issuer key, is useful for minutes, not
  forever.
- **Currency.** The receipt pins the policy that decided. If the policy
  changes, outstanding receipts stop being honored and the call must be
  decided again.
- **Holds.** A decision that requires approval is held until a human signs
  a grant for that decision, under their own key, on their own device.

## Install

    pip install -e ".[dev]"
    python -m pytest

Python 3.14 or later. Redis is optional (`.[redis]`) and only needed to
share the replay cache and pending-approval set across executor replicas.

## Issuing a receipt

The policy is anything with `pin()` and `decide()`; see `gargoyle.policy`.
The interaction you pass carries the call (`tool`, `args`, `principal`) and
whatever claims your policy reads. The receipt records only the call and
the policy pin.

```python
from gargoyle.issuer import ENVELOPE_HEADER, issue

interaction = {
    "tool": "transfer_funds",
    "args": {"amount": 250, "to": "acct-9"},
    "principal": principal,          # who you authenticated, never what they claimed
    **claims,                        # whatever your policy decides on
}
result = issue(policy, "https://tools.example.com/target", interaction,
               signing_key=issuer_private_key, key_id="issuer-2026-10")

if result.envelope is None:
    refuse(result.decision.reason)
elif result.decision.requires_approval:
    hold(result.envelope)            # see "Approval holds"
else:
    send(call, headers={ENVELOPE_HEADER: json.dumps(result.envelope)})
```

`gargoyle.policy.ManifestPolicy` is a reference policy for tests and
examples (token-subset checks against a JSON manifest). Put a real policy
engine behind the interface for anything else.

## Checking a receipt

Every executor runs the same check: establish the live policy pin,
establish the trusted issuer keys, verify the receipt against the call it is
about to run, claim the `decision_id`. `gargoyle.consumer.Consumer` packages
it.

```python
from gargoyle.consumer import Consumer

consumer = Consumer(
    target_id="https://tools.example.com/target",
    pinned_public_keys={"issuer-2026-10": issuer_public_key},
    record_bytes=open("published_record.json", "rb").read(),   # {policy_id, policy_sha256}
)

call = {"tool": name, "args": arguments, "principal": peer_identity}
verdict = consumer.check(envelope, call)
if verdict.honored:
    run(name, arguments)
else:
    refuse(verdict.reason)           # REF_VERIFY_* or REF_TARGET_*
```

`peer_identity` is who *you* authenticated as the caller (an mTLS peer, a
bearer token's subject, an identity a trusted proxy asserted). It is never
read from the request. A consumer refuses to be built without issuer-key
trust, so an unsigned receipt is never honored.

For a live pin that can be reissued, give the consumer a record source
(a publisher-signed record with a serial and an expiry) instead of
anchored bytes; for issuer keys that can be rotated and revoked, a key
record source. Both are consulted on every check and fail closed.

## Two shipped consumers

**MCP server** (`python -m gargoyle.mcp_server`): a stdio MCP server that
executes a `tools/call` only when `params._meta["gargoyle/envelope"]`
carries a valid receipt for that tool, those arguments and the principal
the server serves. Configuration is by environment:

| Variable | Meaning |
|---|---|
| `GARGOYLE_MCP_GATE_KEY_ID`, `GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX` | the pinned issuer key |
| `GARGOYLE_MCP_TARGET_ID` | the target identity receipts bind to |
| `GARGOYLE_MCP_PRINCIPAL` | the client this server serves |
| `GARGOYLE_MCP_RECORD_PATH` | the published policy record |

**Reference HTTP target** (`uvicorn gargoyle.consumer:app`): a FastAPI
service that authenticates the caller (an injected resolver, or a header a
trusted front proxy sets), reads `{"tool", "args"}` from the body and the
receipt from `X-Gargoyle-Envelope`, and acts only on a verdict. Its
environment variables are listed at the top of `gargoyle/consumer.py`.

## Approval holds

When `result.decision.requires_approval` is true, the issuing service holds
the receipt and records an `approval_request_id` bound to its
`decision_sha256` (`gargoyle.pending_store`). A human runs
`gargoyle-approver` on a machine that holds the approver private key; it
shows the held decision and emits a signed grant (`gargoyle.approval`). The
service verifies the grant (provenance, separation of duties, binding to
the decision and the request, expiry), consumes the hold once, and only
then releases the receipt. Approver keys should come from a signed key
record where the key's role is `approver` (`gargoyle.approver_trust`), so
an issuer-controlled key can never approve.

## Modules

| Module | Role |
|---|---|
| `policy` | the decision interface and the reference manifest policy |
| `issuer` | ask the policy, sign the receipt |
| `envelope` | receipt construction, hash region, signature region, currency check |
| `verifier` | the pure target-side check and every refusal code |
| `consumer` | `Consumer` (pin, keys, verify, claim) and the reference HTTP target |
| `mcp_server` | the stdio MCP server |
| `replay_cache`, `pending_store` | single use for receipts and holds; in-memory or Redis |
| `approval`, `approver_cli`, `approver_trust` | grants, the human's tool, approver key trust |
| `published_source`, `published_record_source` | the live policy pin, anchored or signed |
| `key_record_source` | root-signed issuer and approver keys with windows and revocation |
| `transport` | HTTPS with CA bundle, client certificates, no redirects, DNS pinning |

## What Gargoyle does not do

- It does not decide. The policy does, and the receipt is only as good as
  that decision.
- It does not authenticate principals. The issuer and the target each
  authenticate the caller themselves; Gargoyle compares the two results.
- It cannot stop a caller that never asks for a receipt. Only a target that
  refuses unattested calls can.
- It does not distribute trust material. Issuer keys, record anchors, root
  keys and the proxy's identity header are the deployer's to protect.
- The approval flow separates duties only if the approver's private key is
  out of the issuing service's reach. That is a deployment property.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
