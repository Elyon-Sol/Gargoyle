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
spendable once. The decision comes from your policy engine (an OPA adapter
is included); the caller is authenticated by your transport (the
proxy-verified client certificate, by default); Gargoyle sits in front of
your MCP server and lets through only what both agreed to.

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
- **Holds.** A decision that requires approval is flagged inside the signed
  receipt. The target will not run it without a grant a human signed for
  that exact decision, under their own key, on their own device.

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

**Open Policy Agent.** `gargoyle.opa.OpaPolicy` asks OPA's data API and
pins the exact set of policy modules OPA holds, so editing a policy
invalidates every outstanding receipt until the call is decided again.

```python
from gargoyle.opa import OpaPolicy
policy = OpaPolicy("http://127.0.0.1:8181", "gargoyle/decision")
```

```rego
package gargoyle
default decision := {"allow": false, "reason": "DEFAULT_DENY"}
decision := {"allow": true, "requires_approval": input.tool == "transfer_funds"} {
    input.principal == "spiffe://example.org/agents/payments"
    input.tool in {"read_balance", "transfer_funds"}
}
```

OPA unreachable, an undefined document, or a result in no recognized shape
is a refusal, never an issuance. Any other engine goes behind the same
two-method interface. `gargoyle.policy.ManifestPolicy` is a test fixture.

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
trust, and the verifier refuses to run without it, so an unsigned receipt is
never honored. For a flagged receipt, pass the human's grant as
`grant=`; the consumer verifies it against the receipt's own decision and
hold, claims it once, and only then claims the receipt.

For a live pin that can be reissued, give the consumer a record source
(a publisher-signed record with a serial and an expiry) instead of
anchored bytes; for issuer keys that can be rotated and revoked, a key
record source. Both are consulted on every check and fail closed.

## Two shipped consumers

**MCP middleware** (`python -m gargoyle.mcp_server -- <upstream command>`):
a stdio MCP server you put in front of any other stdio MCP server. The
handshake, `tools/list` and everything else are relayed. A `tools/call` is
forwarded only when `params._meta["gargoyle/envelope"]` carries a valid
receipt for that tool, those arguments and the principal the server serves
(and `params._meta["gargoyle/grant"]` a grant, when the receipt is
flagged); a refused call is answered here and never reaches the upstream.
Without an upstream command it runs a built-in demo executor.
Configuration is by environment:

| Variable | Meaning |
|---|---|
| `GARGOYLE_MCP_GATE_KEY_ID`, `GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX` | the pinned issuer key |
| `GARGOYLE_MCP_TARGET_ID` | the target identity receipts bind to |
| `GARGOYLE_MCP_PRINCIPAL` | the client this server serves |
| `GARGOYLE_MCP_RECORD_PATH` | the published policy record |
| `GARGOYLE_MCP_APPROVER_KEY_ID`, `GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX` | the approver key whose grants release flagged calls (optional, both or neither) |

**Reference HTTP target** (`uvicorn gargoyle.consumer:app`): a FastAPI
service that authenticates the caller by transport, reads `{"tool", "args"}`
from the body, the receipt from `X-Gargoyle-Envelope` and a grant from
`X-Gargoyle-Grant`, and acts only on a verdict. The default principal source
is the client certificate the TLS-terminating proxy verified, read from
Envoy's `X-Forwarded-Client-Cert` (URI SAN, else Subject); set
`GARGOYLE_PRINCIPAL_SOURCE=header` and `GARGOYLE_PRINCIPAL_HEADER` for a
proxy-set identity header instead, or inject a resolver. In every mode the
proxy must strip any client-supplied copy of the header. Its environment
variables are listed at the top of `gargoyle/consumer.py`.

## Approval holds

When the policy's decision carries `requires_approval`, the receipt is
issued with `requires_approval: true` and a signed `approval_request_id`.
No target will run it on its own: the consumer demands a grant for exactly
that decision and hold, verifies it (provenance, separation of duties,
binding, expiry), claims it once, and only then claims the receipt. A human
runs `gargoyle-approver` on a machine that holds the approver private key;
given the receipt it shows the tool, argument hash, principal, target and
policy that are inside the issuer's signature, and emits the grant. The
agent presents receipt and grant together. Approver keys should come from a
signed key record where the key's role is `approver`
(`gargoyle.approver_trust`), so an issuer-controlled key can never approve.
An issuer that prefers to hold flagged receipts until the grant exists can
do that too (`gargoyle.pending_store`); the target's check does not depend
on it.

## Modules

| Module | Role |
|---|---|
| `policy` | the decision interface and the reference manifest policy |
| `opa` | the Open Policy Agent adapter |
| `issuer` | ask the policy, sign the receipt |
| `envelope` | receipt construction, hash region, signature region, currency check |
| `verifier` | the pure target-side check and every refusal code |
| `consumer` | `Consumer` (pin, keys, verify, claim) and the reference HTTP target |
| `mcp_server` | the stdio MCP middleware (and demo executor) |
| `replay_cache`, `pending_store` | single use for receipts and holds; in-memory or Redis |
| `approval`, `approver_cli`, `approver_trust` | grants, the human's tool, approver key trust |
| `published_source`, `published_record_source` | the live policy pin, anchored or signed |
| `key_record_source` | root-signed issuer and approver keys with windows and revocation |
| `transport` | HTTPS with CA bundle, client certificates, no redirects, DNS pinning |

## What Gargoyle does not do

- It does not decide. The policy does, and the receipt is only as good as
  that decision.
- It does not authenticate principals. The issuer and the target each
  authenticate the caller themselves (by default, the target trusts the
  client certificate its proxy verified); Gargoyle compares the two results.
- It cannot stop a caller that never asks for a receipt. Only a target that
  refuses unattested calls can.
- It does not distribute trust material. Issuer keys, record anchors, root
  keys and the proxy's identity header are the deployer's to protect.
- The approval flow separates duties only if the approver's private key is
  out of the issuing service's reach. That is a deployment property.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
