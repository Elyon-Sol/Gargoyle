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

[![PyPI](https://img.shields.io/pypi/v/gargoyle-receipts)](https://pypi.org/project/gargoyle-receipts/)

Status: pre-release (`0.16.2.dev0`, on PyPI as `gargoyle-receipts`). The wire format is `gargoyle/3` and may
still change before the first release; it is specified in [SPEC.md](SPEC.md).

## What a receipt gives you

- **Binding.** A receipt for `transfer_funds` with `{"amount": 250}` is
  refused for `{"amount": 250000}`, for `delete_database`, and at any
  target but the one it names.
- **A principal.** The receipt carries the identity the issuer
  authenticated; the target compares it with the identity it authenticated.
  A receipt obtained by one agent cannot be spent by another. When the agent
  acts for a user, the receipt records that too (`on_behalf_of`).
- **Standard encodings.** A receipt can travel as a JWS (EdDSA) that any
  JWT library verifies, and the issuer can take the caller's identity from
  an OAuth bearer token, an RFC 8693 delegation token or a Transaction
  Token, signed EdDSA, RS256 or ES256 by keys from the provider's JWKS.
  With Entra ID the principal is the user's UPN and the token's groups and
  app roles become policy inputs, so a rules file can say "finance may hold
  invoice updates; shipping may not" without naming people.
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
- **Proof of execution.** An executor with a key answers each honored call
  with a signed execution receipt: the decision it fulfilled, the policy
  version that allowed it, and a hash of the outputs. Receipt, grant and
  execution receipt verify together, offline, with three public keys.

## Install

    pip install -e ".[dev]"
    python -m pytest

Python 3.12 or later. A TypeScript verifier and consumer for Node 20+
lives in [ts/](ts/) (`cd ts && npm install && npm test`); its suite
recomputes the same conformance vectors byte for byte, so the two
implementations cannot drift apart silently. Redis is optional (`.[redis]`) and only needed to
share the replay cache and pending-approval set across executor replicas.

## Issuing a receipt

The policy is anything with `pin()` and `decide()`; see `gargoyle.policy`.
The interaction you pass carries the call (`tool`, `args`, `principal`) and
whatever claims your policy reads. The receipt records only the call and
the policy pin.

```python
from gargoyle.issuer import ENVELOPE_HEADER, issue

who = principal_from_token(bearer_or_transaction_token, IDP_KEYS, audience="issuer")  # gargoyle.identity
# IDP_KEYS: pinned, or entra_keys("<tenant>") / keys_from_jwks(<provider JWKS>)
interaction = {
    "tool": "transfer_funds",
    "args": {"amount": 250, "to": "acct-9"},
    "principal": who["principal"],         # the agent, as the identity provider authenticated it
    "on_behalf_of": who["on_behalf_of"],   # the user it acts for, when the token says so
    **claims,                              # whatever your policy decides on
}
result = issue(policy, "https://tools.example.com/target", interaction,
               signing_key=issuer_private_key, key_id="issuer-2026-10")

if result.envelope is None:
    refuse(result.decision.reason)
elif result.decision.requires_approval:
    hold(result.envelope)            # see "Approval holds"
else:
    send(call, headers={ENVELOPE_HEADER: json.dumps(result.envelope)})
    # or, for a target that speaks JWT: gargoyle.jws.encode_receipt(result.envelope, issuer_private_key)
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
two-method interface.

**No engine.** `gargoyle.rules.RulesPolicy` decides from a JSON file:
first matching rule wins, globs on tool name, principal, delegation,
the caller's groups and roles, and string arguments, actions allow, hold
or deny. The pin is the file's hash,
so an edit invalidates outstanding receipts exactly as an engine change
does. This is what `gargoyle init` sets up.

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
(a publisher-signed record with a serial and an expiry) instead of a
static pin; for issuer keys that can be rotated and revoked, a key record
source. Both are consulted on every check and fail closed.

## Proof that it ran

Give a consumer an executor key and it signs an execution receipt after the
side effect. Anyone holding the issuer's, approver's and executor's public
keys can then audit one call with no network and no live state:

```python
from gargoyle.execution import verify_chain

chain = verify_chain(receipt, execution,
                     issuer_public_keys=ISSUER_KEYS, executor_public_keys=EXECUTOR_KEYS,
                     grant=grant, approver_public_keys=APPROVER_KEYS,
                     outputs=outputs, check_outputs=True)
chain["accepted"], chain["steps"]   # True, [("authorization", ...), ("approval", ...), ("execution", ...)]
```

That is the sentence Gargoyle can say that nobody else can: a specific
policy version authorized a specific call for a specific principal, a
human's key released it, and exactly that call ran once, verifiable offline
by anyone. The receipt, grant and execution receipt verify in Python or
TypeScript against the same vectors; the evidence log, the witness, plans
and the older formats verify in Python.

A held call is approved against the state it was shown in. Before asking
for the receipt the middleware hashes the target (a file's bytes, or its
absence); the issuer binds that hash into the signed receipt; the console
shows the proposed content as a diff against that state; after the human
signs, the middleware hashes the target again and refuses if it moved; and
the execution receipt carries the state before and after. An approval
cannot be redirected by changing the file under it, and an audit shows not
only that a write ran but what it changed. An approved change can be
undone the same way: the middleware keeps what a held write replaced and
offers `gargoyle_revert`, which composes the restoring write and sends it
through the gate, held, shown as a diff, bound to the current state, and
refused if anything changed since. The audit marks a revert from the
state hashes alone. Every entry also names the MCP client that asked, from
its initialize handshake, so a fleet with Claude on some desks and ChatGPT
on others still has one trail that says who, through what, did what. The
receipt itself stays model-agnostic.

The evidence is the workstation's own statement, and the workstation
belongs to its user. So the issuer keeps a witness: a signed, hash-chained
record of every receipt it issued and every grant it accepted, on the
operator's server. `gargoyle audit --witness` reconciles the two by
decision id and names what does not agree: a receipt the issuer never
issued, a held call honored without a grant the issuer saw, a receipt
issued with no evidence recorded. `--check-tree` hashes the gated folder
against the evidence's recorded states and names any file changed around
the gate. On a machine the user administers the gate constrains the
assistant, not the user; these two checks make the difference visible.

The MCP middleware also keeps an evidence log: one hash-chained line per
decision, refusals and declined holds included, so the trail answers "what
did the agent try" as well as "what did it do". `gargoyle audit --log`
verifies every entry and the chain, and prints the tail hash to note down
so a later copy that lost its end is caught (SPEC.md section 15).

## Where it sits

MCP gateways (TrueFoundry, Monosign, hoop.dev, Akto and others) hold a
tool call, notify a reviewer and log the click. Gargoyle is not a gateway.
It runs beside the client, and its approval is a signature made with a key
the issuer never holds, checked at execution and again by anyone later. In
2026 three Internet-Drafts describe parts of the same shape: Acta signed
receipts (an access decision, signed), EP authorization receipts (a human's
pre-execution signoff), XAIP receipts (a signed execution record). Gargoyle
chains all three on one decision id with the policy version inside, uses
the same RFC 8785 canonical form they do, and SPEC.md section 16 maps every
field. A hold can also be announced to Slack or any webhook
(`GARGOYLE_HOLD_WEBHOOK_URL`); the notice carries no key, so nothing in a
chat channel can approve anything.

## Deploy it

    pip install gargoyle-receipts

Three commands, no policy engine, no containers, no client changes:

    gargoyle init /path/the/agent/may/touch     # keys, config, rules.json
    gargoyle issuer                             # the issuing service, on rules.json
    gargoyle approve --watch 2                  # where the approver sits (terminal)

or approve in a browser: open the issuer's `/approve` page and load
`approver-web.json`, or, with Entra configured, sign in with Microsoft;
the page shows each held call with its full arguments, checked against
the receipt, and signs the grant locally with WebCrypto. The key never
leaves the browser, and with Entra it is generated there, non-exportable,
and enrolled under the approver's UPN, so grants and audits name the
person. An approver retires a lost or replaced key with
`POST /approvers/revoke` from their own sign-in; the operator revokes
anyone with `gargoyle approvers revoke <upn>` on the issuer's host, and
the running service picks the change up without a restart. Revoked keys
stay on file so earlier grants still audit; new ones are refused at the
issuer and at every middleware on its next held call. Revocation retires
a key, not a person: while the Approver role stands, the person can sign
in and enroll a fresh key, so remove the role too. Approvers, and
only approvers, see the whole queue and the witness; everyone else sees
their own holds. Then paste the server entry from
`gargoyle-deploy/mcp-config.json` into your MCP client.
[docs/guide-hyperv-ubuntu-apache.md](docs/guide-hyperv-ubuntu-apache.md)
is the full single-instance build: Ubuntu VM on Hyper-V, Apache with TLS,
a Windows 11 client running Claude Code. Reads are free, writes block until the approver's key
signs, deletes are refused; the policy is a JSON rules file you edit. A
hold can demand more than one signature: `"approvals": 2` on a rule, with
an optional `"approvers": [...]` naming which keys count, puts the terms
in the receipt itself, and `gargoyle init --approvers 2` creates the keys.
Every honored call comes back with receipt, grants and execution receipt,
and `gargoyle audit` verifies them later offline.
[examples/filesystem-agent](examples/filesystem-agent/) walks through it,
and through the alternative with OPA in Docker for sites that run a policy
engine.

## Scoped grants

One card per held call is right for a mailbox rule and wrong for a long
task. The assistant can ask for a plan (`gargoyle_plan`): a list of steps,
each a tool with exact arguments or argument patterns, and a note saying
why. The issuer judges every step under the policy, signs the plan, and
holds it as one card; the approver signs once; each later call matching
an unused step runs without a card of its own until the plan expires.
Every step is still bound, claimed once, and recorded with the plan and
step that released it. The rules file decides what may be planned
(`"plan": false` keeps a tool individual; sends should be), because a
plan approves scope rather than content.

## Microsoft 365 and other targets: adapters

What a held call changes is the adapter's business (`gargoyle.adapters`):
it describes the target's state before and after, tells the approver what
the call means in plain words, and composes the call that undoes it. Files
on the executor's host are the default. `GARGOYLE_MCP_STATE_PROBE=graph`
selects the Graph adapter for a Microsoft Graph MCP server: inbox rules,
calendar events, contacts and Teams membership are bound to their state,
explained on the card ("creates inbox rule 'Fwd invoices' (to an outside
address: x@evil.example)"), undone by the inverse Graph call, and a send
is marked as something that cannot be undone. The adapter reads state
through the upstream server itself, so the gate needs no Graph credential
of its own. Which tool is which is a JSON spec; the reference naming is in
`gargoyle/specs/graph-reference.json`, and a different server's names are
mapped there, not in code.

## Remote mode

Claude's hosted connectors (claude.ai in the browser, Claude Desktop's
custom connectors) and Microsoft 365 servers are reached over HTTPS, not
through a local process. `gargoyle remote` runs the same gate as a
Streamable HTTP MCP server in front of a stdio command or a remote MCP
server (`--upstream-url`), so those paths go through it too:

    gargoyle remote-token --out gargoyle-deploy --principal dana@contoso.com --url https://gargoyle.lan:8444
    gargoyle remote --out gargoyle-deploy --port 8444 --ssl-certfile ... --ssl-keyfile ... -- python -m gargoyle.fs_server /srv/shared

Each person gets a capability URL (`/mcp/<token>`) that names them on
every receipt; the operator vouches for that mapping, as with an API key,
because a hosted connector cannot carry the user's own Entra token.
Treat the URL as a credential. All sessions share one upstream, one replay
cache, one evidence log and one snapshot store, so single use and undo
hold across users. Device-bound identity remains the stdio mode's
property.

## The shipped consumer

**MCP middleware** (`python -m gargoyle.mcp_server -- <upstream command>`):
a stdio MCP server you put in front of any other stdio MCP server. The
handshake, `tools/list` and everything else are relayed. A `tools/call` is
forwarded only when `params._meta["gargoyle/envelope"]` carries a valid
receipt for that tool, those arguments and the principal the server serves
(and `params._meta["gargoyle/grant"]` a grant, when the receipt is
flagged); a refused call is answered here and never reaches the upstream.
Without an upstream command it runs a built-in demo executor. With
`GARGOYLE_MCP_ISSUER_URL` and `GARGOYLE_MCP_CLIENT_TOKEN` it obtains a
receipt from the issuing service for any call that carries none, and
waits for the human's grant when the call is flagged, so clients that
cannot attach receipts work unchanged. Configuration is by environment:

| Variable | Meaning |
|---|---|
| `GARGOYLE_MCP_GATE_KEY_ID`, `GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX` | the pinned issuer key |
| `GARGOYLE_MCP_TARGET_ID` | the target identity receipts bind to |
| `GARGOYLE_MCP_PRINCIPAL` | the client this server serves |
| `GARGOYLE_MCP_RECORD_PATH` | the published policy record |
| `GARGOYLE_MCP_APPROVER_KEY_ID`, `GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX` | the approver keys whose grants release flagged calls (optional, both or neither; comma-separated lists for several) |
| `GARGOYLE_MCP_EXECUTOR_KEY_ID`, `GARGOYLE_MCP_EXECUTOR_KEY_HEX` | this server's own signing key, so honored calls carry an execution receipt in `_meta["gargoyle/execution"]` (optional, both or neither) |
| `GARGOYLE_MCP_ISSUER_URL`, `GARGOYLE_MCP_CLIENT_TOKEN` | self-issue mode: the issuing service and the identity token (whose subject is this server's principal) to obtain receipts with; `GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS` and `GARGOYLE_MCP_POLL_SECONDS` tune the wait for a grant |
| issuer `GARGOYLE_ISSUER_AUDIENCE` | the `aud` an identity token must carry; a comma-separated list accepts several, so init-minted tokens (`gargoyle-issuer`) and a tenant's tokens (the issuer app's client id) work side by side |
| `GARGOYLE_MCP_ENTRA_TENANT`, `_CLIENT_ID`, `_SCOPE`, `_TOKEN_CACHE` | instead of a fixed client token: the user's own Entra ID token, written by `gargoyle login` (device code, MSAL cache, silent refresh); the principal is their UPN. No usable token refuses `REF_TARGET_LOGIN_REQUIRED` |
| issuer `GARGOYLE_ENTRA_CLIENT_ID`, `GARGOYLE_ENTRA_SCOPE` | lets the console sign approvers in with Entra (code flow with PKCE, no library); the browser generates a non-exportable key and enrolls it under the UPN |
| issuer `GARGOYLE_APPROVERS_PATH`, `GARGOYLE_APPROVER_ROLE`, `GARGOYLE_APPROVER_GROUPS` | where enrolled approvers persist (default `approvers.json` beside the keys, with a `revoked` list; `gargoyle approvers list|revoke`) and which Entra app role (default `Approver`) or groups may enroll, see every hold and the witness |
| issuer `GARGOYLE_ENTRA_TENANT` + `GARGOYLE_ISSUER_AUDIENCE` | trust the tenant's tokens; the audience is required with a tenant (the service will not start without it), and a directory token for any other tenant is `REF_IDENTITY_WRONG_TENANT` |
| issuer `GARGOYLE_HOLDS_PATH` | SQLite file for holds, grants, declines and plans, so a restart loses nothing a person is acting on (`gargoyle issuer` sets `holds.sqlite` beside the keys); `GET /health` reports it |
| issuer `GARGOYLE_MAX_OPEN_HOLDS` | how many held receipts and plans one principal may have waiting at once (default 20); the call over the cap is `REF_ISSUER_TOO_MANY_HOLDS` and nothing is stored |
| issuer `GARGOYLE_WITNESS_PATH` | the issuer's signed, hash-chained record of every decision (`gargoyle issuer` sets `witness.jsonl` beside the keys); `gargoyle audit --witness` reconciles a client's evidence against it, `--check-tree DIR` finds files changed outside the gate |
| issuer `GARGOYLE_LOG_JSON` | one JSON line per decision on stderr: issued, refused, granted, declined, plan, enrolled |
| `GARGOYLE_HOLD_WEBHOOK_URL`, `GARGOYLE_APPROVE_URL` | issuer: POST a notice of every new hold (Slack incoming-webhook shape, `text` plus the hold) with a link to the console; notice only, the grant still needs the approver's key |
| `GARGOYLE_MCP_INSTRUCTIONS` | replaces the standing instructions the gate hands the model in the MCP handshake (default: all work on the target goes through these tools, a wait is normal, a refusal is final, plans and undo exist); the user never has to name the server |
| `GARGOYLE_MCP_STATE_PROBE` | `filesystem` (default) binds a held file write to the file's current state: the approver sees the change as a diff, the call refuses if the file moved before the run (`REF_VERIFY_STATE_MISMATCH`), and the execution receipt records pre and post state; `none` disables |
| `GARGOYLE_MCP_ADAPTER_SPEC` | with `GARGOYLE_MCP_STATE_PROBE=graph`: the tool-to-resource mapping JSON (default: the reference naming) |
| `GARGOYLE_MCP_UPSTREAM_URL`, `GARGOYLE_MCP_UPSTREAM_TOKEN` | remote mode: the MCP server to front over Streamable HTTP, and its bearer |
| `GARGOYLE_MCP_SNAPSHOT_DIR` | where the bytes a held, state-bound write replaces are kept (default `snapshots/` beside the audit log; `none` disables undo); the middleware then offers a `gargoyle_revert` tool that restores an approved change through the gate, held and state-bound like any write |
| `GARGOYLE_MCP_AUDIT_LOG` | the evidence log: every decision, honored or refused, as one hash-chained JSON line with its receipt, grant and execution receipt; `gargoyle audit --log` verifies the file |

**Issuing service** (`gargoyle.issuer_service`, run with uvicorn from
`app_from_env()`): identity token in, receipt out, with the hold and grant
exchange for flagged calls (`/issue`, `/pending`, `/grants`, `/decline`,
`/record`, `/keys`) and the browser approval console at `/approve`. Policy
from a rules file or OPA; identity from a pinned key or, with
`GARGOYLE_ENTRA_TENANT`, the tenant's signing keys (both at once when a
pinned key is also set, so init-minted approver tokens keep working while
users move to `gargoyle login`).


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
| `policy` | the decision interface |
| `opa` | the Open Policy Agent adapter |
| `rules` | a policy from a JSON rules file, for sites without an engine |
| `cli` | the `gargoyle` command: init, issuer, approve, audit |
| `issuer` | ask the policy, sign the receipt |
| `identity` | the issuer's identity input: bearer, delegation and transaction tokens to principal and on_behalf_of |
| `jws` | the receipt as a JWS any JWT library verifies |
| `envelope` | receipt construction, hash region, signature region, currency check |
| `verifier` | the pure target-side check and every refusal code |
| `consumer` | `Consumer` (pin, keys, verify, claim, attest) and the reference HTTP target |
| `execution` | execution receipts and the offline chain check |
| `evidence` | the executor's hash-chained log of every decision, and its offline verifier |
| `mcp_server` | the stdio MCP middleware (and demo executor), with self-issue mode |
| `fs_server` | a small Python filesystem MCP server, for clients without Node |
| `issuer_service` | the HTTP issuing service: identity in, receipts out, holds and grants |
| `replay_cache`, `pending_store` | single use for receipts and holds; in-memory or Redis |
| `approval`, `approver_cli`, `approver_trust` | grants, the human's tool, approver key trust |
| `published_record_source` | the live policy pin as a publisher-signed record with serial and expiry |
| `key_record_source` | root-signed issuer and approver keys with windows and revocation |

## What Gargoyle does not do

- It does not decide. The policy does, and the receipt is only as good as
  that decision.
- It does not authenticate principals. The issuer and the target each
  authenticate the caller themselves (by default, the target trusts the
  client certificate its proxy verified); Gargoyle compares the two results.
- It cannot stop a caller that never asks for a receipt. Only a target that
  refuses unattested calls can.
- It does not distribute trust material. Issuer keys, record files, root
  keys and the client token are the deployer's to protect.
- The approval flow separates duties only if the approver's private key is
  out of the issuing service's reach. That is a deployment property.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
