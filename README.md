# Gargoyle

Signed, single-use, argument-bound receipts and human-approval holds for
agent tool calls.

[![PyPI](https://img.shields.io/pypi/v/gargoyle-receipts)](https://pypi.org/project/gargoyle-receipts/)
[![CI](https://github.com/Elyon-Sol/Gargoyle/actions/workflows/ci.yml/badge.svg)](https://github.com/Elyon-Sol/Gargoyle/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

An agent asks for permission to run a tool. Something you already trust
decides (OPA, Cedar, a JSON rules file, your own code). Gargoyle turns that
decision into a **receipt**: an Ed25519-signed record that names the tool,
a hash of its arguments, the principal the decision was made for, the
target it may be presented to, and the policy that decided. The target
checks the receipt before it acts, and honors it once. When the policy says
a call needs a human, the receipt is held until an approver signs a
**grant** for exactly that decision with a key the issuing service does not
have. After the call runs, the executor signs an **execution receipt** with
the state before and after. The three verify together, offline, with three
public keys.

Gargoyle does not decide whether a call is allowed. It makes an allow
decision portable, verifiable, bound to one call by one caller, and
spendable once, and it keeps a record of what was asked, what was released,
by whom, and what changed.

## Status

Pre-release `0.20.0.dev0` on PyPI as `gargoyle-receipts`. Wire format
`gargoyle/3`, evidence log `gargoyle-evidence/4`, witness
`gargoyle-witness/1`; all three are specified in [SPEC.md](SPEC.md) and may
still change before a first release.

**Run live, on the author's own tenant and hosts (2026-10-16 to 2026-11-01).**
One issuer host on Ubuntu behind Apache with TLS, Claude Code clients on
Windows 11 and on Linux, Claude Desktop on Windows 11, Entra ID for every
identity.
Exercised end to end and recorded in the witness: the receipt, grant and
execution chain with offline verification; state-bound approval and undo;
witness reconciliation and the tree check; Entra sign-in for submitters and
for approvers with browser-held, non-exportable approver keys, including a
lost key revoked and a new one enrolled; a hold routed to an Entra app role
and released under it; the Claude Code hook over Bash, Edit and Write;
discovery mode naming the side doors around the gate; declined holds with
the reason relayed to the assistant and a cooldown on retries; Windows
file-name canonicalization refusing names the OS would rewrite; and on the
issuer host, `gargoyle doctor`, `gargoyle rules` and `gargoyle backup` with
a verified `restore`.

**Built and tested, not yet run against a live counterpart.** Two-signature
(m-of-n) release with a deputy role; the Microsoft Graph adapter (tested
against a fake Graph server); the OAuth broker for hosted connectors
(deployed, metadata and redirect checks verified, no human sign-in through a
connector yet).

**Assurance.** 563 Python tests on Linux and Windows across Python 3.12,
3.13 and 3.14, at dependency floors and at a lock file; a TypeScript suite
that recomputes the conformance vectors byte for byte; two outside,
model-driven security reviews on 2026-10-20 (ten findings, all fixed); the
EMILIA Protocol's own verifiers accepting a live Gargoyle export unmodified,
and EMILIA's repository carrying the Gargoyle interop pack. No human has
reviewed the code independently of the model that wrote it. See
[SECURITY.md](SECURITY.md) and [ROADMAP.md](ROADMAP.md).

## How this was built

Gargoyle is designed and operated by one person with an operations and
security background and no software engineering background. The code,
tests and most of the prose were written by an AI model (Anthropic's
Claude) working under that person's direction: the design decisions, the
threat judgments, the deployments and the choice of what to build, remove
or publish are the author's; the implementation is the model's.

Read that as a limit on assurance. Nobody who can read this code deeply
has reviewed it independently of the model that wrote it. What stands
outside that loop is listed under Status above; the test suite and CI,
which the model also wrote, count for less. SECURITY.md says so and will
until it is false. If you are that reviewer, open an issue.

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
- **State binding.** A held write is bound to the target's current state.
  The approver sees the change as a diff against that state; the call is
  refused if the target moved before it ran; the execution receipt records
  the state before and after; an approved change can be undone through the
  gate the same way.
- **Proof of execution.** An executor with a key answers each honored call
  with a signed execution receipt: the decision it fulfilled, the policy
  version that allowed it, and a hash of the outputs. Receipt, grant and
  execution receipt verify together, offline, with three public keys.

That is the sentence Gargoyle can say: a specific policy version
authorized a specific call for a specific principal, a human's key
released it against a known state, and exactly that call ran once,
verifiable offline by anyone.

## Quick start: the gate in front of a filesystem MCP server

    pip install gargoyle-receipts

Three commands, no policy engine, no containers, no client changes:

    gargoyle init /path/the/agent/may/touch     # keys, config, rules.json
    gargoyle issuer                             # the issuing service, on rules.json
    gargoyle approve --watch 2                  # where the approver sits (terminal)

Then paste the server entry from `gargoyle-deploy/mcp-config.json` into
your MCP client. Reads are free, writes block until the approver's key
signs, deletes are refused; the policy is a JSON rules file you edit.
`gargoyle init --observe` starts a deployment in record-only mode instead:
every call allowed and recorded, nothing held, so a week of
`gargoyle audit --summary` is the input for the hold and deny rules.

Or approve in a browser: open the issuer's `/approve` page and load
`approver-web.json`, or, with Entra configured, sign in with Microsoft. The
console is described below.

[docs/guide-hyperv-ubuntu-apache.md](docs/guide-hyperv-ubuntu-apache.md)
is the full single-instance build: Ubuntu VM, Apache with TLS, a Windows 11
client running Claude Code. [docs/guide-production-entra.md](docs/guide-production-entra.md)
is the same for a Microsoft 365 tenant whose users are on Claude Desktop or
claude.ai. [examples/filesystem-agent](examples/filesystem-agent/) walks
through the gate with OPA in Docker for sites that run a policy engine.

### The `gargoyle` command

| Command | What it does | Where it runs |
|---|---|---|
| `gargoyle init DIR [--observe] [--approvers N] [--client claude-code]` | keys, tokens, rules file, service unit, Apache site, MCP entry | once, anywhere |
| `gargoyle issuer` | the issuing service: receipts, holds, grants, witness, console | the issuer host |
| `gargoyle approve --watch 2` | review and release held calls in a terminal | an approver's machine |
| `gargoyle login --tenant T --client-id C --scope S` | sign a workstation's user in with Entra ID; receipts then name them | each workstation |
| `gargoyle tokens --out DIR` | new client and approver tokens from the same keys | the issuer host |
| `gargoyle approvers list` / `revoke UPN` | the enrolled approver registry; a revoke is picked up without a restart | the issuer host |
| `gargoyle witness [--follow]` | the issuer's witness as a table | the issuer host |
| `gargoyle doctor --env middleware.env` | preflight a workstation's gate, one PASS/WARN/FAIL line per concern | each workstation |
| `gargoyle rules test` / `explain` / `lint` | what a rules file would do, before it is the policy | anywhere |
| `gargoyle sidedoors --env middleware.env [--report]` | list every other way into the gated files this host shows | each workstation |
| `gargoyle backup DIR` / `restore ARCHIVE` | the issuer host's state as one verified archive, and back | the issuer host |
| `gargoyle audit --log audit.jsonl [--witness witness.jsonl] [--check-tree DIR] [--summary]` | verify the evidence log, reconcile it against the witness, find files changed around the gate | anywhere, offline |
| `gargoyle emilia --log audit.jsonl` | export approved calls as EMILIA Trust Receipts | anywhere, offline |
| `gargoyle remote` / `remote-token` | the gate as an HTTPS MCP server for hosted connectors, and a person's capability URL for it | the gate host |
| `gargoyle hook --env middleware.env` | the Claude Code hook command (PreToolUse, PostToolUse) | each workstation, from settings |

## The approval console

The issuer serves a browser console at `/approve`. It shows each held call
with its full arguments, checked against the receipt, and signs the grant
locally with WebCrypto. Below the holds it shows the witness as
**Activity** (who asked, which tool, what the policy did), which is the
whole picture during an observe-mode week; every row opens its witness
entry.

**Keys and sign-in.** The approver's key never leaves the browser. With
Entra it is generated there, non-exportable, and enrolled under the
approver's UPN, so grants and audits name the person. One key per account:
a second browser does not enroll until the first key consents or the
operator revokes it. Every key an approver has held stays in
`approvers.json` (`history`), so an audit of grants released under an
earlier key still verifies; copy the issuer's current file beside the
evidence before auditing.

**Revocation.** An approver retires a lost or replaced key with
`POST /approvers/revoke` from their own sign-in; the operator revokes
anyone with `gargoyle approvers revoke <upn>` on the issuer's host, and the
running service picks the change up without a restart. Revoked keys stay
on file so earlier grants still audit; new grants under them are refused
at the issuer and at every middleware on its next held call. Revocation
retires a key, not a person: while the Approver role stands, the person can
sign in and enroll a fresh key, so remove the role too. The role is what
counts at release time: a grant under an enrolled key is accepted only from
that account, under a token that carries the role now, so a role removed in
the directory ends the power at once.

**Who sees what.** Approvers, and only approvers, see the whole queue and
the witness; everyone else sees their own holds.

**More than one signature.** `"approvals": 2` on a rule, with an optional
`"approvers": [...]` naming which keys count, puts the terms in the receipt
itself, and `gargoyle init --approvers 2` creates the keys.

**Routing by role.** `"approver_roles": ["Approver.Business"]` on a rule
means only a sign-in whose Entra app roles include that one may release
the hold; the issuer attests the role on the grant and the executor refuses
a grant without the attestation. Routing is what keeps approvals rare for
the person who should see few.

**Three views of one hold.** The console renders every hold three ways for
the same signature. The technical view shows tool, raw arguments, hashes,
pin and the diff. The deputy and business views lead with the issuer's
one-line description of the change (`Replace the contents of plan.md in
/srv/clients/acme (412 bytes -> 530 bytes; +4/-1 lines)`), the change as
before and after lines, who asked and how long is left, with the technical
details one click away. The sentence is computed in the issuer from the
held arguments and the bound state (`gargoyle.holdtext`), never authored;
a hold no template can describe is offered to the business view read-only.
The view follows the sign-in's role (`Approver.Deputy`, `Approver.Business`;
plain `Approver` and key files get the technical view) and can be switched.
The business view hides holds routed to other roles and the activity
stream; its status line says how many holds the person released this week
and which tool most of them were, the prompt to add a rule or a scoped
grant instead. The rendering never changes what is signed.

**Notice.** A hold can be announced to Slack or any webhook
(`GARGOYLE_HOLD_WEBHOOK_URL`); the notice carries no key, so nothing in a
chat channel can approve anything.

## Claude Code's own tools: the hook

Claude Code's Bash, Edit, Write and the MCP tools it calls directly do not
pass through an MCP server the gate can front. They do pass through Claude
Code's hooks, and `gargoyle hook` is one:

    gargoyle init /path/the/agent/works/in --client claude-code   # rules for Write/Edit/Bash, claude-settings.json
    gargoyle hook --env middleware.env [--final]                  # the hook command (PreToolUse, PostToolUse)

Same issuer, receipts, holds, approvers and evidence log as the MCP gate;
the approver sees the shell command or the file content, a held Write is
bound to the file's state, the refusal reaches Claude by name. Deploy the
hook from managed settings for a fleet. It covers Claude Code only, and it
is evidence rather than containment where the user owns the workstation: a
line typed with the `!` prefix runs in the user's shell with no hook at all
(verified 2026-10-31), and no setting changes that.
[docs/claude-code-hook.md](docs/claude-code-hook.md) has the setup and the
limits.

## Rules before they are the policy: `gargoyle rules`

First match wins, so a rule one line too late never fires; a glob written
for `path` never sees `move_file`, which sends `source` and `destination`;
a role name typed once wrong routes a hold to nobody. Three commands answer
such questions from the file alone, with the issuer's own `decide_rules`:

    gargoyle rules explain --rules rules.json --tool move_file --arg destination=/x/run.ps1   # every rule, matched or why not
    gargoyle rules test --rules rules.json --calls calls.jsonl --roles Approver,Approver.Business  # one row per call vs `expect`, then lint
    gargoyle rules lint --rules rules.json          # UNREACHABLE, ARG_KEY_UNKNOWN, ROLE_UNKNOWN

`examples/rules/` holds a Windows observe-mode pilot's rules and the
fourteen calls it decided live, as a `calls.jsonl` the suite runs. The
matching model is one page: [docs/rules.md](docs/rules.md).

## Preflight: `gargoyle doctor`

A gate that fails closed looks broken to the person installing it. The
first tenant's install lost an afternoon to four things, none of them in
the gate: the submitter's Entra token could not be refreshed (the API's
enterprise application had "Assignment required" on), the console's
browser key was no longer the one enrolled, Claude Code's own auto-mode
classifier refused the gate's write before the gate saw it, and the
workstation's endpoint protection flagged the signed Claude Code binary.
The doctor reads the same `middleware.env` the gate reads and says, per
concern, PASS, WARN or FAIL with the one fix that applies:

    gargoyle doctor --env C:\gargoyle\middleware.env      # Windows workstation (the installer runs it last)
    gargoyle doctor --env ~/.gargoyle/hook/middleware.env  # a hook host
    gargoyle doctor --env middleware.env --json            # for a script

Checks, in the order a person debugs: the env file is complete and
private; the CA bundle names the issuer's host and has not expired; the
issuer answers `/health` through Python's trust; the clock is within a
minute of the issuer's; the rules pin the gate will enforce is the one the
issuer runs; the submitter gets a token silently, now, as the named user
(an `AADSTS50105` is translated into the Entra setting that causes it); the
state root exists and does not hold the client's own state; the evidence
log and snapshot folder are writable and discovery is not overdue; Claude
Code's layers are right (side doors denied by managed settings or hooked,
the gate's MCP tools allowed by rule, the hook registered with this env
file); and Node, where present, trusts the issuer too. It ends with the
note the installer needs before the EDR alert arrives. Exit 0 when nothing
fails. It changes nothing and sends nothing but two GETs and one silent
token refresh.

## Side doors: discovery mode

A gate stands in front of one tool server. The files behind it can still be
reached around it: a second MCP server in a client's config serving the same
folder without the gate, Claude Code's own Write and Bash with no hook, a
project `.mcp.json` anyone who writes the folder can extend, a managed MCP
file that is not exclusive, a share that exports the folder, a
world-writable folder, a symlink that lands outside it, a gated file
changed with no evidence entry, a script written through the gate that a
person then runs outside it, Claude Code's `!` prefix, and a client's own
state folder (`.claude/`) kept inside the gated root. None of these is an
attack; all of them are what an audit of the evidence log cannot see. The
gate looks for them itself (`gargoyle.sidedoors`):

    gargoyle sidedoors --env middleware.env            # list them now; exit 1 when any are found
    gargoyle sidedoors --env middleware.env --report   # also write audit.sidedoors.json and tell the issuer

The MCP gate takes the same look at startup and the hook on its next run,
whenever the last report beside the evidence log is older than
`GARGOYLE_MCP_DISCOVERY_HOURS` (default 24; `0` disables). Findings go
beside the evidence log with the time each was first seen, and to the
issuer (`POST /sidedoors`), whose witness records them, so they show in the
console's Activity and in `gargoyle audit --summary`. Each finding names a
remedy. Discovery is notice, never admission: nothing is held or refused on
it.

## Evidence, witness and audit

The MCP middleware and the hook keep an evidence log: one hash-chained line
per decision, refusals and declined holds included, so the trail answers
"what did the agent try" as well as "what did it do". Every entry names the
MCP client that asked, from its initialize handshake, so a fleet with
Claude on some desks and another client on others still has one trail. The
replay claims that make a receipt single-use live beside the log in SQLite,
so a restarted gate still refuses a receipt it honored.

The evidence is the workstation's own statement, and the workstation
belongs to its user. So the issuer keeps a witness: a signed, hash-chained
record of every receipt it issued, every grant it accepted, every decline,
enrollment, revocation and discovery report, on the operator's server.

    gargoyle audit --log audit.jsonl                                   # verify every entry and the chain; prints the tail hash to note down
    gargoyle audit --log audit.jsonl --witness witness.jsonl           # reconcile by decision id: unwitnessed receipts, releases without a grant, missing evidence
    gargoyle audit --log audit.jsonl --check-tree /srv/shared          # hash the gated folder against the recorded states; name files changed around the gate
    gargoyle audit --log audit.jsonl --summary                         # calls by principal and tool, side-door findings
    gargoyle audit --log audit.jsonl --issuer https://gargoyle.lan      # take the issuer's keys and every approver key it has seen from the issuer, not from a copied file

The audit needs the public keys (`public-keys.json`, by default beside the
log or in `--out`). Grants verify against every key an approver has held,
so an approver who re-enrolled a browser key is still audited; with
`--issuer` that list comes from the issuer itself and a stale copy of
`approvers.json` can no longer fail a valid grant.

On a machine the user administers the gate constrains the assistant, not
the user; these checks make the difference visible. SPEC.md section 15
specifies the log, the witness and every reconciliation finding.

A held call is approved against the state it was shown in. Before asking
for the receipt the middleware hashes the target (a file's bytes, or its
absence); the issuer binds that hash into the signed receipt; the console
shows the proposed content as a diff against that state; after the human
signs, the middleware hashes the target again and refuses if it moved; and
the execution receipt carries the state before and after. An approved
change can be undone the same way: the middleware keeps what a held write
replaced and offers `gargoyle_revert`, which composes the restoring write
and sends it through the gate, held, shown as a diff, bound to the current
state, and refused if anything changed since. The audit marks a revert
from the state hashes alone.

## Backup and restore

Everything on the issuer host that cannot be regenerated (the hold store,
the witness, the keys, the rules, the enrolled approvers, the remote
gates' state) goes into one archive named with the witness head:

    gargoyle backup /var/backups/gargoyle          # on the issuer host, as root
    gargoyle restore --verify-only ARCHIVE         # check it against the running state; writes nothing
    gargoyle restore ARCHIVE --opt /opt/gargoyle   # put it back; services stopped first

A backup refuses to run if it cannot read every secret it should contain,
and writes nothing. `restore --verify-only` verifies the witness chain and
the hold store's integrity inside the archive. [docs/operations.md](docs/operations.md) says what the archive holds,
how to schedule it, and what a restart does to work in flight.

## Scoped grants

One card per held call is right for a mailbox rule and wrong for a long
task. The assistant can ask for a plan (`gargoyle_plan`): a list of steps,
each a tool with exact arguments or argument patterns, and a note saying
why. The issuer judges every step under the policy, signs the plan, and
holds it as one card; the approver signs once; each later call matching an
unused step runs without a card of its own until the plan expires. Every
step is still bound, claimed once, and recorded with the plan and step that
released it. The rules file decides what may be planned (`"plan": false`
keeps a tool individual; sends should be), because a plan approves scope
rather than content.

## Microsoft 365 and other targets: adapters

What a held call changes is the adapter's business (`gargoyle.adapters`):
it describes the target's state before and after, tells the approver what
the call means in plain words, and composes the call that undoes it. Files
on the executor's host are the default. `GARGOYLE_MCP_STATE_PROBE=graph`
selects the Graph adapter for a Microsoft Graph MCP server: inbox rules,
calendar events, contacts and Teams membership are bound to their state,
explained on the card ("creates inbox rule 'Fwd invoices' (to an outside
address: x@evil.example)"), undone by the inverse Graph call, and a send is
marked as something that cannot be undone. The adapter reads state through
the upstream server itself, so the gate needs no Graph credential of its
own. Which tool is which is a JSON spec; the reference naming is in
`gargoyle/specs/graph-reference.json`, and a different server's names are
mapped there, not in code. The Graph adapter is tested against a fake
Graph server and has not yet run against a tenant's mailbox.

## Remote mode

Claude's hosted connectors (claude.ai in the browser, Claude Desktop's
custom connectors) and Microsoft 365 servers are reached over HTTPS, not
through a local process. `gargoyle remote` runs the same gate as a
Streamable HTTP MCP server in front of a stdio command or a remote MCP
server (`--upstream-url`), so those paths go through it too:

    gargoyle remote-token --out gargoyle-deploy --principal dana@contoso.com --url https://gargoyle.lan:8444
    gargoyle remote --out gargoyle-deploy --port 8444 --ssl-certfile ... --ssl-keyfile ... -- python -m gargoyle.fs_server /srv/shared

With Entra, the connector signs the user in: set `GARGOYLE_OAUTH_BASE_URL`
(and the gate's own app registration, `GARGOYLE_OAUTH_ENTRA_CLIENT_ID` /
`_CLIENT_SECRET`) and the gate is the OAuth authorization server the hosted
client expects (metadata, dynamic registration, code flow with PKCE) while
the sign-in itself happens at the tenant, under its MFA and Conditional
Access. The gate then presents the user's own Entra token to the issuer,
refreshed silently, and the receipt's principal is their UPN; the session
ends when the tenant refuses the refresh (`gargoyle.oauth_broker`,
[docs/guide-production-entra.md](docs/guide-production-entra.md)). Without
a directory, each person gets a capability URL (`/mcp/<token>`) from
`gargoyle remote-token` that names them on every receipt; the operator
vouches for that mapping, as with an API key, so treat the URL as a
credential. All sessions share one upstream, one replay cache, one evidence
log and one snapshot store, so single use and undo hold across users.
Device-bound identity remains the stdio mode's property.

## Where it sits

MCP gateways hold a tool call, notify a reviewer and log the click.
Gargoyle is not a gateway. It runs beside the client, and its approval is a
signature made with a key the issuer never holds, checked at execution and
again by anyone later. In 2026 several Internet-Drafts describe parts of
the same shape: Acta signed receipts (an access decision, signed), EP
authorization receipts (a human's pre-execution signoff), XAIP receipts (a
signed execution record). Gargoyle chains all three on one decision id with
the policy version inside, uses the same RFC 8785 canonical form they do,
and SPEC.md section 16 maps every field.
[docs/comparison-2026-10-20.md](docs/comparison-2026-10-20.md) scores
Gargoyle against its nearest peers from their primary sources;
[docs/interop-emilia.md](docs/interop-emilia.md) records the EMILIA
interoperation, in both directions.

## Using the library

### Issuing a receipt

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
    hold(result.envelope)            # the issuing service does this for you
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
first matching rule wins, globs on tool name, principal, delegation, the
caller's groups and roles, and string arguments; actions allow, hold or
deny; a hold may name `approvals`, `approvers` and `approver_roles`.
Argument globs that look like paths are matched on a normalized form
(separators, `..`, letter case, and on Windows the name the OS would
actually open), so a rule for one folder is not slipped by traversal or
spelling; `*` spans folders. The pin is the file's hash, so an edit
invalidates outstanding receipts exactly as an engine change does. This is
what `gargoyle init` sets up and `gargoyle rules` tests.

### Checking a receipt

Every executor runs the same check: establish the live policy pin,
establish the trusted issuer keys, verify the receipt against the call it
is about to run, claim the `decision_id`. `gargoyle.consumer.Consumer`
packages it.

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
trust, and the verifier refuses to run without it, so an unsigned receipt
is never honored. For a flagged receipt, pass the human's grant as
`grant=`; the consumer verifies it against the receipt's own decision and
hold, claims it once, and only then claims the receipt.

For a live pin that can be reissued, give the consumer a record source (a
publisher-signed record with a serial and an expiry) instead of a static
pin; for issuer keys that can be rotated and revoked, a key record source.
Both are consulted on every check and fail closed.

### Proof that it ran

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

The receipt, grant and execution receipt verify in Python or TypeScript
against the same vectors; the evidence log, the witness, plans and the
older formats verify in Python.

### Approval holds without the issuing service

When the policy's decision carries `requires_approval`, the receipt is
issued with `requires_approval: true` and a signed `approval_request_id`.
No target will run it on its own: the consumer demands a grant for exactly
that decision and hold, verifies it (provenance, separation of duties,
binding, expiry), claims it once, and only then claims the receipt. A human
can run `gargoyle-approver` on a machine that holds the approver private
key; given the receipt it shows the tool, argument hash, principal, target
and policy that are inside the issuer's signature, and emits the grant.
Approver keys should come from a signed key record where the key's role is
`approver` (`gargoyle.approver_trust`), so an issuer-controlled key can
never approve.

## The shipped consumer and its configuration

**MCP middleware** (`python -m gargoyle.mcp_server -- <upstream command>`):
a stdio MCP server you put in front of any other stdio MCP server. The
handshake, `tools/list` and everything else are relayed. A `tools/call` is
forwarded only when `params._meta["gargoyle/envelope"]` carries a valid
receipt for that tool, those arguments and the principal the server serves
(and `params._meta["gargoyle/grant"]` a grant, when the receipt is
flagged); a refused call is answered here and never reaches the upstream.
`--env FILE` before the `--` reads the settings below from a `KEY=VALUE`
file (variables already in the environment win), so an MCP entry that
every local user can read, such as Claude Code's managed
`managed-mcp.json`, names `middleware.env` instead of carrying the executor
key. With `GARGOYLE_MCP_ISSUER_URL` and an identity it obtains a receipt
from the issuing service for any call that carries none, and waits for the
human's grant when the call is flagged, so clients that cannot attach
receipts work unchanged. Configuration is by environment:

| Variable | Meaning |
|---|---|
| `GARGOYLE_MCP_GATE_KEY_ID`, `GARGOYLE_MCP_GATE_PUBLIC_KEY_HEX` | the pinned issuer key |
| `GARGOYLE_MCP_TARGET_ID` | the target identity receipts bind to |
| `GARGOYLE_MCP_PRINCIPAL` | the client this server serves |
| `GARGOYLE_MCP_RECORD_PATH`, `GARGOYLE_MCP_RECORD_URL` | the live policy pin: a file copied out of band, or (what `init` sets) the issuer's signed record at `<issuer>/record`, followed live and cached a minute, so a rule change reaches every gate without a copy or a restart |
| `GARGOYLE_MCP_APPROVER_KEY_ID`, `GARGOYLE_MCP_APPROVER_PUBLIC_KEY_HEX` | the approver keys whose grants release flagged calls (optional, both or neither; comma-separated lists for several) |
| `GARGOYLE_MCP_EXECUTOR_KEY_ID`, `GARGOYLE_MCP_EXECUTOR_KEY_HEX` | this server's own signing key, so honored calls carry an execution receipt in `_meta["gargoyle/execution"]` (optional, both or neither) |
| `GARGOYLE_MCP_ISSUER_URL`, `GARGOYLE_MCP_CLIENT_TOKEN` | self-issue mode: the issuing service and the identity token (whose subject is this server's principal) to obtain receipts with; `GARGOYLE_MCP_APPROVAL_TIMEOUT_SECONDS` and `GARGOYLE_MCP_POLL_SECONDS` tune the wait for a grant |
| `GARGOYLE_MCP_ENTRA_TENANT`, `_CLIENT_ID`, `_SCOPE`, `_TOKEN_CACHE` | instead of a fixed client token: the user's own Entra ID token, written by `gargoyle login` (device code, MSAL cache, silent refresh); the principal is their UPN. No usable token refuses `REF_TARGET_LOGIN_REQUIRED` |
| `GARGOYLE_MCP_STATE_PROBE` | `filesystem` (default) binds a held file write to the file's current state: the approver sees the change as a diff, the call refuses if the file moved before the run (`REF_VERIFY_STATE_MISMATCH`), and the execution receipt records pre and post state; `graph` selects the Graph adapter; `none` disables |
| `GARGOYLE_MCP_STATE_ROOT` | the upstream's root: a relative path argument is made absolute against it before the rules, the gate-folder check, the state probe and the upstream see it, so all four look at the same file (default: the path in a `mcp://filesystem/` target id; `init` writes it). With no root, a relative path on a state-bound tool is refused with `REF_TARGET_RELATIVE_PATH`; a name Windows would rewrite (trailing dot or space, a stream suffix, a device name) with `REF_TARGET_PATH_NOT_CANONICAL`, and globs are matched against the canonical name too |
| `GARGOYLE_MCP_ADAPTER_SPEC` | with `GARGOYLE_MCP_STATE_PROBE=graph`: the tool-to-resource mapping JSON (default: the reference naming) |
| `GARGOYLE_MCP_SNAPSHOT_DIR` | where the bytes a held, state-bound write replaces are kept (default `snapshots/` beside the audit log; `none` disables undo); the middleware then offers a `gargoyle_revert` tool that restores an approved change through the gate, held and state-bound like any write |
| `GARGOYLE_MCP_AUDIT_LOG` | the evidence log: every decision, honored or refused, as one hash-chained JSON line with its receipt, grant and execution receipt; `gargoyle audit --log` verifies the file; the replay claims that make a receipt single-use live beside it in `<log stem>.replay.sqlite` |
| `GARGOYLE_MCP_DISCOVERY_HOURS` | how old the last side-door report may be before the gate looks again at startup or on the hook's next run (default 24; `0` disables) |
| `GARGOYLE_MCP_INSTRUCTIONS` | replaces the standing instructions the gate hands the model in the MCP handshake (default: all work on the target goes through these tools, a wait is normal, a refusal is final, plans and undo exist); the user never has to name the server |
| `GARGOYLE_MCP_UPSTREAM_URL`, `GARGOYLE_MCP_UPSTREAM_TOKEN` | remote mode: the MCP server to front over Streamable HTTP, and its bearer |
| remote gate `GARGOYLE_OAUTH_BASE_URL`, `_ENTRA_CLIENT_ID`, `_ENTRA_CLIENT_SECRET` (`_ENTRA_TENANT`, `_ENTRA_SCOPE`, `_REDIRECT_ALLOW`, `_ACCESS_TTL`) | the hosted connector signs the user in with Entra through the gate (RFC 8414/9728 metadata, RFC 7591 registration limited to the allowed callbacks, code flow with PKCE); the gate holds the user's Entra token for the issuer and refreshes it; sessions in `oauth-state.json` beside the gate's keys |

**Issuing service** (`gargoyle.issuer_service`, run with uvicorn from
`app_from_env()`, or `gargoyle issuer`): identity token in, receipt out,
with the hold and grant exchange for flagged calls (`/issue`, `/pending`,
`/grants`, `/decline`, `/record`, `/keys`, `/approvers`, `/approvers/audit`,
`/sidedoors`) and the browser
approval console at `/approve`. Policy from a rules file or OPA; identity
from a pinned key or, with `GARGOYLE_ENTRA_TENANT`, the tenant's signing
keys (both at once when a pinned key is also set).

| Variable | Meaning |
|---|---|
| `GARGOYLE_ISSUER_AUDIENCE` | the `aud` an identity token must carry; a comma-separated list accepts several, so init-minted tokens (`gargoyle-issuer`) and a tenant's tokens (the issuer app's client id) work side by side |
| `GARGOYLE_ENTRA_TENANT` + `GARGOYLE_ISSUER_AUDIENCE` | trust the tenant's tokens; the audience is required with a tenant (the service will not start without it), and a directory token for any other tenant is `REF_IDENTITY_WRONG_TENANT` |
| `GARGOYLE_ENTRA_CLIENT_ID`, `GARGOYLE_ENTRA_SCOPE` | lets the console sign approvers in with Entra (code flow with PKCE, no library); the browser generates a non-exportable key and enrolls it under the UPN |
| `GARGOYLE_APPROVERS_PATH`, `GARGOYLE_APPROVER_ROLE`, `GARGOYLE_APPROVER_GROUPS` | where enrolled approvers persist (default `approvers.json` beside the keys, with a `revoked` list, re-read when its content changes) and which Entra app role (default `Approver`) or groups may enroll, see every hold and the witness |
| `GARGOYLE_HOLDS_PATH` | SQLite file for holds, grants, declines and plans, so a restart loses nothing a person is acting on (`gargoyle issuer` sets `holds.sqlite` beside the keys); `GET /health` reports `persistent` |
| `GARGOYLE_MAX_OPEN_HOLDS` | how many held receipts and plans one principal may have waiting at once (default 20); the call over the cap is `REF_ISSUER_TOO_MANY_HOLDS` and nothing is stored |
| `GARGOYLE_ALLOW_SELF_APPROVAL` | `1` lets a person release their own call; by default the approver may be neither the hold's principal nor the party acted for (`REF_ISSUER_SELF_APPROVAL`). A grant for an expired hold is `REF_ISSUER_HOLD_EXPIRED` and the hold is dropped |
| `GARGOYLE_WITNESS_PATH` | the issuer's signed, hash-chained record of every decision (`gargoyle issuer` sets `witness.jsonl` beside the keys) |
| `GARGOYLE_HOLD_WEBHOOK_URL`, `GARGOYLE_APPROVE_URL` | POST a notice of every new hold (Slack incoming-webhook shape, `text` plus the hold) with a link to the console; notice only, the grant still needs the approver's key |
| `GARGOYLE_LOG_JSON` | one JSON line per decision on stderr: issued, refused, granted, declined, plan, enrolled, revoked, sidedoors |
| `GET /health` | public: `ok`, the policy pin, pending counts, approver counts, `entra`, `persistent`, `witness_head` (the chain's tail sequence and entry hash, so a client can tell it talks to the issuer whose witness it will later reconcile against), and the week's hold and release figures by tool and by role |

A declined hold carries the approver's reason back to the assistant
verbatim, and a principal whose same tool and path have been declined
repeatedly is refused with `REF_ISSUER_DECLINED_RECENTLY` and the earlier
reason, without a new card.

## Modules

| Module | Role |
|---|---|
| `policy`, `opa`, `rules`, `globs` | the decision interface; the OPA adapter; a policy from a JSON rules file; argument glob matching |
| `issuer`, `envelope`, `identity`, `jws` | ask the policy and sign; receipt construction and currency; identity tokens to principal and `on_behalf_of`; the receipt as a JWS |
| `verifier`, `consumer`, `execution` | the pure target-side check and every refusal code; `Consumer` (pin, keys, verify, claim, attest); execution receipts and the offline chain |
| `approval`, `approver_cli`, `approver_trust`, `approvers` | grants; the human's terminal tool; approver key trust; the enrolled-approver registry with history and revocation |
| `state`, `revert`, `adapters`, `holdtext` | state-bound approval; undo through the gate; what a call changes, per target type; the one-line description of a hold |
| `plans` | scoped grants: one approval for a bounded plan |
| `evidence`, `witness`, `reconcile` | the executor's hash-chained log; the issuer's signed witness; reconciliation and the tree check |
| `replay_cache`, `pending_store`, `holdstore` | single use for receipts and holds, in memory, SQLite or Redis; the issuer's persistent hold store |
| `mcp_server`, `remote`, `oauth_broker`, `fs_server` | the stdio middleware with self-issue mode; the gate as a Streamable HTTP server; Entra sign-in for hosted connectors; a Python filesystem MCP server |
| `claude_hook` | the same gate as a Claude Code hook over its own tools |
| `sidedoors` | discovery mode: every other way into the gated files this host shows |
| `issuer_service`, `entra_login`, `notify` | the HTTP issuing service and console; `gargoyle login`; the hold webhook |
| `doctor`, `rulecheck`, `operations` | `gargoyle doctor`; `gargoyle rules`; `gargoyle backup` and `restore` |
| `emilia`, `emilia_runner` | EMILIA Trust Receipt export and the EMILIA conformance runner |
| `published_record_source`, `key_record_source` | the live policy pin as a publisher-signed record; root-signed issuer and approver keys with windows and revocation |
| `cli` | the `gargoyle` command |

## Documentation

| Document | What it is for |
|---|---|
| [SPEC.md](SPEC.md) | the wire specification: receipt, grant, execution receipt, evidence log, witness, plans, JWS, relation to other receipt formats; every vector recomputed by the suite |
| [ROADMAP.md](ROADMAP.md) | what was built when, what was found live, and what is next |
| [SECURITY.md](SECURITY.md) | how to report a problem, what is in scope, what the design does not claim |
| [docs/guide-hyperv-ubuntu-apache.md](docs/guide-hyperv-ubuntu-apache.md) | the single-instance build, end to end, with troubleshooting |
| [docs/guide-production-entra.md](docs/guide-production-entra.md) | one tenant, one hosted gate, Entra ID as the control point |
| [docs/entra-setup.md](docs/entra-setup.md) | the two app registrations, app roles, and the settings that bite |
| [docs/claude-code-hook.md](docs/claude-code-hook.md) | the gate as a Claude Code hook, and its limits |
| [docs/rules.md](docs/rules.md) | how a call is decided by a rules file, on one page |
| [docs/operations.md](docs/operations.md) | what the issuer host holds, backup, restore, restart |
| [docs/beta-checklist.md](docs/beta-checklist.md) | a first client deployment: set up, tell people, watch, back out |
| [docs/scenario-client-workstation.md](docs/scenario-client-workstation.md) | the scenario the design answers (2026-10-16) |
| [docs/comparison-2026-10-20.md](docs/comparison-2026-10-20.md) | Gargoyle against its nearest peers, from primary sources |
| [docs/interop-emilia.md](docs/interop-emilia.md) | interoperation with the EMILIA Protocol, both directions |
| [docs/ally-design.md](docs/ally-design.md) | how Gargoyle fits beside governance runtimes and the receipt drafts |
| [ts/README.md](ts/README.md) | the TypeScript verifier and consumer |
| [examples/](examples/) | the gated filesystem agent with OPA; a live pilot's rules and the calls they decided |

## Install for development

    pip install -e ".[dev]"
    python -m pytest

Python 3.12 or later. The TypeScript verifier and consumer for Node 20+
lives in [ts/](ts/) (`cd ts && npm install && npm test`); its suite
recomputes the same conformance vectors byte for byte, so the two
implementations cannot drift apart silently. Redis is optional (`.[redis]`)
and only needed to share the replay cache and pending-approval set across
replicas of the remote gate; `.[entra]` adds MSAL for `gargoyle login`.

## What Gargoyle does not do

- It does not decide. The policy does, and the receipt is only as good as
  that decision.
- It does not authenticate principals. The issuer and the target each
  authenticate the caller themselves; Gargoyle compares the two results.
- It cannot stop a caller that never asks for a receipt. Only a target that
  refuses unattested calls can. On a workstation its user administers, the
  gate constrains the assistant, not the user; changes made around the gate
  are detected by reconciliation, the tree check and discovery, not
  prevented.
- It does not judge the change. The console proves the approver saw the
  exact arguments and the exact diff and signed; whether the change should
  happen is the approver's call.
- It does not distribute trust material. Issuer keys, record files, root
  keys and the client token are the deployer's to protect.
- The approval flow separates duties only if the approver's private key is
  out of the issuing service's reach. That is a deployment property; the
  browser console's non-exportable key is how the reference deployment
  meets it.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
