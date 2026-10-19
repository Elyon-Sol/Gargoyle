# Ally design concepts

Gargoyle proves; the toolkits beside it govern, notify or record. The
assessment of 2026-10-19 found three groups converging on the same shape:
signed-receipt protocols (NOA Receipt, the Acta, EP, XAIP and Vaara
drafts), governance runtimes (Microsoft's Agent Governance Toolkit, the
small MCP proxies) and approval layers (withHuman, awaithumans, Temporal
patterns). This note sets out how Gargoyle could work with each rather than
against it, in the order of least work for most reach. None of these
changes a byte of the receipt format.

## 1. Shared conformance corpus with NOA Receipt

NOA and Gargoyle both sign JCS-canonical records with Ed25519, chain
entries by hash, and verify offline. NOA's corpus has 21 attack vectors
and 9 malformed vectors checked across five verifiers; Gargoyle's has its
section 11 vectors checked across two. A joint corpus would give each
project the other's adversarial cases for free and give an outside
reader one place to see two independent implementations agree.

Concrete step: publish `tests/fixtures/wire_vectors.json` and the
gargoyle/2 historical fixture with a one-page reading guide, and offer to
run NOA's corpus through Gargoyle's verifier in CI. Where a NOA attack
vector has no Gargoyle analogue, add one. Cost: a day.

## 2. Evidence export in NOA's chain shape

NOA's receipt records agent, action (with `paramsHash`, `riskClass`,
`reversible`, `rollbackRef`), verdict, approval and a chain block. Every
Gargoyle evidence entry already carries the same facts: the decision, the
grant, the execution receipt with its state hashes, and the chain link. An
exporter that emits a NOA-shaped chain from a Gargoyle log, with each NOA
entry carrying the Gargoyle receipt as its attachment, lets a NOA verifier
accept Gargoyle evidence at NOA's level of assurance and lets a Gargoyle
verifier go further on the same record. The `reversible` and
`rollbackRef` fields map directly onto the undo mechanism; NOA defines
the fields and has no mechanism, which is the complement.

Concrete step: `gargoyle audit --export noa` writing a chain NOA's
`noa verify` accepts. Cost: two days, one of them reading NOA's spec.

## 3. Gargoyle as the proof layer under Microsoft's toolkit

AGT decides (YAML, OPA, Cedar), identifies agents, scores trust and logs a
hash chain. It does not sign receipts, bind a human's key to a release,
record execution against an authorization, or verify offline. Those are
Gargoyle's properties, and AGT's own post lists workflow-level policy and
intent declaration as roadmap items. The fit is a policy hook: AGT's
pre-execution check calls Gargoyle's issuer for the receipt, AGT's
approval requirement becomes a Gargoyle hold, and AGT's log entry carries
the Gargoyle receipt and execution receipt as attachments. AGT customers
keep their policy language and dashboards; the evidence underneath
becomes verifiable by anyone.

Concrete step: an AGT adapter package, the same size as the OPA adapter,
exposing Gargoyle as an AGT policy provider and an AGT audit sink. Cost:
a week, most of it AGT's preview APIs moving.

## 4. Approval layers as transport

withHuman, awaithumans and the Temporal pattern own the channels: Slack,
email, dashboards, durable resumption. Gargoyle owns the signature. The
webhook notice already posts a hold to any of them; the missing half is
the return path, where the approver's click in Slack becomes a Gargoyle
grant. That needs the approver's key on the approver's device, which a
chat client does not hold, so the honest integration is: notify through
their channel, sign in Gargoyle's console (one link in the message), and
let their dashboard show the state transitions from Gargoyle's evidence.
withHuman's open approval protocol (AAP) could carry the hold and the
console link as its payload.

Concrete step: a hold notice shaped for AAP and for Slack Block Kit with a
console deep link, and a `/holds/{id}` page the console opens directly on
one card. Cost: two days.

## 5. The standards drafts

Acta, EP, XAIP and Vaara each define one stage. SPEC.md section 16 maps
Gargoyle's fields to the first three. The useful offer to those authors
is a running implementation of all their stages in one chain, with
vectors, that they can cite as an existence proof for the combined
design; and, for EP specifically, a worked example of state binding
addressing the presentation-attack limit their draft names.

Concrete step: a short note to each draft's author with the section 16
table and a link to the live audit rows 36 and 37 (anonymised). Cost: an
afternoon, and the one step on this list that needs a person rather than
code.

## Order

1 and 5 first: they cost least and put Gargoyle in front of the readers
most likely to understand it. 2 next, because it makes NOA an ally with
one command. 3 when AGT leaves preview. 4 when a client asks for Slack.
