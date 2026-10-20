# Gargoyle against its nearest peers (2026-10-20)

Third comparison. The first (2026-10-16, 17 properties, vendor pages) put
ActionProxy nearest at 62% and named two properties nobody else had: a
receipt that dies when the policy changes, and a human grant as a separate
key verified at execution. The second (2026-10-19, 12 properties) added
NOA, Microsoft's Agent Governance Toolkit and Obsigno. Both were scored
from product pages. This one was scored from primary sources only: the
repositories, specs, Internet-Draft texts and official docs, read on
2026-10-20 by four independent readers, each quote recorded. Where a source
is silent the score is 0, so these are floors.

Scoring: 1 = the source shows the property; 0.5 = partial or implied;
0 = absent or not stated. "Core 6" is the subset that makes the thing a
security primitive rather than a workflow: rows 1 to 6.

## The property set (fixed; reuse it next time)

1. Signed artifact the executor verifies before running the call
2. Bound to the exact arguments (hash)
3. Bound to an authenticated directory identity (IdP subject), not an opaque id
4. Single use enforced at execution
5. Invalidated when the policy it was decided under changes (pin checked at execution)
6. Human approval is a separate approver-held key, verified at execution
7. Bound to tool name
8. Bound to a target or resource identifier
9. Expiry on the artifact
10. Decision from an external or pluggable policy engine
11. Approval terms (required, m-of-n, approver set) inside the signed artifact
12. Signed execution receipt bound to the authorization (same decision id)
13. State-bound approval: pre-state hash of the resource in the artifact
14. Undo through the gate, snapshots proven by hashes
15. Hash-chained evidence log including refusals
16. Independent witness: issuer log reconciled against executor log
17. Offline verification with published conformance vectors
18. Second-language verifier passing the same vectors
19. RFC 8785 canonical form and/or JWS
20. Key rotation and revocation via signed records
21. Enforcement at the execution point beside the client, not only a gateway
22. MCP middleware deployment (and whether HTTP exists)
23. Open source with a published wire spec

## Scores

Columns: Gy = Gargoyle 0.18.0.dev0; EM = EMILIA Protocol (I-D -13 plus
reference code); NOA = NOA Mandate Core; SG = Signet; AGT = Microsoft Agent
Governance Toolkit; AP = ActionProxy; OB = Obsigno; PoB = AgentLedger
Proof-of-Behavior I-D; AAE = sm-aae; TxT = Transaction Tokens for Agents
I-D; AWS = Bedrock AgentCore Policy/Gateway; DO = DigitalOcean Action
Gateway; HL = HumanLayer.

| # | Gy | EM | NOA | SG | AGT | AP | OB | PoB | AAE | TxT | AWS | DO | HL |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 1 | 0.5 | 0.5 | 0 | 0.5 | 0.5 | 1 | 0 | 0 | 0 |
| 2 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0.5 | 1 | 0 | 0.5 | 0.5 | 0.5 |
| 3 | 1 | 1 | 0 | 0 | 0.5 | 1 | 0 | 0.5 | 0 | 1 | 0.5 | 0.5 | 0 |
| 4 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| 5 | 1 | 1 | 0.5 | 0.5 | 1 | 1 | 0 | 0.5 | 0 | 0 | 0.5 | 0.5 | 0 |
| 6 | 1 | 1 | 1 | 0.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 7 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0.5 | 0.5 | 1 |
| 8 | 1 | 1 | 0.5 | 1 | 1 | 0.5 | 1 | 0 | 1 | 0.5 | 0.5 | 0 | 0 |
| 9 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0.5 | 0 |
| 10 | 1 | 0.5 | 1 | 1 | 1 | 1 | 1 | 1 | 0.5 | 0 | 1 | 0.5 | 0 |
| 11 | 1 | 1 | 0.5 | 0.5 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0.5 |
| 12 | 1 | 0.5 | 1 | 1 | 0.5 | 0.5 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0 |
| 13 | 1 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 14 | 1 | 0 | 0.5 | 0 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 15 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0.5 | 0.5 | 0 |
| 16 | 1 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0.5 | 0 | 0 | 0 | 0 | 0 |
| 17 | 1 | 1 | 1 | 1 | 0.5 | 0.5 | 0.5 | 0.5 | 0.5 | 0 | 0 | 0 | 0 |
| 18 | 0.5 | 1 | 1 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 19 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0.5 | 0.5 | 1 | 0 | 0 | 0 |
| 20 | 0.5 | 1 | 1 | 0.5 | 0.5 | 0 | 0 | 0 | 0 | 0.5 | 0 | 0 | 0 |
| 21 | 1 | 1 | 1 | 1 | 1 | 0.5 | 1 | 1 | 0 | 0 | 0 | 0 | 1 |
| 22 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0.5 | 0.5 | 1 |
| 23 | 1 | 1 | 1 | 1 | 1 | 1 | 0.5 | 1 | 1 | 0.5 | 0 | 0 | 0.5 |
| All 23 | 96% | 87% | 83% | 72% | 70% | 59% | 41% | 39% | 30% | 24% | 20% | 22% | 20% |
| Core 6 | 6/6 | 6/6 | 4.5 | 4 | 4 | 4.5 | 1 | 2 | 1.5 | 2 | 1.5 | 2.5 | 0.5 |

Gargoyle's two half marks: row 18, the per-call chain verifies in
TypeScript but the evidence log, witness and record reader are Python only;
row 20, issuer and record keys are signed records but the approver registry
and its revoked list are a plain file served over TLS. EMILIA's row 22 is
scored on its implementation (MCP server and HTTP gate); the draft text has
no MCP section.

## What the numbers say

- The 2026-10-16 claim that no one else had a keyed human grant verified at
  execution was wrong. EMILIA (WebAuthn approver keys, challenge = context
  hash) and NOA (approver Ed25519 verified against a keyring before the
  proxy forwards) both have it, and EMILIA's draft revisions predate the
  claim. The policy-pin row is shared with EMILIA, Microsoft AGT and
  ActionProxy. Rows 5 and 6 are now the field's consensus, not a moat.
- Three rows remain Gargoyle's alone at full marks: state-bound approval
  (row 13: the pre-state hash of the resource in the signed receipt, so a
  release covers the bytes the approver saw; EMILIA and NOA bind a display
  hash, not resource state), undo proven by snapshot hashes (row 14), and
  the issuer witness reconciled against client evidence (row 16).
- One row is Gargoyle's alone in kind rather than score: row 3 at the
  directory level on both ends. The requester is an Entra account and the
  approver is an Entra account with an app role whose browser key is
  enrolled under that account. EMILIA's approver directory is its own
  Merkle tree ("does not prove the holder is a particular natural person"),
  NOA's approver id is opaque by design, Signet's is a URI, ActionProxy
  binds the requester to OIDC but approvals are gateway state.
- Scored the other way, EMILIA and NOA each beat Gargoyle on verifier
  count (three and five languages), vector corpus size, a frozen wire
  format, signed approver directories with revocation, and an individual
  Internet-Draft. EMILIA adds formal models in CI and an enforcement-class
  declaration in receipts. Microsoft AGT and Signet beat it on breadth
  (framework adapters, scanners, delegation budgets). The gateways beat it
  on hosting, catalogs and identity federation, and have no artifact at
  all.
- Nothing found combines what Gargoyle combines. That sentence was true in
  October's first two comparisons and is still true, but it is weaker than
  it sounds: the combination is three exclusive rows plus identity
  integration on top of a primitive that three other teams have also
  built, two of them further along on verification breadth.

## Where that leaves the project

The ROADMAP's own stop rule (after steps 1 to 3: "if nobody has opened an
issue, run the vectors, or wired the middleware into a server, the next
work is positioning and outreach, not step 4") triggered weeks ago and was
not acted on; steps 4 to 6, observe mode, two review rounds and the
operability list were built instead. The code is real (446 tests, a live
pilot deployment, four PyPI releases in a day), but it has no external user,
and that is the Elyon-Sol pattern the roadmap was written to avoid.

The comparison says where the substance is and is not:

- Not in the primitive. Signed receipt, args hash, single use, policy pin,
  keyed grant: consensus. Competing on it means competing with EMILIA's
  standards work and NOA's five verifiers from behind.
- In three things nobody else does (state binding, proven undo, witness
  reconciliation) and one thing nobody else does at this level (Entra
  identity for requester and approver, approver key enrolled in the
  browser under the account, role re-checked at grant time). The last is
  the one a small-business Microsoft 365 shop would pay for and the one
  that matches the Elyon-Sol client base.

Two moves follow, and neither is a new feature:

1. Interoperate instead of differentiate on the primitive. Run EMILIA's
   conformance vectors against a Gargoyle-to-EMILIA export (or NOA's), and
   file the gaps as issues on their trackers. If Gargoyle receipts can be
   verified by their verifiers, the five-language problem is solved by
   someone else, and the first outside contact is made with the people
   most likely to understand the work.
2. Put the pilot in front of one client this week, in observe mode, and
   treat the first real audit a client's IT person runs as the milestone
   that matters. Until that happens, every further commit is verification
   for no external user.

## Sources

EMILIA: https://www.ietf.org/archive/id/draft-schrock-ep-authorization-receipts-13.txt ,
https://github.com/emiliaprotocol/emilia-protocol (README, CONFORMANCE.md),
companion draft-schrock-ep-authorization-evidence-chain-08.
NOA: https://github.com/NordenSoft/noa-mandate-core (docs/receipt-spec.md,
packages/mcp-proxy, packages/gate, NON-CLAIMS.md), noa-receipt 0.9.0,
noa-mcp-proxy 0.5.1.
Signet: https://github.com/Prismer-AI/signet v0.11.0 (README, SECURITY.md,
crates/signet-core, packages/signet-mcp-server).
Microsoft AGT: https://github.com/microsoft/agent-governance-toolkit
(docs/adr/0030-action-bound-approval-protocol.md, docs/specs/*), 5.0.0.
ActionProxy: https://github.com/ActionProxy/actionproxy v0.1.1 (docs/SECURITY_MODEL.md,
docs/execution-authorization-v1.md, apps/server/src/security/*).
Obsigno: https://github.com/amudhan22/obsigno 0.3.0.
Proof-of-Behavior: https://www.ietf.org/archive/id/draft-dembowski-agentledger-proof-of-behavior-00.txt ,
https://github.com/dembovvski/agentledger.
sm-aae: https://github.com/Sharathvc23/sm-aae 0.1.0 (SPEC.md, THREATMODEL.md).
Transaction Tokens for Agents: https://www.ietf.org/archive/id/draft-araut-oauth-transaction-tokens-for-agents-02.html
AWS: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html and sibling pages.
DigitalOcean: https://docs.digitalocean.com/products/managed-agents/action-gateway/
HumanLayer: https://github.com/humanlayer/humanlayer (SDK deprecated 2025-09-29; local approvals in hld/hlyr).
