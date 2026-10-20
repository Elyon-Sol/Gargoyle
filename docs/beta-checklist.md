# Beta checklist for a client deployment

What to set up, what to tell people, what to watch, and how to back out.
This is for a first client beta of a prerelease: one issuer, one approver
console, a handful of workstations, files or Microsoft 365 behind the gate.

## Before the first user

- [ ] Issuer on a server the client controls, with `gargoyle issuer --out DIR`
      run by a service unit (`DIR/gargoyle-issuer.service` from `init`); confirm
      `GET /health` answers and reports `"persistent": true`.
- [ ] TLS from a CA the clients trust (Apache in front, `DIR/apache-gargoyle.conf`);
      the private PoC CA is for labs only.
- [ ] Entra: the two app registrations (docs/entra-setup.md), the Approver app role
      assigned to the people who approve, `GARGOYLE_ISSUER_AUDIENCE` set as a list.
- [ ] Or start in observe mode (`gargoyle init --observe`): a week of recording, then
      the hold and deny rules from `gargoyle audit --summary` (guide 4.4c).
- [ ] `rules.json` reviewed with the client: what is free, what is held, who approves
      what (`approvers` by UPN), what may be planned (`"plan": false` on sends), what
      is denied. Keep the first version small; widen later.
- [ ] Hold notices to the approver's channel (`GARGOYLE_HOLD_WEBHOOK_URL`), with the
      console link.
- [ ] Back up DIR: keys, `rules.json`, `approvers.json`, `holds.sqlite`.
- [ ] Snapshot and audit retention on each workstation: copy `C:\gargoyle\audit.jsonl`
      and `C:\gargoyle\snapshots` off the machine on a schedule; note the tail hash.
- [ ] Reconciliation on a schedule: the issuer's `witness.jsonl` against each
      workstation's evidence (`gargoyle audit --witness`), and the gated folder against
      the evidence (`--check-tree`). Every FINDING line is a conversation with the user.

## Each workstation

- [ ] `pip install "gargoyle-receipts[entra]"` pinned to the beta version.
- [ ] `gargoyle login` as the user; the printed principal is their UPN.
- [ ] The client's own side doors closed (guide Part 8): Claude Desktop's Filesystem
      extension off, Claude Code's Edit/Write/Bash denied in the project, no second
      connector to the same data.
- [ ] One free read, one held write, one audit, before handing over.

## What to tell users

- Reads happen at once. Writes pause for a few seconds while an approver looks;
  the assistant may say "the server did not respond" during a long pause, which
  only means the approver has not clicked yet.
- A refused call is a refusal: the assistant should say so, not work around it.
  If it tries another route, that is a side door to close, not a bug in the gate.
- "Undo the last approved change" is available and goes through approval too.
- A plan ("request a plan for ...") turns many cards into one, and the approver
  sees scope, not content.

## What to tell approvers

- The card shows the exact change, as a diff against the file as it is. If the
  diff is not what the user described, decline; the user's assistant is told.
- A plan card lists tools and patterns, not contents. Approve plans only for
  work you would let the person do unsupervised.
- Your key lives in your browser. A new browser means enrolling again, which
  replaces the old key; tell the operator if that was not you.

## What to watch, weekly

- `gargoyle audit --log` on each workstation: 0 failed, chain intact, the tail
  hash recorded and compared to last week's.
- `GET /health`: pending counts not growing; an approver list that matches HR.
- Reconciliation findings: an UNWITNESSED_* line is a workstation whose evidence
  the issuer cannot vouch for; MISSING_EVIDENCE is a workstation that stopped
  recording; CHANGED_OUTSIDE_GATE is a side door still open or a user editing by hand.
- The issuer's JSON event log: refusals by tool (policy too tight?), holds per
  person per day (card fatigue?), declines (what did users try?).
- Time from hold to grant. If approvers are slow, the plan feature and the
  notice channel are the levers; if they are fast and never decline, the rules
  are too broad.

## Rollback

- Remove the MCP entry from the client config and restart the client: the
  assistant is back to its own tools, with no gate. The evidence collected so
  far stays verifiable.
- Keys compromised: `gargoyle init` into a new DIR, redistribute, keep the old
  `public-keys.json` for audits of the old evidence.

## What this beta cannot promise yet

- One issuer process. A second instance is not safe for single use yet.
- Capability URLs for hosted connectors are credentials; OAuth is not built.
- Approver authority rests on the issuer's operator (spec section 8.3).
- Microsoft 365 adapters have not run against a real tenant.
