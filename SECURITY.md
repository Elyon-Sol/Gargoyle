# Security policy

Gargoyle is pre-release software by one author, proven in one deployment.
It was reviewed twice on 2026-10-20 by outside, model-driven reviewers
with repository access; their ten security findings are fixed as of
0.17.0 and recorded in ROADMAP.md. No independent human review has been
completed. Treat every release as alpha. The
threat model and the limits of the design are in SPEC.md section 15.1
and in the technical report's section 9; read those before deploying.

## Supported versions

Only the latest release on PyPI (`gargoyle-receipts`) receives fixes.
Wire formats are versioned (`gargoyle/3`, `gargoyle-evidence/4`); a fix
that changes a format is a new version, and older receipts keep verifying
through the historical path in `gargoyle audit`.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- Preferred: GitHub private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability").
- Or email admin@elyon-sol.io with "Gargoyle security" in the subject.

Include the version, what you did, what you expected the gate to do, and
what it did instead. A receipt chain or an evidence log excerpt that
shows the problem is the most useful thing you can send; replace account
names if you need to.

You will get an acknowledgement within 3 working days and a fix or a
written decision within 30 days. Credit is given in the release notes
unless you ask otherwise. There is no bounty.

## Scope

In scope: anything that lets a tool call run without the receipt, grant
or state binding the specification requires; anything that lets evidence
or the witness be altered without detection; identity handling at the
issuer; the approval console; the remote gate.

Out of scope by design, and documented: on a workstation its user
administers, the gate constrains the assistant, not the user. Changes
made around the gate are detected by reconciliation and the tree check,
not prevented. See SPEC.md section 15.1.
