# Licensing

This page states, once, what is open, what will be commercial, and where the line is.
It is a statement of intent by the copyright holder and binds future releases; it does
not change the licence of anything already published.

## Open, permanently: Apache License 2.0

Everything in this repository through version 0.22 is licensed under the Apache License,
Version 2.0, and that grant is irrevocable. The following stay Apache-2.0 in every future
version, because "verifiable offline by anyone" is the product's central claim and a
reviewer must be able to read, run and reimplement it:

- the receipt, grant, execution-receipt and witness formats, and `SPEC.md`;
- the canonical form and every verifier (`gargoyle.verify`, `gargoyle.audit`, the
  TypeScript package under `ts/`, and any later language);
- the conformance vectors and the EMILIA interoperability runner and exports;
- the client side: the MCP gate, the Claude Code hook, `gargoyle doctor`,
  `gargoyle sidedoors`, `gargoyle rules test|lint|explain`, `gargoyle report`;
- the workstation installer, including the service-account gate, share permissions and
  the Claude Desktop and Claude Code policy pack, so the free product protects a
  workstation completely;
- adapters that place the gate in front of other tools and hosted integration layers
  (Composio and similar), because interoperability behind a paywall is not
  interoperability;
- the issuer and the approver console as published here.

## Commercial, from version 0.23: the operations layer

Code first published after 0.22 that exists to run the gate for someone else, rather than
to prove or verify a receipt, is developed in a separate repository under commercial terms
and is not part of this package. Today that perimeter is:

- a multi-tenant hosted issuer and its console;
- warm standby, failover and the recovery tooling around them;
- export of the witness to a tenant's SIEM or log workspace;
- support with a response time, and the evidence-report service.

In one line: what proves, verifies or protects a workstation is open; running the gate for
someone else is commercial.

Nothing in that layer changes a receipt, a verifier or a format. A receipt produced by the
commercial layer verifies with the open verifier, byte for byte, or the commercial layer is
wrong. Commercial terms are available from the copyright holder; see `GOVERNANCE.md` for
the neutrality commitments that apply to them.

## What this means for you

- **Using Gargoyle** as published: Apache-2.0, no fee, no registration, no telemetry.
- **Verifying evidence** produced by anyone's Gargoyle, open or commercial: Apache-2.0,
  always.
- **Contributing**: see `CONTRIBUTING.md`. Contributions to this repository are
  Apache-2.0 under the Developer Certificate of Origin; nothing here is ever relicensed
  without the contributor's consent, which Apache-2.0 already makes unnecessary.
- **Running it for clients** as an integrator or managed-service provider: permitted by
  Apache-2.0 for everything here. The operations layer is licensed separately for that use.

## Names

"Gargoyle" and the project marks identify this project and its steward's products. Apache-2.0
licenses the code, not the names. Anyone may implement the specification, fork the code and
verify receipts without using the name; presenting a product as this project is subject to
the marks. The product-line name may change; this section will name it when it is settled.

## Patents

Apache-2.0 section 3 grants every user a licence to any patent claim of the contributors
that the published code practises. If the copyright holder files a patent on the mechanism
(policy-pinned single-use receipt, separately keyed human release verified at execution,
execution receipts reconciled offline against an issuer witness), it will carry a
non-assertion covenant for any implementation that conforms to the published specification
and passes the published vectors.

Version of this page: 1, 2026-11-04. Changes to it are made by pull request and recorded
in the repository history.
