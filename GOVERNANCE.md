# Governance

## Steward

Gargoyle is written and stewarded by Justin LaPorte (GitHub: Elyon-Sol), who holds the
copyright in the repository's contents to date. A legal entity to hold the copyright, the
marks and the commercial layer is being formed; this page will name it when it exists.
Until then, "the steward" means the copyright holder.

## Decisions

- The steward merges. A change to `SPEC.md`, a wire format or a verifier is a versioned
  change: the specification carries a version, released vectors are never edited, and a
  format change ships with vectors that the previous verifier rejects and the new one
  accepts.
- Issues and pull requests are the record. Decisions that matter are made in them, not in
  private channels, so the reasoning is public.
- Security reports follow `SECURITY.md` and are not discussed in public until fixed.

## Licensing split

`LICENSING.md` states what is open permanently and where the commercial operations layer
begins. The split is by role: what proves and verifies is open; what runs the gate for
someone else may be commercial. The steward does not move an item from the open list to the
commercial list.

## Neutrality

These commitments apply to the steward and to any entity that succeeds to the marks:

1. The verifier is free, in every language it is published in, and verifies every
   conformant receipt, whoever issued it.
2. Conformance material (specification, vectors, interoperability runners) is public.
   There is no paid tier of vectors and no private test suite.
3. The steward's own products receive no privilege at the protocol level: no field, flag or
   verifier behaviour that only the commercial layer can produce or consume.
4. There is no certification programme today. If one is created, it is offered to every
   implementer on identical published terms.
5. Interoperability never requires the name. Anyone may say their receipts verify with the
   Gargoyle verifier; only presenting a product as Gargoyle is subject to the marks.

## Marks

"Gargoyle" and the project's marks are held by the steward. Apache-2.0 licenses code,
specifications and vectors; it does not license names. Forks keep the licence and change the
name. The product-line name may change; the open list in `LICENSING.md` does not change
with it.

## Irrevocability

Every released version is Apache-2.0 and stays Apache-2.0. The steward cannot and will
not withdraw a published grant. A contributor's work is never relicensed without the
contributor's consent.

## Contributions

`CONTRIBUTING.md`: Developer Certificate of Origin sign-off by a natural person on every
commit, Apache-2.0 inbound, contributors keep their copyright. Work produced with an AI
model's assistance is accepted when a natural person signs it off and takes
responsibility for it; the model is credited in a `Co-Authored-By` trailer, as this
repository's own history does.

## Standards

The steward intends to publish the architecture and threat model as an individual
Internet-Draft and to register a media type for the receipt JSON. Change control of the
specification passes to a working group if one adopts it. Until then it rests here.

Version of this page: 1, 2026-11-04.
