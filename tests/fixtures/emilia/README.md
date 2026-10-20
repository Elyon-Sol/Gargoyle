Conformance vectors from the EMILIA Protocol repository
(https://github.com/emiliaprotocol/emilia-protocol, Apache-2.0, commit 3f712d2,
copied 2026-10-20): receipts.v1.json (EP-RECEIPT-v1, 14 vectors) and
canonicalization.v1.json (EP-CANONICALIZATION-v1, 35 vectors). They are
EMILIA's, not Gargoyle's; tests/test_emilia_interop.py runs them against
gargoyle.emilia so a change to Gargoyle's canonical form or key handling that
breaks agreement with EMILIA's verifiers fails here first.
