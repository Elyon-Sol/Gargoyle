# Acta conformance fixtures

Copied unmodified from github.com/ScopeBlind/agent-governance-testvectors
(Apache-2.0), commit 5c749de569b247b2db7c01bdbe1487267615afc4 of 2026-11-04:

- `key-window/`, `chain-link/`, `signing-input/`, `timeliness/`, `revocation/`:
  the repository's `verifier-vectors/`, each with its `index.json` naming the
  verdict a verifier must reach (the generator scripts are not copied);
- `embedded-key/`: the two negative receipts of `negative/embedded-key/`, whose
  own public key must never be trusted (draft section 9.5);
- `policy/`: the Cedar policy of `fixtures/policy/` and `expected/chain.jsonl`,
  whose `policy_digest` the section 6.8 construction must reproduce.

tests/test_acta.py runs gargoyle.acta over them. Nothing here is executed.
