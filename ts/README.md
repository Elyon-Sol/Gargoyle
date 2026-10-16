# gargoyle-receipts (TypeScript)

Verifier and consumer for Gargoyle receipts, the second implementation of
[SPEC.md](../SPEC.md). It is validated byte for byte against the same
conformance vectors as the Python reference (`tests/fixtures/wire_vectors.json`):
the test suite recomputes every hash and signature in the vectors from the
seed labels and compares.

What is here: canonical JSON, Ed25519 over Node's crypto, receipt
build/sign, `verifyProvenance`, `verifyEnvelope`, grants, execution
receipts, `verifyChain`, and a `Consumer` with single-use claims and
`attest`. Not yet ported: the signed published-record and key-record
readers (sections 9 and 10); hand the consumer a validated pin and key map.

    npm install
    npm test

```ts
import { Consumer, publicKeyFromRaw } from "gargoyle-receipts";

const consumer = new Consumer({
  targetId: "https://tools.example.com/target",
  record: { policy_id: "opa:payments/3", policy_sha256: "..." },   // the live pin
  pinnedPublicKeys: { "issuer-2026-10": publicKeyFromRaw(ISSUER_PUBLIC_KEY_HEX) },
});
const verdict = consumer.check(receipt, { tool, args, principal: peerIdentity }, { grant });
if (verdict.accepted) run(tool, args); else refuse(verdict.reason);
```

Requires Node 20 or later. Apache-2.0.
