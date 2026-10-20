# Live EMILIA export, redacted

`gargoyle-emilia-live-redacted.v1.json` is the first Trust Receipt exported by
`gargoyle emilia` from a pilot client (gargoyle-receipts 0.19.0.dev0, 2026-10-20),
in the vector-file format of EMILIA's conformance runners. The requester and
approver account names and the workstation path are inside the signed bytes, so
this copy replaces them (requester@pilot.example, approver@pilot.example,
C:\pilot\project) and is re-signed under two throwaway keys. Hashes, timestamps,
decision id and structure are the live artifact. EMILIA's run-js.mjs and run_py.py
at their commit 3f712d2 accept it; see ../interop-emilia.md.
