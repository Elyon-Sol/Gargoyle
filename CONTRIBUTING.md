# Contributing

Thank you. Three things make a contribution mergeable here.

## 1. Sign your commits (Developer Certificate of Origin)

Every commit carries a `Signed-off-by: Your Name <you@example.com>` trailer, added with
`git commit -s`. By adding it you certify the Developer Certificate of Origin 1.1
(https://developercertificate.org): that you wrote the change or have the right to submit
it under this project's licence, Apache-2.0, and that you understand the contribution is
public and kept. The name must be a natural person's; a pull request without a sign-off on
every commit fails the `dco` check and is not merged.

Work produced with an AI model's help is welcome. You sign it off, you are responsible for
it, and the model is credited with a `Co-Authored-By:` trailer (this repository's history
shows the form). There is no contributor licence agreement: Apache-2.0 inbound equals
Apache-2.0 outbound, and you keep your copyright.

## 2. Keep the tests green on both platforms

`python -m pytest -q` must pass on Linux and Windows; CI runs both and the main branch
refuses a merge until every job is green. A change to a format or a verifier ships with
vectors. A change to the issuer ships with a test that reads the witness.

## 3. Say what changed, in the title

Pull request titles name the change ("Witness: refusals by rule record what was refused"),
not the task or the file. The description says why, what was verified and how, and what
was not run.

## What is in scope here

Everything on the open list in `LICENSING.md`. The commercial operations layer lives in a
separate repository and is not developed here. A pull request that would move an item from
the open list to the commercial list is declined; see `GOVERNANCE.md`.

## Security

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.
