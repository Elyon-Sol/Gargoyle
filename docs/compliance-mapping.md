# Compliance mapping: what Gargoyle is evidence of, clause by clause

Dated 2026-11-25, against release `1.0.0rc3` and [SPEC.md](../SPEC.md) as
frozen on 2026-11-06 (SPEC.md section 12).

This page is for an auditor, a control owner or a compliance lead who has
to decide which requirement a Gargoyle record can be offered as evidence
for. It maps mechanisms to requirements. It is not a statement of
compliance.

## 1. How to read this page

- **Software is not compliant; a deployment is assessed.** Nothing here
  says that Gargoyle, or a system using it, meets any standard. A
  requirement is met by an organization's control, operated over a period
  and tested by its assessor. Gargoyle implements human oversight and
  record-keeping for agent actions, and produces evidence that such a
  control operated.
- **The mapping is the author's.** Every row was written by the project
  from the specification and the published text of each instrument. No
  auditor, assessor or regulator has reviewed it, and no independent human
  has reviewed the code ([SECURITY.md](../SECURITY.md)). Row 17 of the
  matrix records this.
- **Every row cites a mechanism.** Each row names the SPEC.md section that
  defines the behaviour, the artifact a reviewer would ask for, and the
  refusal or finding codes that show the control refusing. A row without
  those would be an opinion, and there are none.
- **Statuses** are used in section 4:

  | Mark | Meaning |
  |---|---|
  | ● | met by the design: the specified behaviour does this with no further condition |
  | ◐ | met under a stated deployment condition, named in the row |
  | ○ | partly addressed; the row says what is missing |
  | - | not addressed by the software; the deployer supplies it |

## 2. What Gargoyle is

Gargoyle is a control-evidence component: a pre-execution authorization
control with a human release that is cryptographically separate from the
issuing service, producing tamper-evident records that a third party
verifies offline with three public keys.

The flow, independent of any host or agent product:

1. An **issuer** asks a **policy** to decide a call and signs the decision
   as a **receipt** bound to the tool, a hash of the arguments, the
   principal, the target and the policy version (SPEC.md sections 3 to 6).
2. Where the policy requires a person, the receipt is **held** until one
   or more approvers each sign a **grant** with a key the issuer does not
   have (section 8).
3. The **executor** verifies the receipt and grants, claims the decision
   once, performs the call and signs an **execution receipt** with the
   state before and after (sections 6, 7 and 13).
4. The executor appends every decision, refusals included, to a
   hash-chained **evidence log**; the issuer keeps its own signed,
   hash-chained **witness** of what it issued, released and refused
   (section 15).
5. An auditor verifies both records offline and reconciles them by
   decision id (section 15.1).

What it is not: a policy engine, an identity provider, an AI
risk-management system, or a governance, risk and compliance platform. The
policy decides; Gargoyle makes the decision and its release verifiable.

## 3. Where it fits, in order

**Closest fit: authorization and non-repudiation controls over changes.**
These frameworks ask for the same four things: a change is approved before
it is made, the approver is not the requester, the record of both cannot
be altered without detection, and the record can be produced later.
Gargoyle implements those four for actions taken by an agent. See
section 5.1.

**Fit at the level of mechanism: electronic records and signatures.**
The record-keeping and identity mechanisms correspond to parts of
21 CFR Part 11 and to the criteria of eIDAS Article 26. Two gaps keep this
at the level of mechanism (section 6): the approval page is served by the
issuer's operator, and the grant itself does not carry the time and
meaning of the signature. See section 5.2.

**Prospective fit: rules for AI systems.** The EU AI Act's record-keeping
and human-oversight articles, ISO/IEC 42001 and the agent work at NIST and
OWASP describe needs these records address. The obligations are either not
yet in application or not final. See section 5.3.

**Not a fit, and not claimed:**

- GDPR Article 22 (decisions based solely on automated processing): a
  release record does not establish that a human's involvement was
  meaningful.
- HIPAA or any other sector rule not named in section 5.
- Certification or attestation of any kind.
- Prevention of action around the gate. A caller that never asks for a
  receipt is stopped only by a target that refuses unattested calls.
  Elsewhere, action around the gate is detected, not prevented
  (SPEC.md section 15.1).

## 4. Conformance matrix

Seventeen requirements that recur across the instruments of section 5,
stated in plain terms. Codes beginning `REF_` are refusal codes; the
others are reconciliation findings. Code names are never renamed or reused
(SPEC.md section 12).

| # | Requirement | Status | Mechanism (SPEC.md) | Evidence a reviewer asks for | Codes that show it refusing |
|---|---|---|---|---|---|
| 1 | No consequential action without prior authorization | ◐ | Sections 6 and 7: a verifier has no unsigned mode and a consumer cannot be built without issuer-key trust. **Condition:** the target itself refuses calls without a receipt. Where the agent can reach the target another way, see row 9 and section 15.1. | receipt; evidence entry (`honored` or `refused`) | `REF_VERIFY_ENVELOPE_ABSENT`, `REF_VERIFY_SIGNATURE_UNKNOWN_KEY`, `REF_VERIFY_SIGNATURE_INVALID`, `REF_TARGET_NO_DECISION_ID`; finding `UNWITNESSED_RECEIPT` |
| 2 | Authorization bound to the exact action and actor | ● | Sections 3 to 6: tool, argument hash, principal, target and, when described, the target's prior state are inside the issuer's signature and checked at execution. | receipt; execution receipt | `REF_VERIFY_BINDING_MISMATCH`, `REF_VERIFY_PRINCIPAL_MISMATCH`, `REF_VERIFY_STATE_MISMATCH`, `REF_VERIFY_REASSERT_INVALIDATED` |
| 3 | Approval by a named, authenticated individual | ◐ | Section 8.3: an approver enrols a key under an identity-provider identity; the role is checked again at every release; the permanent id (issuer and subject, section 14) is kept beside the readable name. **Conditions:** approvers are enrolled people, not configured keys; and the limit in section 6.1 of this page. | grant; witness `enrolled` and `granted` (`approver_id`, `approver_name`) | `REF_APPROVAL_KEY_UNKNOWN`, `REF_APPROVAL_SIGNATURE_INVALID`, `REF_ISSUER_NOT_AN_APPROVER`, `REF_ISSUER_SUBJECT_MISMATCH` |
| 4 | The approver is not the requester and not the issuing authority | ◐ | Section 8, step 3: a grant under the issuer's key id is refused before its signature is read. Section 8.3: self-approval is refused by name and by permanent id unless the operator turns it on. **Condition:** the approver's private key is out of the issuing service's reach, which is a property of the deployment. | grant; witness `granted` (`requested_by_id`, `approver_id`); witness `grant_refused` | `REF_APPROVAL_SOD`, `REF_ISSUER_SELF_APPROVAL` |
| 5 | Two-person or m-of-n release | ◐ | Section 8.0: the receipt carries the required count, the eligible approvers and roles inside the issuer's signature; a caller cannot lower them. **Condition:** built and covered by test vectors; not yet run on a live issuer. | receipt `approval` member; grants; witness `granted` (`collected`, `required`) | `REF_APPROVAL_INSUFFICIENT`, `REF_APPROVAL_DUPLICATE_APPROVER`, `REF_APPROVAL_APPROVER_NOT_ELIGIBLE`, `REF_APPROVAL_ROLE_UNATTESTED`, `REF_APPROVAL_ROLE_NOT_ELIGIBLE` |
| 6 | The approver sees exactly what will happen | ◐ | Section 6.1: the console checks that the state shown hashes to the state the receipt binds before it enables approval; the executor refuses if the state moved. **Conditions:** the call is state-bound and approved singly (a plan's approver sees scope, not content, section 17); and the limit in section 6.1 of this page. | receipt `request_context.state_sha256`; execution receipt `pre_state_sha256` | `REF_ISSUER_STATE_TEXT_MISMATCH`, `REF_VERIFY_STATE_MISMATCH`, `REF_TARGET_STATE_UNREADABLE` |
| 7 | No reuse, replay, extension or transfer of an approval | ● | Sections 5, 7 and 8.1: decision id, grant id and expiry are signed; each is claimed once in a store that outlives the process; a replay the store missed is found afterwards. The store's scope is the scope of the guarantee: replicas must share one. | evidence log; replay store | `REF_VERIFY_REPLAY`, `REF_APPROVAL_REPLAY`, `REF_VERIFY_SIGNATURE_EXPIRED`, `REF_APPROVAL_EXPIRED`, `REF_EVIDENCE_REPLAY`; finding `REPLAYED_RECEIPT` |
| 8 | Approval tied to the policy in force; a stale approval is not honored | ● | Section 6, step 3, and section 9: a receipt issued under a policy that has since changed is refused; the published record's serial detects rollback. | receipt `policy`; published record; witness `issued` (`policy`) | `REF_VERIFY_REASSERT_RE_EVALUATE_REQUIRED`, `REF_VERIFY_PUBLISHED_RECORD_STALE`, `REF_VERIFY_PUBLISHED_RECORD_INVALID` |
| 9 | Proof that the approved action, and only it, ran | ◐ | Section 13: the execution receipt copies the authorized fields byte for byte and adds output and state hashes. Section 15.1: reconciliation and the tree check report work done around the gate. **Condition:** the executor is trusted for the truth of what it reports. | execution receipt; reconciliation report | `REF_EXEC_BINDING_MISMATCH`, `REF_EXEC_SIGNATURE_INVALID`, `REF_EXEC_GRANT_MISSING`; findings `UNWITNESSED_RELEASE`, `MISSING_EVIDENCE`, `CHANGED_OUTSIDE_GATE` |
| 10 | A complete, tamper-evident record, refusals and declines included | ◐ | Section 15: both records are hash-chained and the witness is signed per entry; an edited, removed or inserted entry fails verification. **Condition:** truncation at the end leaves a valid shorter chain, so the reviewer records the tail hash at each audit and compares it at the next. | evidence log; witness log; recorded tail hashes | `REF_EVIDENCE_HASH_MISMATCH`, `REF_EVIDENCE_CHAIN_BROKEN`, `REF_EVIDENCE_MALFORMED` |
| 11 | Verifiable by a third party without access to the system | ● | Section 13 (`verify_chain`) and section 15: the three artifacts and three public keys suffice, with no live state. Two implementations recompute the same vectors (section 11); the TypeScript one verifies the current receipt version and does not yet verify plan releases. | public keys; the artifacts themselves | `REF_EXEC_KEY_UNKNOWN`, `REF_EXEC_MALFORMED`, `REF_EVIDENCE_RECEIPT_MISSING` |
| 12 | A trustworthy time source | ○ | Sections 6 and 13: times are the host's clock, with a configured tolerance; `executed_at` is signed by the executor and each witness entry's `at` by the issuer. Missing: a time attested by a party outside the deployment. | witness `at`; execution receipt `executed_at` | none |
| 13 | Retention, write-once storage, export to a monitoring system | - | Not in the software. [operations.md](operations.md) describes backup and restore of the issuer host; retention period, storage that cannot be rewritten, and export are the deployer's. | the deployer's storage and retention records | none |
| 14 | Approver competence, attention and authority | ○ | Section 8.0 routes a hold to a role; section 8.3 caps one principal's open holds and stops repeated requests after declines. Whether the person is competent, attentive and authorized is the organization's to establish. | witness `declined` (`meaning`, `by_id`); witness `grant_refused` (`reason`) | `REF_ISSUER_TOO_MANY_HOLDS`, `REF_ISSUER_DECLINED_RECENTLY`, `REF_APPROVAL_ROLE_NOT_ELIGIBLE` |
| 15 | The approver authenticated recently | ◐ | Section 8.3: where a sign-in age is set, a release is accepted only from a token whose sign-in time is present and recent. **Condition:** the setting is off by default, and the identity provider must put the sign-in time in the token. | witness `granted`, `grant_refused`, `declined` (`auth_time`, `auth_age_seconds`, `auth_max_age_seconds`) | `REF_ISSUER_AUTH_TIME_MISSING`, `REF_ISSUER_AUTH_TOO_OLD` |
| 16 | Key management over the life of a key | ◐ | Section 10: a root-signed key record with validity windows and revocation. Section 8.3: enrolment, replacement only with the current key's consent, revocation, and a history so earlier grants still audit. **Condition:** keys are not bound to hardware; protecting the issuer, root and executor keys is the deployer's. | key record; witness `enrolled`, `revoked`, `enroll_refused` | `REF_VERIFY_KEY_REVOKED`, `REF_VERIFY_KEY_OUT_OF_WINDOW`, `REF_VERIFY_KEY_UNKNOWN`, `REF_ISSUER_KEY_ENROLLED`, `REF_ISSUER_KEY_REVOKED` |
| 17 | Independent assurance of the implementation | ○ | Section 11: conformance vectors recomputed by two implementations in continuous integration. Two model-driven reviews are recorded in [SECURITY.md](../SECURITY.md). Missing: a review by an independent human. | SECURITY.md; test results | none |

## 5. Clause map

Each clause is named by its published title or subject, followed by the
matrix rows that bear on it. A clause is listed because a Gargoyle record
is relevant evidence for it, not because the record satisfies it.

### 5.1 Authorization and non-repudiation controls

| Instrument | Clause | Rows |
|---|---|---|
| NIST SP 800-53 Rev. 5 | AC-3(2) Access Enforcement: Dual Authorization | 4, 5 |
| | AC-5 Separation of Duties | 4 |
| | AU-8 Time Stamps | 12 |
| | AU-9 Protection of Audit Information | 10 |
| | AU-10 Non-repudiation | 2, 3, 10, 11 |
| | AU-10(2) Validate Binding of Information Producer Identity | 3, 11 |
| | AU-11 Audit Record Retention | 13 |
| | CM-3 Configuration Change Control | 1, 2, 8 |
| | CM-5 Access Restrictions for Change | 1, 4 |
| SOC 2 (Trust Services Criteria) | CC6.1 to CC6.3 logical access, authorization and role-based access | 3, 4, 16 |
| | CC7.2 monitoring for anomalies | 9, 10 |
| | CC8.1 authorization, approval and implementation of changes | 1, 2, 4, 8 |
| ISO/IEC 27001:2022, Annex A | 5.3 Segregation of duties | 4 |
| | 8.15 Logging | 10, 11 |
| | 8.16 Monitoring activities | 9 |
| | 8.17 Clock synchronization | 12 |
| | 8.32 Change management | 1, 2, 8 |
| PCI DSS v4.0.1 | 6.5.1 changes to system components follow established procedures, including documented approval | 1, 2, 4 |
| | 10.2 audit logs are implemented | 10 |
| | 10.3 audit logs are protected from destruction and unauthorized modification | 10 |
| | 10.5 audit log history is retained | 13 |
| | 10.6 time-synchronization mechanisms | 12 |
| Regulation (EU) 2022/2554 (DORA) | Article 9(4)(e): ICT changes are recorded, tested, assessed, approved, implemented and verified in a controlled manner | 1, 2, 4, 10 |
| Sarbanes-Oxley section 404 | IT general controls over change management and segregation of duties, as an entity and its auditor define them | 1, 4, 10 |

For AU-10, the FedRAMP Rev. 5 parameter names approval among the actions
to be covered. Sarbanes-Oxley names no clause for these controls; the
entity's own control descriptions are what a record is tested against.

### 5.2 Electronic records and signatures

| Instrument | Clause | Rows | Limit |
|---|---|---|---|
| 21 CFR Part 11 | 11.10(e) time-stamped audit trails | 10, 12 | host clocks (row 12) |
| | 11.10(g) authority checks | 3, 4, 5 | |
| | 11.50 signature manifestations: printed name, date and time, meaning | 3 | carried by the witness entry, not by the grant (section 6.2) |
| | 11.70 signature and record linking | 2, 7 | |
| | 11.100(a) a signature unique to one individual | 3, 16 | |
| | 11.200(a) two distinct identification components | 3, 15 | the sign-in is the identity provider's; a second factor is the deployer's to require |
| Regulation (EU) No 910/2014 (eIDAS) | Article 26(a), (b): uniquely linked to and capable of identifying the signatory | 3 | |
| | Article 26(c): signature creation data under the signatory's sole control | 3 | not met while the limit in section 6.1 stands |
| | Article 26(d): linked to the data so that a later change is detectable | 2, 10 | |

No Gargoyle grant is offered as an electronic signature under either
instrument. The working description is a control with an audit trail.

### 5.3 Rules for AI systems

| Instrument | Clause | Rows | State on 2026-11-25 |
|---|---|---|---|
| Regulation (EU) 2024/1689 (AI Act), as amended by Regulation (EU) 2026/1744 | Article 12 record-keeping; Article 19 logs kept by providers | 10, 11, 13 | high-risk obligations apply from 2 December 2027 (Annex III) and 2 August 2028 (Annex I) |
| | Article 14(4) measures that let a person oversee, intervene and stop | 3, 6, 14 | as above |
| | Article 26(2) and 26(6) deployers assign oversight and keep logs | 3, 13, 14 | as above |
| ISO/IEC 42001:2023, Annex A | controls on event logs and on responsible use | 10, 14 | certifiable |
| OWASP Top 10 for Agentic Applications 2026 | ASI02 Tool Misuse and Exploitation; ASI03 Identity and Privilege Abuse; ASI09 Human-Agent Trust Exploitation | 1, 2, 3, 6 | a risk list, not a requirement |
| NIST AI Risk Management Framework and the agent identity and authorization work at NIST | - | - | in progress; nothing final to cite as a requirement |

These obligations fall on the provider or deployer of a high-risk AI
system. Gargoyle is neither; it is a component such a party may use to
produce the records.

## 6. Limits that bear on these mappings

### 6.1 The approval page is served by the issuer's operator

SPEC.md section 8.3 states it: the approver's key never leaves the
browser, but the page that asks it to sign comes from the issuing service.
An operator who alters that page can have an approver's key sign a release
the approver did not see, and the grant verifies. Rows 3 and 6, and eIDAS
Article 26(c), are limited by this until a mitigation is built. Until
then, the operator of the issuer and the approvers are to be different
people, and the deployment's control description should say so.

### 6.2 The grant does not carry the time and meaning of the signature

The grant's signed fields are listed in SPEC.md section 8. The time of
release, the approver's printed name and the meaning of the act
(`approval`, `rejection`, `withdrawal`) are in the issuer's witness entry
(section 15.1), signed by the issuer, not by the approver. A reviewer
holding a grant alone does not see them.

### 6.3 Records are complete only up to the last recorded tail

See row 10. The practice that closes it is the reviewer's: record the tail
hash that `gargoyle audit` prints, and the witness head, at each audit.

### 6.4 Action around the gate is detected, not prevented

See rows 1 and 9, and "What Gargoyle does not do" in the
[README](../README.md).

## 7. Wording used in this project

Used: "implements human oversight and record-keeping for agent actions";
"evidence of who released what, against which state, under which policy";
"detects, not prevents, action around the gate"; "tamper-evident".

Not used, in any document or page: a statement that Gargoyle or a
deployment of it complies with, or is certified to, any instrument named
here; that it stops misuse; or that its records cannot be altered. They
can be altered; the alteration is detected.

## 8. What was checked, and when

- Mechanisms, codes and section numbers: read from SPEC.md at commit
  `d2b0e92` on 2026-11-25.
- Clause titles: from the published text of each instrument as the author
  knows it. The text of ISO/IEC 27001, ISO/IEC 42001 and PCI DSS was not
  open during writing; confirm titles against your licensed copy.
- AI Act dates: Regulation (EU) 2026/1744 was published on 24 July 2026
  and entered into force on 27 July 2026; the two application dates above
  are as reported by several law-firm summaries read on 2026-11-25, not
  from the Official Journal text. Article numbers were not re-checked
  against the consolidated text.
- FedRAMP AU-10 parameter and the OWASP entry names: read on 2026-11-25.

A dated entry is added here when any of these is checked again.
