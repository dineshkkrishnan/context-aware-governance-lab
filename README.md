# Context-Aware Governance Lab

A dependency-free Python policy sandbox that evaluates **synthetic** document-access requests using role, purpose, classification, channel trust and an anomaly flag. Produces allow/review/deny decisions with reasons and minimal hash-linked audit records.

Independent portfolio experiment by Dinesh Kumar Krishnan. No employer data, patient data or live integrations.

## Publication connection
Inspired by [AI-Enabled Information Governance for Healthcare Productivity Systems: Addressing Limitations of Traditional Data Loss Prevention](https://computerfraudsecurity.com/index.php/journal/article/view/1099/792), Computer Fraud and Security, 2026.

This implements a transparent **rule-based baseline**, not the publication's broader AI architecture. Classification and anomaly labels are supplied in the synthetic input; this code neither discovers PHI nor trains a classifier. It does not reproduce the paper's findings or demonstrate regulatory compliance.

## Run
Requires Python 3.11 or newer, with no pip packages or API keys.

```bash
python3 app.py
python3 app.py --verify output/audit.json
python3 -m unittest discover -s tests -v
```

Expected sample decision counts: `{"allow": 3, "deny": 5, "review": 4}`.
The output is `output/audit.json`. A checked-in demonstration is in [examples/audit.json](examples/audit.json).

## Input contract
JSON array of requests with unique nonempty `request_id` and fields:

| Field | Accepted values |
| --- | --- |
| resource_id | Nonempty fictional identifier |
| role | engineer, analyst, clinician, auditor, external |
| purpose | operations, analytics, care, audit |
| classification | public, internal, sensitive, restricted, unknown |
| channel_trust | trusted, untrusted, unknown |
| anomalous | Boolean, not a string |

Actor identity, role, purpose and trust are **unverified input assertions** in this lab. A real enforcement system must bind them to authenticated identities and trusted context. Unknown or malformed context never returns allow. Invalid/missing request IDs and duplicate IDs reject the batch; other invalid contexts create a review decision.

## Policy order
1. Invalid schema or unsupported context → review.
2. Internal role/purpose mismatch → deny.
3. Unknown classification → review.
4. Restricted resource → deny for every role.
5. External role with nonpublic content → deny.
6. Untrusted channel with nonpublic content → deny.
7. Anomaly flag → review.
8. Unknown channel trust → review.
9. Sensitive content for a role other than clinician/auditor → deny.
10. Remaining context → allow.

Role-purpose pairs are engineer/operations, analyst/analytics, clinician/care and auditor/audit. External users can only receive public classifications after the remaining checks. These deliberately simplified choices are lab policy, not recommended healthcare access rules. The reason identifies the first matching rule.

## Audit design
Records contain sequence, request/resource IDs, policy version, decision, reason, previous hash and record hash. Document bodies, emails and supplied extra fields are not copied to the audit.

SHA-256 links detect changed records and broken ordering when hashes are not recomputed. **This is not immutable storage or cryptographic proof of authenticity.** An attacker can rewrite the entire chain or truncate its tail; without an independently anchored terminal hash, those changes may remain undetected. Empty chains are valid. Audit IDs must remain fictional; identifiers can themselves be sensitive.

## Scope and tests
This is an evaluator, not an access enforcement service. `review` does not contact a reviewer; `allow` does not open a document. No semantic classification, behavioral model, authentication, network endpoint, encryption, persistent append-only service or compliance certification.

Tests cover role/purpose boundaries, sensitivity, external access, unknown context, anomaly precedence, input types, duplicate IDs, content minimization and audit-chain tampering.

## Next experiments
- Add a synthetic labeled dataset and compare a semantic classifier against this baseline.
- Measure false approvals, false denials and review burden against independently defined expected decisions.
- Introduce authenticated context and externally anchored audit hashes in a separate integration lab.

The example counts are execution results, not accuracy metrics. There is no independent ground-truth evaluation yet.

Prepared with AI assistance. Review the policy and tests and explain their limitations before presenting this as portfolio work.
