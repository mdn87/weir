# Batch 0 contract freeze

Status: frozen on 2026-08-27 after Fable accepted D1–D12 with A1–A9 and
C1–C6. Browser action execution remains disabled.

The executable interchange fixture is
`contracts/fixtures/batch-0-v1.json`. Its raw file digest is published beside it
in `batch-0-v1.sha256`; the fixture also contains canonical digests for every
positive document and every referenced schema. Consumers copy the fixture and
pin those digests so their standalone tests do not require a sibling checkout.

## Frozen contract versions

| Contract | Version | Authority |
| --- | --- | --- |
| `WorkContext` | 0.1 | Authenticated orchestrator creates the immutable root |
| `AcquisitionEnvelope` | 0.1 | WEIR validates full context plus request |
| `EvidenceReference` | 0.1 | WEIR binds reusable capture content to one context |
| `ActionProposal` | 0.3 | WEIR proposes; it grants no authority |
| `ExecutionPermit` | 0.1 | Fade issues; WEIR validates and consumes once |
| `ExecutionReceipt` | 0.3 | WEIR records the effect outcome |
| `QuarantineRecord` | 0.1 | WEIR appends active and operator-cleared records |
| correlation header | schema version 1 | Every producer carries the same identity fields |
| WEIR action event | schema version 1 | WEIR constructs already-redacted public metadata |

Proposal, permit, and receipt versions are independent from the browser
session/observation version. A change to one no longer bumps every browser
contract. Read-only schemas for ActionProposal v0.2 and ExecutionReceipt v0.2
remain under `contracts/legacy/` for the published retention window; new producers
must emit the versions in the table.

## Canonical JSON and hashes

Hashed contracts use UTF-8 JSON with recursively sorted keys, no insignificant
whitespace, and a `sha256:` prefix. The hash basis is the complete object except
its own `*_hash` field. Extensible proposal parameters use lowercase ASCII keys,
integers within the IEEE-754 safe range, and no floats; this keeps Python and
TypeScript hashes identical.

`WorkContext.evidence_refs` contains caller-supplied inputs known when the root
is created. It is an immutable tuple at runtime and an array in JSON. Acquisition
outputs never accumulate there; each output gets a separate
`EvidenceReference` bound to `context_hash`.

For retained capture content, the materialized artifact is exactly the canonical
JSON bytes of `WebCapture.content` after truncation. Hashing those bytes must
equal `EvidenceReference.content_hash`, and the opaque artifact reference embeds
the same digest. A metadata-policy reference has no artifact and cannot satisfy
a content evidence input. Cache identity includes both `capture_policy` and
`max_capture_bytes`.

At Autowork's assignment boundary, evidence agreement uses `correlation_id` and
`assignment_id`. `DispatchRequest` does not invent a pre-parse `run_id`; the
orchestrator attests the later run linkage.

## Authority, expiry, and redaction

WEIR service authentication uses named clients with separate secrets outside
contracts and logs. `lugos-mcp` receives acquisition/read scopes; Fade's WEIR
authority service receives its own action scope and must not reuse Aire's
credential.

WEIR's clock decides permit validity. Maximum tolerated clock skew is 5 seconds,
Fade must leave at least 15 seconds of dispatch margin, and permit lifetime is
30–300 seconds. A permit has `use_limit=1`; durable reservation happens before
the browser effect. Reuse or content mismatch is rejected.

Action parameters, including `fill` and `select` form values, travel only in the
authenticated full-authority proposal channel and carry `parameter_data_class`.
The WEIR action-event schema has a closed allowlist and cannot contain parameters,
DOM, page bodies, prompts, credentials, cookies, private profile IDs, or reusable
permits. This redaction happens at producer construction because HUD reads are
currently unauthenticated. Proposal and permit field names also avoid Fade's
recursive `FORBIDDEN_KEYS` vocabulary.

## Unknown outcomes and quarantine

`ExecutionReceipt.result=outcome_unknown` is distinct from failure. It keeps the
pre-effect capture and durable reservation reference, carries no verification or
post-state claim, and requires a `weir-quarantine:` reference. New permits for
that session must be rejected while the corresponding active quarantine exists.

A restart, retry, timeout, or expired permit never clears quarantine. An operator
creates a new `QuarantineRecord(state=cleared)` that names the active record hash;
the active record remains in the append-only history.

## Retention

- Evidence references and their available artifacts: at least 90 days. A stricter
  data-class policy may forbid artifact persistence, in which case the reference
  cannot be used as a materialized content input.
- Permits and receipts: at least 400 days.
- Active unknown outcomes: until operator disposition, with no time-based expiry.
- Cleared quarantine history: at least 400 days after disposition.

These are reader-compatibility and audit minimums. Batch 0 does not add a deletion
job or weaken a longer deployment policy.

## Consumer conformance

Regenerate and verify the fixture after a deliberate contract change:

```bash
python scripts/generate_contract_fixtures.py --write
python scripts/generate_contract_fixtures.py
node scripts/verify_contract_fixtures.ts
python -m pytest -q tests/test_contract_fixtures.py
```

The fixture's negative documents freeze rejection behavior and reason codes.
Its `integration_invariants` section also records the sibling-owned APU attribution
shape and C1–C6 version/deployment edges. Those entries are executable review
inputs, not WEIR claiming ownership of Dias, Autowork, Fade, HUD, Mission Control,
`lugos-mcp`, or APU schemas.

The Fade action canary, Dias receipt-store schema, and APU watcher deployment still
need their own operator approvals when their implementation batches reach those
mutating steps.
