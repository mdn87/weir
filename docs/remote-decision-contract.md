# Remote decision relay contract

Batch 8 uses a signed outbound pull design. It does not expose Fade or WEIR on the
network, and it does not route approval through HUD's shared bearer. A workstation
agent may eventually poll a separate relay service, but every related feature flag
remains off until the post-implementation review and a separate enablement approval.

## Frozen WEIR contract

`RemoteDecisionCapsule/v1` carries only the identifiers needed to bind one human
decision to one proposal:

- `command_id`, `proposal_hash`, `action_id`, and `work_context_hash`;
- the authenticated human `actor_id`, target `device_id`, issuer, and audience;
- `issued_at`, `expires_at`, a 128-bit nonce, and an opaque SHA-256 `step_up_ref`;
- the Ed25519 `key_id` and signature over canonical WEIR JSON excluding only the
  signature field.

The exact-set schema has no extension or generic payload field. Action parameters,
DOM, prompt text, evidence bodies, credentials, cookies, private profile IDs, and
permits cannot be represented. Capsules are limited to 8 KiB and 120 seconds. The
verifier pins the issuer, audience, device, and public key; it accepts no future issue
time and applies only the accepted five-second expiry skew.

The companion contracts define:

- append-only queue records for `queued`, `claimed`, `acknowledged`, `denied`,
  `expired`, and `revoked` states;
- terminal workstation acknowledgements with human `actor_id` and authenticated
  `transport_principal` as separate fields;
- durable revocation records; and
- a redacted audit record, including a one-way nonce digest for durable uniqueness,
  retained after the capsule body is purged.

`outcome_unknown` is terminal and never authorizes another effect. A claim is a lease,
not action authority. The live queue cap is 1,024 entries.

The canonical schemas, deterministic Ed25519 vectors, negative cases, and
Python/TypeScript parity checks are in:

- `contracts/remote-decision-*.schema.json`;
- `contracts/fixtures/remote-relay-v1.json`;
- `scripts/generate_remote_relay_fixtures.py`;
- `scripts/verify_remote_relay_fixtures.ts`; and
- `tests/test_remote_decision.py` plus `tests/test_remote_relay_fixtures.py`.

## Disabled source boundary

WEIR owns the portable contracts and verification helpers only. It has no remote
listener, queue server, relay credential, signer key, or production decision route.
The planned issuer is a separate least-privilege process beside Mission Control, and
the planned workstation client initiates every cross-host connection before presenting
a verified capsule to a flag-gated Fade loopback endpoint. Fade remains the permit
authority and must reload the authoritative proposal before dispatch.

These flags default to false across the design:

```text
MC_REMOTE_DECISIONS_ENABLED=false
LUGOS_RELAY_ISSUER_ENABLED=false
FADE_REMOTE_RELAY_ENABLED=false
FADE_WEIR_RELAY_INGRESS_ENABLED=false
```

An off-path test must prove that false means no queue write, signature, network call,
or local dispatch.

## Decisions required before enablement

Source fixtures do not choose production operations. Before any positive remote
canary, the operator and post-implementation security review must approve:

1. the stable Mission Control actor identifier format;
2. the WebAuthn/passkey identity provider, enrollment, and recovery owner;
3. the separate relay process placement and operational owner;
4. the relay hostname, CA, mTLS enrollment, and device-revocation lifecycle;
5. signer-key custody, rotation overlap, and emergency revocation; and
6. audit retention plus the exact terminal capsule-body purge deadline.

The first enabled policy remains limited to the reversible synthetic public-data
action. Purchases, messages, account changes, uploads, credentials, and production
forms require a separate authority decision.

## Verification

```powershell
python scripts/generate_remote_relay_fixtures.py
python -m pytest -q tests/test_remote_decision.py tests/test_remote_relay_fixtures.py
node scripts/verify_remote_relay_fixtures.ts
```

The complete repository gate remains `python -m pytest -q`.
