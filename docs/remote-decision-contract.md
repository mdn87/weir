# Remote decision relay contract

Batch 8 uses a signed outbound pull design. It does not expose Fade or WEIR on the
network, and it does not route approval through HUD's shared bearer. A workstation
polls a separate relay service only when both Fade ingress flags are explicitly
enabled. All related source flags default off. The operator separately approved the
first production deployment on 2026-08-29, and its bounded synthetic canary passed;
see [`acceptance/batch8-remote-relay-20260829.md`](acceptance/batch8-remote-relay-20260829.md).

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

## Implementation and deployment boundary

WEIR still owns only the portable contracts and verification helpers and has no remote
listener or credential. Mission Control now has a passkey-gated decision route and a
separate least-privilege relay process. The relay uses an isolated SQLite queue, signs
with Ed25519, accepts enqueue only on loopback, and exposes only TLS 1.3/mTLS pull to
the pinned workstation. Fade initiates every cross-host connection, verifies the
certificate-bound transport principal and signed capsule, reserves it durably, checks
revocation, and then invokes the existing loopback authority. Fade remains the permit
authority and reloads the authoritative proposal before dispatch.

These flags default to false across the design:

```text
MC_REMOTE_DECISIONS_ENABLED=false
LUGOS_RELAY_ISSUER_ENABLED=false
FADE_REMOTE_RELAY_ENABLED=false
FADE_WEIR_RELAY_INGRESS_ENABLED=false
```

An off-path test must prove that false means no queue write, signature, network call,
or local dispatch.

## Frozen first-activation decisions

The first deployment choices are now concrete:

1. Mission Control actors use `mc:user:<numeric local user ID>`.
2. `knot.newman.foo` supplies the HTTPS origin for user-verifying WebAuthn passkeys;
   password reauthentication owns enrollment and recovery.
3. `lugos-host` runs the relay as restricted user `lugos-relay`; Mission Control talks
   to loopback `127.0.0.1:8792` and `4070pc` pulls from `10.0.1.33:8793`.
4. The workstation generates its P-256 key. The host CA signs one client certificate
   bound to `workstation-4070pc` / `relay-device:4070pc`; UFW admits only
   `10.0.1.30`.
5. The host keeps the Ed25519 signing key root-readable and exposes it to the relay via
   systemd credentials. Fade accepts one to three pinned public keys for rotation.
6. Terminal capsule bodies are purged within five minutes. Redacted uniqueness,
   transition, acknowledgement, and audit anchors remain durable.

The first enabled policy remains limited to the reversible synthetic public-data
action. Purchases, messages, account changes, uploads, credentials, and production
forms require a separate authority decision.

The reusable activation runner is `scripts/run_remote_relay_canary.py`. It publishes
one redacted `proposed` event, waits for an exact passkey decision, verifies the mTLS
and signed-capsule bindings, executes the workstation-local fixture once, restarts the
poll loop to prove replay safety, and publishes the terminal event. It also records
the installed `apu-watch` attribution health; `apu-watch` is not misclassified as a
generic process supervisor.

## Verification

```powershell
python scripts/generate_remote_relay_fixtures.py
python -m pytest -q tests/test_remote_decision.py tests/test_remote_relay_fixtures.py
node scripts/verify_remote_relay_fixtures.ts
```

The complete repository gate remains `python -m pytest -q`.
