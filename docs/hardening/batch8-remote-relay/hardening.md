# Security Hardening Review: Batch 8 Remote Approval Relay

## Evidence Basis

I inspected the frozen WEIR decisions and the current Fade, HUD, Mission Control, and
lugos-link boundaries at the revisions recorded in [context.md](context.md). The
current path is intentionally safe because remote approval is absent: Fade and WEIR
stay on loopback, Mission Control authenticates an operator, and HUD has no WEIR
decision command or identity-preserving route.

The structural issue is not basic connectivity. It is carrying one human decision
across two hosts without turning a shared service credential, delayed queue entry, or
compromised browser into reusable action authority.

## Constraints

- Fade and WEIR action services remain bound to loopback.
- The relay never receives action parameters, DOM, credentials, or reusable permits.
- Approval binds the exact `command_id`, `proposal_hash`, `action_id`, and
  `work_context_hash`; Fade reloads the authoritative proposal.
- Human operator identity and relay transport identity remain distinct and auditable.
- Offline, expired, replayed, revoked, or ambiguously acknowledged approvals fail
  closed and cannot become a later action.
- Batch 8 remains disabled until the local Batch 9 canary succeeds.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Preserve human authority across a remote, asynchronous boundary | Loopback authority, identity loss at the HUD hop, and existing network options (`E1`–`E13`) | 1. Local-only baseline; 2. authenticated tunnel; 3. signed outbound pull relay | Option 3 after the local canary | [Remote decision capsules](proposals/remote-decision-capsules.md) |

## Recommendation Summary

I recommend Option 3: a workstation agent makes an outbound authenticated connection
to a bounded relay queue and accepts only short-lived, signed, parameter-free decision
capsules. Mission Control must reload the current projection, bind the authenticated
operator, and require explicit step-up confirmation before the relay signer issues an
approval. Fade verifies the capsule locally and records both the human actor and the
relay transport principal before using its existing proposal-reload and permit path.

This costs a small durable queue, a signing-key lifecycle, and a supervised workstation
agent. Those costs are proportionate because they avoid exposing Fade through a tunnel,
make delayed approvals expire deterministically, and preserve identity without trusting
the browser to restate action details.

## Next Decisions

Implementation update (2026-08-28): WEIR now owns the frozen, parameter-free capsule,
queue, acknowledgement, revocation, and redacted-audit contracts plus deterministic
Ed25519 Python/TypeScript vectors. This is disabled source scaffolding only; it adds no
listener, signer deployment, credential, or remote authority. The decisions below and
the required post-implementation review still gate positive enablement.

- Accept, modify, or reject Option 3 after the local synthetic canary evidence exists.
- Choose the step-up mechanism; WebAuthn/passkey user verification is preferred.
- Choose the authenticated outbound transport available on both deployed hosts; HTTPS
  with per-device mTLS is preferred, while Tailscale may carry but must not replace
  application identity.
- Set measured delivery and retention bounds during implementation; the proposal gives
  initial acceptance thresholds rather than claiming measured performance.
