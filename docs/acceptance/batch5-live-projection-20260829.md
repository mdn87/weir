# Batch 5 Live Projection Acceptance — 2026-08-29

Status: **live Mission Control/HUD acceptance passed**. The remote decision relay
remains disabled.

## Release identity and activation order

- Target: known-good SSH alias `lugos-host`, corroborated by SSH config and
  `lugos-link` inventory as `matt@10.0.1.33`.
- Lugos parent release: `d741dd363ff638038ee9a36c03be382a733c9436`.
- Mission Control child: `203a1989077cc6b5d0f88f57462f6fdb5227f070`.
- Rollback release: `91cefb87486bb941d404ad47dea95af7eb8ba4fd`.
- Both `lugos-mission-control.service` and `lugos-operator-api.service` were active
  after deployment, with zero error-priority journal entries during activation.

The parent release changes the installer itself: Mission Control now restarts and
must proxy an authenticated snapshot from the still-running old operator API before
the operator API producer restarts. The final gate then probes both the producer and
the Mission Control proxy. This makes consumer-first compatibility a repeatable
deployment invariant rather than a one-off manual sequence.

Local verification before deployment passed:

- `python -m pytest tests/test_mission_control_deploy.py -q`: 2 passed;
- `bash -n install-lugos-mission-control.sh`: passed; and
- the Lugos root suite: 3,760 passed, 51 skipped.

## Live snapshot and SSE evidence

Both the operator API and authenticated Mission Control proxy returned exactly:

```text
autowork,task-loop,weir,fleet,cockpit-diagnostics,bran-readiness
```

The WEIR snapshot schema was `lugos-hud-weir/v1`. A recursive field check found none
of `parameters`, `form_values`, `credential`, `permit`, `profile_id`, or
`page_content` in the projected response.

The projection-only canary appended synthetic cancelled event
`event-hud-projection-canary-mtdwa6ni`; it invoked no browser action, permit, or
effect. Mission Control received a `projection.snapshot` SSE event, the subsequent
snapshot retained `state=cancelled`, and neither carried the synthetic authority
marker or its field names. An authenticated POST to
`/api/lugos/remote-decisions` returned HTTP 404, proving Batch 8 remained disabled.

## Canary-found event-journal follow-up — closed

The generic event-ingest redactor removed the nested `secret` but did not remove the
synthetic top-level `credential` marker before writing the append-only journal. This
did not cross the HUD/Mission Control construction-time allowlist, but it exposed an
upstream custody gap.

Parent commit `6f0b8cf4de6bd47da30ce8729b37dbedb1e2d392` fixes the source redactor for
credentials plus WEIR's authority-only fields while preserving `proposal_hash` and
`permit_hash`; all 26 event-ingest tests pass. The operator approved its separate
production rollout, and the copied runtime source on `lugos-host` was replaced and
`lugos-event-ingest.service` restarted at 2026-08-29 00:57:54 EDT.

The live runtime digest is
`e0301a1fd71ed2e2830c93f2968d589780572a56afbf4fe5b6b2c3c714e3b4df`.
The prior source is recoverable at
`/srv/lugos/releases/lugos-event-ingest/20260829T045754Z-pre-6f0b8cf4de6bd47da30ce8729b37dbedb1e2d392/redaction.py`.
The service is active and enabled, `/health` reports the primary node healthy, and
the journal contains no error-priority entries after the successful restart.

Authenticated synthetic event
`event-event-ingest-redaction-20260829T045917Z` then exercised the live HTTP and
append-only journal path. Its ten authority or credential fields were all persisted
as `[REDACTED]`; the unique marker prefix was absent from the stored record; and its
`proposal_hash` and `permit_hash` remained intact. The canary was already in the
terminal `cancelled` state and invoked no browser action, permit, or effect.

An initial guarded restart attempt automatically restored the prior file because its
health probe used loopback while this service intentionally binds only to
`10.0.1.33:8787`. The corrected rollout used the configured bind address and passed.
The earlier retained marker is synthetic test data, not a credential, and remains in
the journal as audit evidence.
