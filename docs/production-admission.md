# Production worker admission

WEIR production admission is a live fail-closed check, not a deployment flag. An
authenticated caller cannot execute an action merely because the HTTP route, client
credential, or effect driver exists. The host must supply current evidence for every
control in this document, and that evidence must bind the exact worker process and
caller.

The source implementation does not create service accounts, credentials, ACLs,
firewall rules, cgroups, network namespaces, or background services. Those are host
deployment changes with their own operator approval. It also does not add a production
effect adapter; the only supplied positive action policy remains the reversible local
synthetic fixture.

## Admission contract

`ProductionControlEvidence` is immutable, hash-bound, exact-set data containing only
control metadata:

- the platform, restricted service identity, worker ID, worker instance, and PID;
- process-tree, parent-death, memory-limit, and process-count evidence;
- one ACL-policy digest and opaque protected-source ID per caller identity;
- the lifecycle supervisor and its current healthy instance;
- an OS egress-policy ID, digest, and enforcement result; and
- a bounded verification and expiry window.

It never contains a credential value, cookie, browser storage state, profile ID, URL,
action parameter, or reusable authority. A caller must have exactly one protected
credential-source entry. The evidence lifetime cannot exceed five minutes, and WEIR
uses the frozen five-second clock-skew rule at admission.

`ProductionAdmission` reloads evidence from an injected host inspector for every
browser-worker or external-action admission. Missing, expired, malformed, wrong-host,
wrong-worker, caller-mismatched, or incomplete evidence raises a policy denial before
worker use. A request cannot submit or override admission evidence.

`LocalSyntheticActionAdmission` is a separate explicit type. It accepts only
`SyntheticFixtureEffectPolicy`, whose origin is an HTTP loopback IP and whose actions
remain public and reversible. Supplying an action driver without either admission gate
leaves `POST /v1/actions/execute` unavailable; status reconciliation remains readable
to the existing Fade identity.

## Process enforcement

`ProcessBrowserWorker` exposes `containment_evidence` and accepts explicit
`WorkerResourceLimits`.

- On Windows, WEIR applies Job Object kill-on-close, job-memory, and active-process
  limits before allowing the child to construct the browser worker.
- On Linux, the existing process group is not misrepresented as a cgroup or network
  namespace. Resource-limited startup requires a trusted prepared-containment verifier
  that proves the exact child PID inherited the requested cgroup v2 controls. Missing
  evidence fails startup.

The containment record alone is insufficient. Production admission also requires
current restricted-identity, credential-protection, lifecycle, and OS egress evidence.
Worker-death evidence remains separate and never releases a credential reservation.

## Host rollout checklist

The deployment owner must perform and independently read back these controls before
constructing `ProductionAdmission`:

1. Run WEIR under a dedicated non-administrator/non-root identity and prove the worker
   inherited that identity.
2. Provision a distinct caller credential for each client. Restrict each source to the
   service identity and its intended provisioner; hash the normalized ACL policy, not
   the credential bytes.
3. Install lifecycle supervision with readiness, heartbeat, restart limits, and a
   stable instance identifier.
4. On Windows, configure a firewall/AppContainer-equivalent default-deny worker egress
   policy. On Linux, configure cgroup v2 plus a dedicated network namespace and
   nftables-equivalent policy.
5. Have the trusted host inspector verify the live service, worker PID, ACLs,
   supervisor, limits, and egress policy and issue short-lived evidence.
6. Run a denial-only probe first. A missing inspector, stopped supervisor, altered ACL,
   expired record, wrong PID, or disabled firewall rule must invoke no worker.
7. Keep all action flags off until an independently reviewed production effect adapter
   and a separately approved host canary exist.

Rollback disables producers and action admission while retaining captures, permits,
reservations, receipts, quarantines, and control evidence for the applicable audit
window. It never converts stale evidence into an allow decision.

## Verification

Run the focused admission gate:

```powershell
python -m pytest -q tests/test_browser_admission.py tests/test_process_worker.py `
  tests/test_browser_broker.py tests/test_client_service.py tests/test_effect_driver.py
```

The complete repository gate remains `python -m pytest -q`.
