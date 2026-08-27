# WEIR Roadmap

This roadmap is exploratory. Engine promotion and final authority ownership require evidence.

## P0 - Contracts and benchmark harness

- [x] Define subsystem boundary and name.
- [x] Seed core data contracts.
- [x] Seed read-only `oc` and `agent-browser read` adapters.
- [x] Validate schemas against fixtures.
- [x] Build repeatable benchmark runner.
- [x] Add task corpus for public acquisition.
- [x] Record engine versions and normalized metrics (oc exposes no version; tracked via package manifest).
- [x] Produce first route comparison report (`benchmarks/reports/first-route-comparison.md` — directional, not a promotion decision).

Gate: WEIR can run the same read task through multiple engines and compare normalized evidence without callers depending on engine syntax.

## P0.5 - Marketplace vertical slice (eBay -> Lode)

First real consumer-driven slice. Proves the connector rung and enrichment ladder
against live work instead of a synthetic corpus. Full design: `docs/marketplace-slice.md`.

- [x] Decide `search` mode vs. overloaded `discover` for structured search (new `search` mode; requires query + source).
- [x] Define the result-set / normalized-listing capture shape (`contracts/marketplace-listing.schema.json`; set rides in WebCapture content).
- [x] Implement the `ebay` connector engine (`weir search` → Browse API item_summary; `weir read --engine ebay` → item by legacy id; live-verified against production with the Lode keyset).
- [x] Implement enrichment fallback (`weir enrich`: oc → agent-browser-read page rung; browser observe waits for P2).
- [x] Return immutable, hashed, provenance-bearing listing captures (per-listing state hash excludes observed_at).
- [x] Prove Lode can consume WEIR captures in place of its own eBay collector (Lode `WeirCollector`, vein `collector = "weir"`; live-verified: 50 production listings end-to-end with WEIR provenance in listing attributes).

Gate: Lode obtains normalized eBay listings (with enrichment fallback) through WEIR by
intent, and the same evidence bundle is comparable across providers.

## P1 - Public acquisition broker

- [x] Add route classifier (seed: connector vs compact_reader, deterministic reasons; `weir route`).
- [x] Add connector/API adapter interface (generic `http` engine; eBay slice to build on it).
- [x] Add a reusable acquisition broker so CLI and library callers share routing, policy, fallback, and capture behavior.
- [x] Add capture hashing and artifact persistence boundary (optional immutable manifests + content-addressed artifacts).
- [x] Add deterministic reader fallback reasons (auto-read fallback chain; policy blocks abort, never fall through).
- [x] Add domain policy (initial + returned targets for every engine; per-hop enforcement in the HTTP connector).
- [x] Bound normalized output (5 MiB reader limit; structured results fail rather than break their contract).
- [x] Add cache policy by data class (shared cache only for unauthenticated public evidence).
- [x] Add site profiles only where benchmark evidence supports them (GitHub public + live eBay slice).
- [x] Add metadata-only AITU-compatible spans (`web.route`, fetch/search, fallback, cache, persistence).

Gate met (2026-08-27): public research callers can use `AcquisitionBroker` or the CLI
to acquire sources with provenance, bounded output, deterministic fallback, optional
immutable persistence, and no authenticated browser dependency.

## P2 - Browser session broker

- [x] Define the versioned browser command protocol and digest-bound command envelope.
  The result-envelope schema is a remote-transport target; current in-process workers
  still return typed Python values directly.
- [x] Add a contained `agent-browser` session adapter (ephemeral observation only;
  persistent profile/state/CDP modes are rejected because they conflict with its domain allowlist).
- [x] Add a direct Playwright comparison adapter (fresh nonpersistent contexts,
  opaque read-only profile-state provider, JavaScript disabled, GET/HEAD-only
  transport, pinned DNS, observation only).
- [x] Add profile isolation and one-live-session reservations per worker-local profile
  namespace. Global cross-worker credential locking requires a store-schema decision.
- [x] Add expiring controller leases with monotonic fencing generations.
- [x] Add same-owner recovery, durable per-session command reservation, worker-context
  quarantine, and fenced manual takeover/return semantics.
- [ ] Add an authorized, audited dead-worker reservation retirement path; until then,
  unacknowledged OPEN dispatches remain quarantined and direct store edits are unsupported.
- [ ] Move the Playwright adapter behind a killable worker-process boundary with a
  broker-enforced wall-clock deadline plus OS memory and egress limits. Declared
  response-size checks are defense in depth, not a substitute for process containment.
- [x] Add structured observations and deterministic semantic locators.
- [x] Add immutable browser-observation and screenshot evidence capture.
- [ ] Add a reversible DOM-interaction worker surface only after it accepts an
  authorization permit rather than a raw action request.

Gate status: observation passed against a local authenticated Playwright fixture with
session isolation and durable evidence. DOM interaction remains intentionally closed,
so the full observe-and-interact gate is not yet met.

## P3 - Action authority integration

Cross-repository sequence and proposed ownership decisions:
`docs/sibling-integration-plan.md`.

- [ ] Confirm Fade authorization/coordinator ownership and WEIR browser effect-driver
  ownership; do not collapse both roles into one ambiguous "executor."
- [x] Compile observations into hash-bound `ActionProposal` objects.
- [x] Add a non-downclassifiable risk taxonomy.
- [x] Add a default-deny approval authority interface.
- [ ] Connect an authenticated Fade/Operator approval authority.
- [ ] Reacquire state immediately before execution.
- [x] Add deterministic semantic post-action verification and `ExecutionReceipt` contracts.
- [ ] Produce receipts from a real authorized executor.
- [ ] Add bounded recovery patterns.

Gate: a staged external action cannot execute without policy evaluation and, when required, explicit approval; success is proven by post-state evidence.

## P4 - Lugos integration

- [x] Define explicit, hashed `WorkContext` identity for objective/run/assignment/correlation provenance.
- [ ] `lugos-mcp` surface.
- [ ] task-router integration.
- [ ] run-profile policy.
- [ ] Autowork campaign integration.
- [ ] Sulis provenance/summary records.
- [ ] AETA source-capture handoff.
- [x] Add a metadata-only browser session/event journal suitable for AITU/HUD projection.
- [ ] Register that journal with the AITU/HUD integration surfaces.
- [ ] HUD session/evidence/approval views.
- [ ] COGIN/APU behavior-registry feedback.

Gate: multiple Lugos seats can request web capabilities without direct engine knowledge, and route decisions are observable.

## P5 - Visual fallback

- [x] Screenshot evidence adapter with content-addressed binary retention.
- [ ] Targeted crop evidence adapter.
- [ ] Argus interpretation contract.
- [ ] Visual verifier.
- [ ] Ambiguity classification.
- [x] Manual takeover path with atomic pause/fence rotation/return.

Gate: structured-browser failures can escalate to visual interpretation without bypassing action policy.

## Deferred

- automatic site-profile generation
- large-scale web crawling
- generalized credential brokerage
- arbitrary autonomous purchasing
- online self-training from browser activity
- WEIR-owned model routing
