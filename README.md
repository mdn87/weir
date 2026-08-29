# WEIR

**Web Evidence, Interaction & Retrieval**

WEIR is the proposed web capability plane for the Lugos ecosystem. It provides one typed boundary for public web acquisition, authenticated browser observation, browser interaction, evidence capture, engine routing, and escalation to visual fallbacks.

WEIR is not a browser, search engine, autonomous agent, or second orchestrator. It is the subsystem that lets Lugos ask for web capabilities without coupling callers to a specific implementation such as `oc`, `agent-browser`, Playwright, Chromium/CDP, or a service-specific API.

## Thesis

Web work in Lugos should be routed by required capability and authority, not by whichever browser tool happens to be installed.

```text
User / CLI / HUD / ORCA seat
             |
             v
    task-router + run profile
             |
             v
          Autowork
             |
             v
           WEIR
   request + engine routing
   sessions + observations
   captures + evidence
      |       |       |
      v       v       v
 connector  reader   browser
 / API      engines  engines
      \       |       /
       \      |      /
        typed result
             |
      action proposal
             |
             v
     Fade / approval boundary
             |
             v
 Validation -> Sulis -> AITU -> HUD
```

The critical separation is between **observation** and **authority**. WEIR may discover, read, observe, and propose. Consequential side effects should cross the Lugos execution and approval boundary rather than being silently performed by an arbitrary browser engine.

## Two web planes

### Public acquisition

For public, credential-free work:

- search and discovery
- documentation and articles
- forums and repositories
- public APIs, feeds, Markdown, and `llms.txt`
- source capture and provenance
- comparison and research

This lane should be cheap, aggressively cacheable, easy to parallelize, and safe to run without browser profiles.

### Authenticated operations

For stateful web applications:

- existing login sessions
- account dashboards
- authenticated downloads
- form preparation
- staged uploads
- settings and administrative workflows
- other actions that can produce external side effects

This lane requires isolated profiles, controller leases, explicit risk labels, approval policy, post-action verification, and stronger artifact retention rules.

The two lanes share typed contracts. They do not share authority.

## Preferred capability ladder

WEIR should select the highest-level reliable interface that satisfies the task:

```text
1. Connected service / direct API
2. Public Markdown, feed, JSON, or compact HTTP reader
3. JavaScript-rendered DOM / accessibility observation
4. Reversible browser interaction
5. Consequential browser action through approval authority
6. Visual interpretation fallback
7. Human takeover
```

A failed compact reader is a routing event, not permission to improvise.

## Engine candidates

Initial evaluation targets:

- `oc` from `only-cli/oc` as a compact public reader
- `agent-browser read` as a non-Chrome or rendered-session reader
- `agent-browser` as a managed Chromium interaction substrate
- direct Playwright/CDP as a lower-level browser engine
- direct service APIs/connectors when available
- Argus or screenshot/vision tooling only when structured browser state is insufficient

No engine is canonical yet. The first benchmark exists specifically to decide which engines earn which routes.

## Core contracts

WEIR defines stable objects independent of engine syntax:

- `WebRequest`
- `WebCapture`
- `BrowserSession`
- `ControllerLease`
- `Observation`
- `SemanticLocator`
- `ActionProposal`
- `ExecutionReceipt`
- `ExecutionPermit`
- `EvidenceReference`
- `AcquisitionEnvelope`
- `SiteProfile`
- `WorkContext`
- `MarketplaceListing`
- `MarketplaceSearchResult`

Engine-local references such as `oc`'s `[17]` or browser snapshot `@e4` are ephemeral. Durable recipes and evidence must use semantic locators, capture hashes, preconditions, postconditions, and verifier rules.
Element postconditions carry their locator and re-resolve it on the newer observation;
generic click and input/change primitives remain `risk=unknown` until their effects are
attested by a narrower action contract.

## Repository map

```text
contracts/              JSON Schemas for the public WEIR data model
docs/                   architecture, authority, evaluation, security, and slice notes
profiles/               example site-profile definitions
src/weir/                acquisition broker, policies, persistence, telemetry, and adapters
tests/                   contract and adapter tests
HARNESS_CONTRACT.md      boundary with the rest of Lugos
```

`docs/marketplace-slice.md` defines the first consumer-driven vertical slice
(marketplace acquisition for the Lode deal evaluator); `concept.md` carries the
broader three-tier framing behind it.

## Current state

**P1 public acquisition is operational; P2 authenticated observation now has a
durable session kernel.**

The reusable `AcquisitionBroker` now owns route selection, site-profile policy,
domain checks, bounded fallback, capture creation, immutable evidence persistence,
public-cache eligibility, and metadata-only trace spans. Its public `read`, `search`,
and `enrich` methods require an `AcquisitionEnvelope` and return a newly persisted
context-bound `EvidenceReference` with the reusable capture. The standalone CLI keeps
a private legacy seam until the authenticated WEIR service replaces in-process sibling
calls. The eBay marketplace slice is a live consumer through Lode, including structured
search, pagination, listing hashes, and page enrichment.

WEIR still does not declare one reader the universal winner. Existing benchmark
evidence promotes direct HTTP for API-shaped resources and keeps `oc` then
`agent-browser read` as the general compact-reader chain. More repeated fidelity
evidence remains useful, but it no longer blocks callers from using the broker.

The browser kernel adds explicit work-context identity, a host-global reservation for
each trusted credential binding (plus the worker-local profile constraint),
SQLite-backed session revisions, durable command reservation,
expiring fenced controller leases, same-owner recovery, fenced manual takeover/return,
semantic observations, immutable evidence, and an append-only metadata event journal.
Unacknowledged OPEN dispatches and unconfirmed worker cleanup quarantine the profile
instead of freeing it for reuse. Structured observations and requested screenshots are
captured as one document-generation-checked worker result, not as two independently
timed reads. A direct Playwright worker passed an authenticated local smoke test in a fresh,
nonpersistent, sandboxed, direct-network, DNS-pinned browser process with bounded and
redacted resource telemetry. The contained `agent-browser` worker is an
ephemeral protocol comparison only: its allowlist conflicts with profile/state restore,
so the authenticated broker does not admit it.

The broker can now host either adapter behind `ProcessBrowserWorker`, which establishes
an OS process tree before constructing the worker, kills that tree when a command
deadline expires, its parent disappears, or its wrapper is abandoned, exchanges only a
strict size-bounded JSON operation/result union, and emits hash-bound death evidence.
Production source admission now requires this exact transport plus current memory,
process-count, restricted-identity, per-caller credential-protection, lifecycle, and
OS egress evidence. Windows applies memory and process limits in the Job Object before
worker construction; Linux requires an injected verifier for prepared cgroup v2 and
network-namespace controls and fails closed without it. Host accounts, ACLs, firewall
rules, and supervisors are not provisioned by the library. Death evidence never grants
reuse: only cleanup from the
exact live reservation holder or an authenticated, exact operator retirement can
release a quarantined credential. Existing schema-v1 stores require the separately
approved offline procedure in `docs/browser-store-v2.md`; no migration runs at startup.

WEIR now has a disabled-by-default Batch 7 action boundary for Fade-issued permits.
The source implementation verifies the immutable proposal and exact request digest,
atomically pauses the session under a rotated controller fence, reacquires durable
pre-state, re-resolves the semantic target, and rechecks proposal/permit expiry plus the
exact credential-holding worker instance at the durable dispatch marker. It then sends
one bounded private effect command and verifies durable post-state before publishing a
receipt. A dispatch with no terminal receipt becomes
`outcome_unknown` and quarantines the session; it is never replayed automatically.
Only an explicitly injected synthetic-fixture worker can use this path, and its policy
allows public `fill`, `select`, `check`, and `uncheck` effects on one HTTP loopback IP
origin. The first approved local canary now passes through real Playwright plus the
Fade and WEIR HTTP boundaries, including response-loss reconciliation, conflicting
replay rejection, and restart replay with exactly one DOM effect. Its runner and
redacted evidence are in `scripts/run_fade_weir_action_canary.py` and
`docs/acceptance/batch9-local-acceptance-20260828.md`. This does not add a production
effect adapter, service deployment, or production credential. See
`docs/focus-and-interaction.md` for the cross-system identity and controller model.
The implementation-ready cross-repository sequence and Fable review decisions are in
`docs/sibling-integration-plan.md`; the focused post-freeze delivery plan for the
remaining sibling work is in `docs/remaining-integration-plan.md`. The accepted Batch
0 schemas, retention rules, negative cases, and Python/TypeScript parity process are in
`docs/contract-freeze.md` and `contracts/fixtures/batch-0-v1.json`.
The implemented Batch 1A caller, cache, persistence, and telemetry invariants are in
`docs/context-bound-acquisition.md`.
The 7P evidence contract, fail-closed gates, and host rollout boundary are in
`docs/production-admission.md`.
The frozen Batch 8 signed-capsule, queue, acknowledgement, revocation, and redacted
audit contracts are in `docs/remote-decision-contract.md` and
`contracts/fixtures/remote-relay-v1.json`. They add no remote listener and every relay
feature remains disabled by default.
RF7 selects Autowork's post-assignment, pre-provider evidence-acquisition phase as the
first trusted `DispatchContext` provider; its authoritative fields, rejected
alternatives, and activation tests are in `docs/dispatch-context-provider.md`.
The disabled-by-default Batch 2 authenticated acquisition/proposal/retirement service
slices and their remaining Batch 2 work are described in `docs/service-boundary.md`.
The schema-v2 trust model and offline backup/migration/readback procedure are in
`docs/browser-store-v2.md`.

## Development

Requires Python 3.11+.

```bash
python -m pip install -e ".[test]"
weir engines
weir browser-engines
weir read https://example.com --engine auto
weir search "Keychron C2 Pro" --source ebay --pages 2
weir search "Keychron C2 Pro" --constraints '{"switch":"red","max_total_cost":40}'
```

For the optional direct browser worker:

```bash
python -m pip install -e ".[test,browser]"
python -m playwright install chromium
WEIR_PLAYWRIGHT_SMOKE=1 python -m pytest -q tests/test_playwright_observer.py
```

Built wheels include the versioned JSON contracts and default YAML site profiles under
`weir/data`. The CLI loads those packaged profiles by default; `WEIR_PROFILE_DIR`
explicitly replaces them for a deployment, and a missing configured directory fails
closed rather than silently falling back.

The reader commands expect the selected external engine to already be installed. They return a WEIR-normalized JSON envelope rather than exposing the rest of Lugos to engine-specific output.

Search constraints are preserved in the evidence bundle for the domain consumer. The
eBay adapter does not silently reinterpret `max_total_cost` as item price, because Lode
owns shipping-inclusive cost, unknown-value handling, and scoring.

### Optional state and traces

The default CLI remains stateless. Set these paths to enable the corresponding local
boundaries:

```bash
export WEIR_STATE_DIR=.weir
export WEIR_PROFILE_DIR=profiles
export WEIR_TRACE_FILE=.weir/aitu-spans.jsonl
```

`WEIR_STATE_DIR` stores immutable capture manifests, context-bound evidence references,
content-addressed JSON and binary evidence, and a short-lived file cache. Only
unauthenticated `public` read/search requests qualify for that shared cache;
authenticated, personal, internal, and restricted evidence bypasses it. In the
context-bound broker, a cache hit reuses the original immutable capture but persists a
new evidence reference for the requesting work context. The CLI remains on the
temporary unbound path and should not be used as a sibling integration boundary.

`WEIR_TRACE_FILE` receives metadata-only `web.*` JSONL spans. The sink rejects unknown
attribute names and unbounded values; queries, URLs, page bodies, errors, credentials,
and raw artifacts are not trace attributes. Normalized reader content is
limited to 5 MiB; oversized prose captures carry an explicit bounded preview, while an
oversized structured-search set fails instead of violating its result-set contract.

## Name

**WEIR** = **Web Evidence, Interaction & Retrieval**.

A weir controls and directs flow without pretending to be the water itself. That is the intended architectural role here: external web state flows through a governed, observable boundary before it becomes agent context or action authority.
