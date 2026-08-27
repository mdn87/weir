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
- `Observation`
- `ActionProposal`
- `ExecutionReceipt`
- `SiteProfile`
- `MarketplaceListing`
- `MarketplaceSearchResult`

Engine-local references such as `oc`'s `[17]` or browser snapshot `@e4` are ephemeral. Durable recipes and evidence must use semantic locators, capture hashes, preconditions, postconditions, and verifier rules.

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

**P1 public acquisition broker, read-only.**

The reusable `AcquisitionBroker` now owns route selection, site-profile policy,
domain checks, bounded fallback, capture creation, optional immutable persistence,
public-cache eligibility, and metadata-only trace spans. The CLI is a thin caller of
that same path. The eBay marketplace slice is a live consumer through Lode, including
structured search, pagination, listing hashes, and page enrichment.

WEIR still does not declare one reader the universal winner. Existing benchmark
evidence promotes direct HTTP for API-shaped resources and keeps `oc` then
`agent-browser read` as the general compact-reader chain. More repeated fidelity
evidence remains useful, but it no longer blocks callers from using the broker.

The executable surface remains intentionally read-only. P2 browser sessions and P3
action execution stay separate until profile isolation, controller leases, and the
Fade/approval ownership boundary are implemented.

## Development

Requires Python 3.11+.

```bash
python -m pip install -e ".[test]"
weir engines
weir read https://example.com --engine auto
weir search "Keychron C2 Pro" --source ebay --pages 2
weir search "Keychron C2 Pro" --constraints '{"switch":"red","max_total_cost":40}'
```

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

`WEIR_STATE_DIR` stores immutable capture manifests, content-addressed public artifacts,
and a short-lived file cache. Only unauthenticated `public` read/search requests qualify
for that shared cache; authenticated, personal, internal, and restricted evidence bypasses it. A cache
hit returns the original immutable capture and names its capture ID in the envelope.

`WEIR_TRACE_FILE` receives metadata-only `web.*` JSONL spans. Queries, page bodies,
credentials, and raw artifacts are not trace attributes. Normalized reader content is
limited to 5 MiB; oversized prose captures carry an explicit bounded preview, while an
oversized structured-search set fails instead of violating its result-set contract.

## Name

**WEIR** = **Web Evidence, Interaction & Retrieval**.

A weir controls and directs flow without pretending to be the water itself. That is the intended architectural role here: external web state flows through a governed, observable boundary before it becomes agent context or action authority.
