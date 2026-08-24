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

Engine-local references such as `oc`'s `[17]` or browser snapshot `@e4` are ephemeral. Durable recipes and evidence must use semantic locators, capture hashes, preconditions, postconditions, and verifier rules.

## Repository map

```text
contracts/              JSON Schemas for the public WEIR data model
docs/                   architecture, authority, evaluation, and security notes
profiles/               example site-profile definitions
src/weir/                engine-neutral Python skeleton and read-only adapters
tests/                   contract and adapter tests
HARNESS_CONTRACT.md      boundary with the rest of Lugos
```

## Current state

**Seed / architecture experiment.**

This repository deliberately does not declare `oc`, `agent-browser`, or Playwright the winner. The next meaningful milestone is an evidence-producing benchmark across real Lugos web tasks, followed by a routing decision.

The initial executable surface is intentionally read-only. Side-effectful browser execution must not be smuggled into the seed before the Fade/approval ownership boundary is resolved.

## Development

Requires Python 3.11+.

```bash
python -m pip install -e .
weir engines
weir read https://example.com --engine oc
```

The reader commands expect the selected external engine to already be installed. They return a WEIR-normalized JSON envelope rather than exposing the rest of Lugos to engine-specific output.

## Name

**WEIR** = **Web Evidence, Interaction & Retrieval**.

A weir controls and directs flow without pretending to be the water itself. That is the intended architectural role here: external web state flows through a governed, observable boundary before it becomes agent context or action authority.
