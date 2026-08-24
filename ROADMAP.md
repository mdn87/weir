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

- [ ] Decide `search` mode vs. overloaded `discover` for structured search.
- [ ] Define the result-set / normalized-listing capture shape.
- [ ] Implement the `ebay` connector engine (`ebay.api.search`, `ebay.api.item`).
- [ ] Implement enrichment fallback (`ebay.page.read`, then `ebay.browser.observe`).
- [ ] Return immutable, hashed, provenance-bearing listing captures.
- [ ] Prove Lode can consume WEIR captures in place of its own eBay collector.

Gate: Lode obtains normalized eBay listings (with enrichment fallback) through WEIR by
intent, and the same evidence bundle is comparable across providers.

## P1 - Public acquisition broker

- [ ] Add route classifier.
- [ ] Add connector/API adapter interface (generalized from the eBay slice).
- [ ] Add capture hashing and artifact persistence boundary.
- [ ] Add deterministic reader fallback reasons.
- [ ] Add domain policy.
- [ ] Add cache policy by data class.
- [ ] Add site profiles only where benchmark evidence supports them.
- [ ] Add AITU spans.

Gate: public research campaigns can acquire sources through WEIR with provenance, bounded output, deterministic fallback, and no authenticated browser dependency.

## P2 - Browser session broker

- [ ] Define browser worker protocol.
- [ ] Add `agent-browser` interactive adapter.
- [ ] Add direct Playwright/CDP comparison adapter.
- [ ] Add profile isolation.
- [ ] Add controller leases.
- [ ] Add session attach/takeover semantics.
- [ ] Add structured observations and semantic locators.
- [ ] Add browser-session evidence capture.

Gate: WEIR can observe and perform reversible interactions in an authenticated test application while preserving session isolation and durable evidence.

## P3 - Action authority integration

- [ ] Resolve Fade/Operator execution ownership.
- [ ] Compile observations into `ActionProposal` objects.
- [ ] Add risk taxonomy.
- [ ] Add approval handoff.
- [ ] Reacquire state immediately before execution.
- [ ] Add post-action verification and `ExecutionReceipt`.
- [ ] Add bounded recovery patterns.

Gate: a staged external action cannot execute without policy evaluation and, when required, explicit approval; success is proven by post-state evidence.

## P4 - Lugos integration

- [ ] `lugos-mcp` surface.
- [ ] task-router integration.
- [ ] run-profile policy.
- [ ] Autowork campaign integration.
- [ ] Sulis provenance/summary records.
- [ ] AETA source-capture handoff.
- [ ] AITU traces and metrics.
- [ ] HUD session/evidence/approval views.
- [ ] COGIN/APU behavior-registry feedback.

Gate: multiple Lugos seats can request web capabilities without direct engine knowledge, and route decisions are observable.

## P5 - Visual fallback

- [ ] Screenshot/crop evidence adapter.
- [ ] Argus interpretation contract.
- [ ] Visual verifier.
- [ ] Ambiguity classification.
- [ ] Manual takeover path.

Gate: structured-browser failures can escalate to visual interpretation without bypassing action policy.

## Deferred

- automatic site-profile generation
- large-scale web crawling
- generalized credential brokerage
- arbitrary autonomous purchasing
- online self-training from browser activity
- WEIR-owned model routing
