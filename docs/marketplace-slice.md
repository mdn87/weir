# Vertical slice: marketplace acquisition (eBay → Lode)

This document turns the "deal finding as WEIR's first vertical slice" concept (see
`../concept.md`, section *Deal finding as WEIR's first vertical slice*) into concrete
definitional pressure on the WEIR project: what it adds to the contracts, which engine
it introduces, how it exercises the capability ladder, and what it proves.

The point of choosing this slice is not that eBay is important. It is that a real,
already-built consumer (Lode) forces WEIR to implement the parts of its own abstraction
that are otherwise easy to hand-wave: connector-first acquisition, structured multi-item
search results, provenance, enrichment fallback, and normalized captures.

## Consumer boundary: what Lode is, and is not, asking for

Lode ("Leverage Optimized Deal Extraction") is a deterministic deal evaluator. It owns
the domain intelligence — *veins* (saved searches/watches), *claims* (tracked listings),
*candidates*, *strikes*, *yield*, *grade*, comps, history, dedup, scoring, and alerting —
and it deliberately keeps an LLM out of the collection path:

> "Do not make an LLM the primary collector, database, scheduler, or calculator."

Lode already collects through the eBay Browse API with pagination, per-run
deduplication, listing-state change detection, and shipping-inclusive cost that refuses
to guess unknown shipping or tax. **WEIR does not replace any of that domain logic.**
Lode asks WEIR only to *acquire and preserve evidence*, by intent rather than by engine:

```text
intent: marketplace_search
source: ebay
query: Keychron C2 Pro
constraints:
  switch: red
  max_total_cost: 40
evidence_required: true
```

WEIR returns normalized listing captures. Lode decides what they are worth.

## New capability: structured marketplace search

WEIR's current `WebRequest` modes are `discover | read | observe | interact | commit`,
and `WebCapture` models a *single* page/document. Marketplace search does not fit either
cleanly: it is a connector call that returns *many* normalized items, each of which may
later be individually enriched.

Two design options:

1. **New mode `search`** on `WebRequest`, returning a result set of lightweight listing
   captures. Cleanest semantically; requires a result-set capture shape.
2. **Reuse `discover`** (which today means "locate candidate sources") and let a
   connector engine return typed listing candidates instead of URLs.

Recommendation: option 1. `discover` is about *finding sources*; marketplace search is
about *retrieving normalized records from one known source*. Overloading `discover`
would blur the capability ladder. A `search` mode keeps "give me a source list" and
"give me records from this source" distinct, which matters once Chron fans out across
eBay, Newegg, Slickdeals, Reddit, and arbitrary URLs.

Either way this exposes a gap: **WEIR currently has no contract for a result set of
captures**, only for one capture. That is the first real contract addition the slice
demands.

## New engine: `ebay` connector (rung 1 of the capability ladder)

The capability ladder's top rung — *connected service / direct API* — has no adapter
today; only `oc` and `agent-browser read` exist, both of which sit on lower rungs. The
eBay Browse API is the first concrete reason to build a connector engine.

Proposed engine capabilities (names are illustrative, not final contract terms):

```text
ebay.api.search     Browse API item_summary search -> normalized listing set
ebay.api.item       Browse API single-item detail -> normalized listing capture
ebay.page.read      item page acquisition (oc / agent-browser read) for enrichment
ebay.browser.observe rendered listing observation (photos, JS-only detail)
```

The connector engine must:

- authenticate with public application credentials via a **profile id**, never raw
  credentials in the `WebRequest` (per `authority-boundaries.md`);
- handle Browse API pagination and bounded rate-limit/retry behavior at the WEIR layer,
  so consumers do not each reimplement it;
- emit a normalized listing capture with content hash + provenance so listing-state
  change detection and multi-provider parity both work off the same evidence;
- mark unknown fields (e.g. shipping/tax) as explicitly unknown rather than guessing,
  matching Lode's existing discipline.

Note the division of labor: **WEIR** owns pagination and rate-limit mechanics as
acquisition concerns; **Lode** owns per-run dedup, history, and cost/scoring as domain
concerns. Where Lode already implements pagination internally, the slice is an
opportunity to move the acquisition mechanics down into WEIR and leave Lode consuming a
normalized set — but that migration is a Lode decision, not a WEIR precondition.

## Normalized listing capture shape

A marketplace listing is a specialization of `WebCapture`, not a new top-level object.
The engine-neutral fields it needs (candidate list, to be schema-ized):

```text
listing:
  source: ebay
  source_item_id: ...
  canonical_url: ...
  title: ...
  price:        {amount, currency}
  shipping:     {amount, currency} | unknown
  total_cost:   derived | unknown        # WEIR may leave derivation to Lode
  condition:    raw + structured | unknown
  observed_at:  ...
  content_hash: sha256:...               # for listing-state change detection
  raw_artifact_ref: ...                  # immutable Browse API payload
  enrichment:   none | page | rendered   # which ladder rung produced detail
```

This rides on the existing `WebCapture` guarantees (immutable, hashed, provenance-
bearing). Engine-local handles (`oc` `[17]`, browser `@e4`) must not leak into it.

## Enrichment: the capability ladder made concrete

The slice is the first place WEIR's engine-fallback claim runs against real work:

```text
ebay.api.search        -> normalized listing set              (rung 1)
  |
  | Lode flags a listing as a candidate but the API detail is thin
  v
ebay.page.read         -> description + structured condition  (rung 2, oc / read)
  |
  | still insufficient (photos, JS-only spec table)
  v
ebay.browser.observe   -> rendered observation                (rung 3)
```

A failed or thin API read is a **routing event**, not permission for a provider to
improvise browsing. WEIR performs the escalation and records which rung produced the
evidence (`enrichment` field above).

## Provider-parity payoff (why this reinforces WEIR's core thesis)

Lode's Phase 1 forbids providers from browsing because
*"Providers cannot silently collect different evidence in Phase 1."* WEIR's immutable
`WebCapture` is precisely the object that lets that rule be *relaxed* rather than kept as
a blanket ban: WEIR produces one evidence bundle, and Claude and Codex both evaluate the
same hashed captures. This is the strongest argument that WEIR's "observation vs
authority" separation is load-bearing and not decorative — it directly enables
comparable multi-provider evaluation downstream.

## What the slice proves for WEIR

- rung 1 (connector/API) is real and has an adapter, not just a diagram box;
- `WebRequest`/`WebCapture` can express *structured search + per-item enrichment*, or
  they need the additions identified above (a result-set contract, a `search` mode, a
  listing capture profile);
- engine fallback and provenance work end-to-end against a live workload;
- a real consumer (Lode) validates the abstraction instead of a synthetic benchmark.

## Open definitional questions

1. `search` mode vs. overloading `discover` — decide before the connector lands.
2. Result-set capture: a new `WebCaptureSet` contract, or a `WebCapture` whose `content`
   is a typed listing array? (Leaning toward the latter to avoid a second top-level
   object.)
3. Does WEIR own Browse API pagination/rate-limit, or expose raw pages and let Lode
   keep owning it during the slice? (Recommend WEIR owns it, so Newegg/Slickdeals reuse
   it — but stage the migration so Lode is never blocked.)
4. Which rung-2 reader wins enrichment for eBay item pages — `oc` vs `agent-browser
   read` — is a benchmark question, not an architecture question.
5. Credential/profile handling for the eBay application keys through the profile
   boundary, never the request object.

## Relationship to the roadmap

This slice is the concrete driver for the P1 "connector/API adapter interface",
"capture hashing and artifact persistence", and "deterministic reader fallback reasons"
items, and it front-loads a real consumer earlier than the abstract benchmark corpus in
P0. See `../ROADMAP.md`.
