Right. My previous framing optimized too early around “install oc, add a fallback, and move on.” That would give Lugos another useful command, but it would miss the larger opportunity.

The better question is:

What should web access look like as a first-class Lugos capability, and which engines deserve to operate underneath it?

Best long-term shape: a Lugos Web Plane

The strongest implementation is a dedicated web acquisition and browser-session subsystem with a stable Lugos contract. oc would be one engine inside it, not the architecture itself.

User / CLI / HUD / ORCA seat
|
v
task-router + run profile
|
v
Autowork
campaign and delegation
|
v
lugos.web API
exposed by lugos-mcp
|
v
+----------------------------------+
| Lugos Web Plane |
| |
| request classifier |
| engine router |
| browser session broker |
| site/profile registry |
| policy labels |
| capture and evidence manager |
| verifier |
+----------------------------------+
| | |
v v v
public read live browser visual fallback
APIs/oc/ Chrome/CDP/ Argus/screenshots
markdown Playwright
| |
+-----+-----+
|
v
proposed action
|
v
Fade / execution authority
approvals and side effects
|
v
Validation -> Sulis -> AITU -> HUD

This follows the existing Lugos design principle that structured interfaces should take priority over browser automation, browser automation over pixels, and pixels over raw HID control. The Operator concept already describes that adapter hierarchy and calls for typed observations, typed actions, verification, approvals, replay, and reusable recipes.

Split web work into two trust planes

“Browsing” currently collapses two fundamentally different activities:

Public acquisition plane

This handles:

Search and discovery
Public documentation
Articles, forums, release notes, repositories
Public APIs and feeds
Static or server-rendered pages
Research source capture
Citation and provenance generation

It should usually be stateless, credential-free, aggressively cacheable, and safe to distribute across workers.

Authenticated operations plane

This handles:

Logged-in applications
Client portals
Account dashboards
Downloads tied to a session
Filling forms
Uploading files
Submitting records
Sending messages
Changing settings
Purchases or other consequential actions

This requires isolated browser profiles, exclusive session ownership, credential boundaries, action classification, approval gates, and post-action verification.

These planes can share capture, evidence, session, and action schemas. They should not share authority. A public research tool should never inherit permission to submit an authenticated form merely because both activities happen in a browser.

Where oc actually belongs

oc is a strong candidate for a compact_http or public_reader engine.

Its useful properties are:

Compact numbered output
Machine-readable JSON
Deterministic continuation commands
Saved page blocks, so read, find, and next do not refetch
A distinct no-readable-content result, including exit code 2 and an empty field
Browser-like HTTP fingerprints
Explicit blocking of private and internal targets
A small implementation surface

Those properties make it suitable for inexpensive public-page acquisition and for deterministic escalation when it cannot read a page.

But several parts of oc should not become Lugos contracts:

Its sessions are plain local JSON files.
There are no cookies.
The default session is globally named default.
Numeric page handles only have meaning against the latest saved render.
Session persistence is local to OC_HOME.
The saved state is operational cache, not an immutable research record.
It deliberately refuses private network addresses.
Forms, submission, authentication, and JavaScript rendering are not implemented.

The session code explicitly describes a local file containing the current URL, distilled blocks, cursor, and short history, with no cookies.

Therefore the Lugos adapter should:

Invoke oc --json rather than parsing its human display.
Give every run its own OC_HOME.
Generate a unique session name from the Lugos run and step IDs.
Translate oc handles into capture-relative Lugos references.
Store the resulting capture separately from the oc session.
Treat exit code 2 as an engine-routing signal.
Never weaken its private-address protection to make it read internal services.
Pin the package version rather than using an unbounded npx --yes invocation.

For internal sites, Lugos should use a separate explicitly allowlisted internal HTTP or browser adapter. Disabling oc’s SSRF protections globally would erase a useful security boundary. Its fetch layer validates resolved addresses and redirect destinations specifically to prevent internal-address access.

oc should compete for the reader slot

We should not assume oc automatically wins the public read lane.

Current agent-browser now has a substantial read command:

Reading an explicit URL does not launch Chrome.
It requests Markdown where available.
It can locate llms.txt and llms-full.txt.
It falls back to HTML text extraction.
Reading without a URL extracts the rendered DOM from the active authenticated browser.
The same tool also exposes Chrome sessions, accessibility snapshots, screenshots, cookies, storage, HAR capture, CDP connections, streaming, tabs, and interactions.

That overlap changes the evaluation. The real candidates for the reader lane are:

Candidate Strength Weakness
oc Very compact, numbered navigation, simple, deterministic failure signal No rendered DOM, cookies, authentication, or forms
agent-browser read Shares infrastructure with the interactive browser and can read authenticated rendered state Larger dependency and operating surface
In-process extraction stack Complete Lugos control and no CLI translation layer Lugos owns extraction quality and maintenance
Direct API or connector Highest fidelity and least brittle Only available for supported services
Rendered Chrome extraction Works on JavaScript-heavy sites Highest resource and latency cost

The right answer may be:

connector/API
-> agent-browser read or direct Markdown
-> oc compact extraction
-> rendered browser DOM

Or oc may outperform agent-browser read enough that the order reverses. We need Lugos-specific measurements, not vendor benchmarks.

The Web Plane should route by task semantics

It should not merely try the cheapest engine until one returns text. The request should declare what is actually required.

A useful routing order is:

1. Connected service or direct API
2. Public Markdown, feed, JSON, or static-page extraction
3. JavaScript-rendered DOM observation
4. Reversible browser interaction
5. Consequential browser action
6. Visual interpretation
7. Human takeover

Examples:

Read an API reference
-> public reader

Compare five product pages
-> public reader with capture and citation requirements

Inspect a logged-in billing page
-> authenticated browser observation

Fill a draft form but do not submit
-> authenticated browser interaction

Submit the form
-> action proposal -> approval -> execution -> verification

Operate a canvas application with no usable accessibility tree
-> browser screenshot -> Argus interpretation -> bounded action

That is consistent with the existing Operator model, which says actions must be typed, risk-labelled, inspectable, and followed by explicit verification rather than assumed successful.

Stable Lugos contracts

The main architectural investment should be the contracts, not the first engine adapters.

WebRequest
request_id: webreq_...
run_id: run_...
intent: compare current documentation for three libraries
mode: discover | read | observe | interact | commit
urls: []
query: optional
auth_context: none | profile_id
data_class: public | personal | bwa_internal | restricted
allowed_domains: []
maximum_depth: 4
capture_policy: metadata | content | full_evidence
evidence_required: true
side_effects_allowed: false
WebCapture
capture_id: cap_...
requested_url: ...
canonical_url: ...
captured_at: ...
engine: oc
engine_version: 0.4.0
http_status: 200
auth_scope: none
content_hash: sha256:...
trust: untrusted_external_content
title: ...
structured_blocks: []
outbound_links: []
raw_artifact_ref: ...
screenshot_artifact_ref: null
BrowserSession
session_id: browser_...
owner_run_id: run_...
controller_lease: seat_...
worker_id: windows-browser-worker
profile_id: ebay-personal
auth_scope: personal
allowed_domains:

- ebay.com
  state: active
  current_url: ...
  expires_at: ...
  Observation
  observation_id: obs_...
  session_id: browser_...
  capture_id: cap_...
  url: ...
  title: ...
  elements:
- ref: element_...
  role: button
  label: Submit order
  state: enabled
  ActionProposal
  action_id: act_...
  type: browser.click
  target:
  semantic_locator:
  role: button
  name: Submit order
  risk: purchase
  side_effect: external_commit
  preconditions: []
  expected_postconditions: []
  approval: required
  ExecutionReceipt
  action_id: act_...
  before_capture_id: cap_before
  executed_by: fade
  result: completed
  after_capture_id: cap_after
  verification:
  method: confirmation_id_present
  confidence: verified

The important point is that recipes must not persist @e4 or [17] as durable selectors. Those values belong to one snapshot. Recipes should retain semantic locators, relevant capture hashes, preconditions, verifier rules, and fallback logic.

Ownership across Lugos

There is a genuine architecture conflict in the current documents.

The older Operator concept assigns adapter routing, policy, execution, approvals, verification, recording, and events to Operator.

The newer Argus boundary says:

Argus owns continuous external visual observation and state inference.
Fade owns deterministic execution and approvals.
Remotedesk owns cooperative target-side capture.

That conflict should be resolved before browser action ownership hardens. My recommended division is:

Component Recommended responsibility
task-router Classify intent and select the web capability family
run profile Set exploration depth, autonomy, evidence, and approval requirements
Autowork Own the campaign, agent assignments, delegation, and outcome gates
Lugos Web Plane Own browser transport, sessions, captures, engine routing, and site profiles
Fade Own authority to execute side-effectful actions and issue receipts
Operator Compose target-machine workflows and present live run state, if retained as a distinct product layer
Argus Interpret pixels when structured browser state is insufficient
Remotedesk Provide cooperative target-side capture and remote session access
validation Judge whether the requested result was demonstrated
Sulis Store typed run state, provenance, summaries, hashes, and durable references
AETA Consume and organize source captures where source-handling workflows need them
AITU Record telemetry, costs, latency, route choices, failures, and waterfalls
lugos-mcp Expose the protocol surface without becoming the runtime or database

Autowork is already the natural owner for policy-bound campaigns and should not be displaced by a browser package that includes its own autonomous agent loop. The accepted-write concept makes the same point about avoiding a second permanent orchestrator.

Public MCP and CLI surface

The external interface should express user intent, not engine commands.

lugos.web.search
lugos.web.read
lugos.web.capture.get

lugos.web.sessions.open
lugos.web.sessions.list
lugos.web.sessions.get
lugos.web.sessions.close
lugos.web.sessions.attach

lugos.web.observe
lugos.web.actions.propose
lugos.web.actions.execute
lugos.web.actions.verify

lugos.web.profiles.list
lugos.web.profiles.get
lugos.web.profiles.test

lugos.web.evidence.get
lugos.web.takeover

The direct actions.execute route should only be callable through the proper policy authority. Ordinary ORCA seats could propose actions but not bypass Fade by issuing arbitrary clicks.

The terminal interface could expose the same objects:

lugos web read https://example.com
lugos web search "browser automation CLI"
lugos web session open --profile ebay-personal
lugos web session observe browser_123
lugos web session attach browser_123
lugos web action propose browser_123 \
--click-role button \
--name "Submit"

attach could open either:

A terminal inspector showing URL, accessibility tree, tabs, actions, history, and evidence
A streamed browser view for human takeover
A HUD view using the same session

This would provide reasonable terminal usability without forcing the human or agent to operate directly through oc’s primitive session model.

Site profiles should become richer than oc shortcuts

oc currently defines site shortcuts as small JSON URL templates. They are useful but do not describe behavior, policy, authentication, or verification. Its changelog confirms that shortcuts resolve to URLs and then use the normal open path.

Lugos site profiles should add:

id: github-public
domains:

- github.com
- api.github.com
  preferred_engines:
- github_connector
- oc
- agent_browser_read
  auth_mode: optional
  allowed_actions:
- read
- navigate
  rate_policy: conservative
  content_boundaries: external_untrusted
  known_failures:
- challenge_page
  fallbacks:
  challenge_page: authenticated_browser
  verification:
  issue_lookup: title_and_number_match

For a portal:

id: client-portal
domains:

- portal.example.com
  preferred_engines:
- agent_browser
  auth_mode: dedicated_profile
  allowed_actions:
- observe
- download
- stage_upload
  approval_actions:
- submit
- overwrite
- delete
  retention:
  screenshots: restricted
  har: metadata_only

Profiles should be added in response to measured recurring behavior. Lugos should not immediately create hundreds of brittle site adapters.

COGIN, APU, and model-specific behavior

This subsystem would provide a clean source of evidence for the provider/model behavior registry you were describing.

The relevant performance key becomes:

model
thinking level
task class
site profile
engine
auth mode
observation format

Examples of learnable behavior:

A model performs well with 500-token compact captures but deteriorates on full accessibility trees.
Another model needs screenshots whenever labels are sparse.
A model repeatedly explores irrelevant links unless given a hard navigation budget.
A model uses stale element references after DOM mutations.
A model needs forced post-action resnapshotting.
A model is strong at research synthesis but unreliable at form interaction.
A lower thinking level is sufficient for extraction, while a higher level materially improves cross-source comparison.

COGIN or APU can then recommend a browsing strategy for a seat. Hard security constraints must remain outside those model-specific profiles. No model profile should be able to increase its own allowed domains, approval authority, credential scope, or action budget.

AITU instrumentation

Every meaningful operation should produce spans such as:

web.route
web.connector.call
web.http.fetch
web.oc.distill
web.browser.launch
web.browser.navigate
web.browser.snapshot
web.browser.action.propose
web.browser.action.execute
web.browser.verify
web.engine.fallback
web.operator.takeover

Useful dimensions:

Engine and version
Model and thinking level
Site profile
Authentication mode
Input and output size
Tokens returned to the model
Fetch and render latency
Fallback reason
Browser startup cost
Action count
Resnapshot count
Verification confidence
Operator interventions
Prompt-injection detection
Session recovery success

AITU already calls for tool and retrieval spans, asynchronous export, and metadata-only capture by default. It should observe the Web Plane without storing raw page contents as analytic fields.

Raw HTML, screenshots, HAR files, and downloaded artifacts belong in an artifact store with retention rules. Sulis should retain hashes, provenance, typed summaries, verification outcomes, and references.

Implementation possibilities worth evaluating
Architecture Benefit Structural problem Verdict
Install oc as a skill on every seat Immediate access and little engineering Scattered state, inconsistent versions, no shared evidence, weak policy enforcement Useful experiment only
Wrap oc and agent-browser directly in lugos-mcp One tool surface and quick testing MCP gradually becomes a stateful browser runtime Reasonable prototype boundary
Put browser adapters only inside Fade or Operator Strong action policy integration Public research becomes coupled to target-machine execution Good action lane, incomplete overall
Dedicated Lugos Web Plane Shared research, browser sessions, evidence, policy, model tuning, and replaceable engines Largest deliberate architecture investment Best long-term design
Fork oc into Lugos Complete control over distillation, sessions, security, and schema Permanent maintenance burden for a very young project Conditional after benchmarks
Adopt a full external browser-agent framework Large feature set and quick demonstrations Introduces another planner, model router, memory layer, and orchestration loop Benchmark candidate, poor canonical owner
Build directly on Playwright/CDP Maximum deterministic control and tight contracts More browser lifecycle and compatibility engineering Strong long-term engine option
Use agent-browser as the managed browser substrate Rich current CLI, session, snapshot, network, and streaming capabilities CLI/daemon dependency and external release coupling Strong near-term substrate
Evaluation before choosing the engine stack

The benchmark should use actual Lugos work rather than six generic pages.

Task corpus
Static documentation
Large technical article
Search results and link following
GitHub repository and issues
Reddit discussion
JavaScript-only application
Consent wall
Bot challenge
Authenticated dashboard
Form draft
File download
Staged upload
Approved submission
Internal allowlisted service
Deliberate prompt-injection page
Concurrent browser sessions
Session crash and recovery
Compare
direct connector/API
oc
agent-browser read
custom in-process extractor
agent-browser rendered DOM
direct Playwright snapshot
visual screenshot interpretation
Measure
End-to-end task success
Extraction fidelity
Citation fidelity
Token cost
Latency
Memory and process cost
Authentication persistence
Fallback frequency
Concurrent-session isolation
Reproducibility
Evidence completeness
Recovery success
Prompt-injection resistance
Number of operator interventions
Maintenance complexity

Run that matrix across the providers, models, and thinking levels intended for ORCA seats. The result becomes the first real web-capability inventory for the model-behavior registry.

Recommended target repository
lugos-web/
README.md
HARNESS_CONTRACT.md
contracts/
request.schema.json
capture.schema.json
session.schema.json
observation.schema.json
action.schema.json
receipt.schema.json
site-profile.schema.json
core/
broker.py
router.py
policy.py
sessions.py
captures.py
evidence.py
verifier.py
events.py
engines/
connector.py
oc_reader.py
agent_browser_reader.py
agent_browser.py
playwright.py
argus.py
profiles/
github.yaml
reddit.yaml
microsoft_learn.yaml
workers/
public_reader.py
browser_worker.py
cli/
main.py
service/
api.py
benchmarks/
corpus/
runners/
reports/
tests/

Deployment should be hybrid:

Stateless public-reader workers can run on general Lugos nodes.
Authenticated browser workers should be pinned to appropriate user-owned hosts.
Home, BWA, and development profiles should be completely separate.
Each browser session needs one controller lease.
Handoffs need explicit receipts.
Public captures may be cached by URL and content hash.
Authenticated captures must not be shared across lanes.
Package and browser versions should be pinned in managed worker images.
Best pursuit path

This is not the smallest build. It is the sequence that preserves the best architecture while answering the expensive questions early:

Define the Lugos web contracts and authority boundaries.
Build the benchmark corpus and evaluation runner.
Implement adapters for oc, agent-browser read, interactive agent-browser, and direct Playwright.
Add the browser session broker, controller leases, and profile isolation.
Add immutable captures, evidence bundles, provenance, and artifact retention.
Integrate routing through task-router, run profiles, and Autowork.
Route consequential actions through Fade and approval receipts.
Instrument the entire path through AITU.
Add HUD inspection, session streaming, approval cards, and manual takeover.
Use benchmark and operating evidence to decide whether to keep oc, fork it, replace it, or use it only for specific site classes.

The architecture should remain correct if oc disappears tomorrow. Its likely value is as a fast compact-reader engine, but it should earn that role against agent-browser read and a direct extraction implementation. The larger Web Plane is worth considering because it would serve ORCA research, Autowork campaigns, AETA source work, Operator workflows, Fade actions, model-specific behavior tuning, terminal browsing, and future visual supervision through one coherent capability boundary.

---

# Deal finding as WEIR's first vertical slice

The abstract Web Plane needs a real consumer to prove it is useful rather than architectural make-work. Lode — the existing deal evaluator — is that consumer, and marketplace acquisition is a strong candidate for WEIR's first end-to-end vertical slice. This section records how deal finding should sit across the Lugos stack and why it exercises exactly the WEIR machinery that matters.

## The mistake to avoid

Two tempting conflations would damage the architecture:

- Do **not** make WEIR itself the deal finder. Knowing what constitutes a deal — comps, history, dedup, scoring, thresholds, alerting — is domain intelligence and belongs to Lode.
- Do **not** make Hermes the eBay collector. Lode already made the correct call: *"Do not make an LLM the primary collector, database, scheduler, or calculator."* An LLM as the collection layer is slower, nondeterministic, and unaccountable.

WEIR is the layer in between: get things from the web reliably and preserve evidence. Nothing more, nothing less.

## The clean three-tier shape

```text
        Chron / Lode deal finder
        (veins, scheduling, watch intent)
                    |
                    v
            search / watch intent
                    |
                    v
                  WEIR
          acquisition + evidence
                    |
        +-----------+------------------+
        |                              |
        v                              v
   eBay Browse API            page / browser fallback
   preferred                  oc / agent-browser
        |                              |
        +--------------+---------------+
                       v
              normalized listings
                       |
                       v
                 Lode evaluation
       dedupe / history / comps / scoring
                       |
                  strong candidate (strike)
                       |
                       v
              Hermes / LLM review
               when useful
                       |
                       v
                     alert
```

Three responsibilities, cleanly separated:

| Layer | Job |
| --- | --- |
| WEIR | Get things from the web reliably and preserve evidence |
| Lode / Chron | Know what constitutes a deal; track listings, dedupe, score, and alert |
| Hermes | Open-ended investigation and judgment when deterministic logic isn't enough |

WEIR is the source/acquisition abstraction. Lode remains the domain intelligence. Hermes sits one level higher and *consumes* WEIR; it must not reinvent browsing.

## What WEIR actually contributes to Lode

Lode already collects through the eBay Browse API today — with pagination, per-run deduplication, listing-state change detection, shipping-inclusive cost, and an explicit refusal to guess unknown shipping or tax. WEIR does not replace that; it gives that logic a better conceptual home and two capabilities Lode does not have on its own.

**1. A home for acquisition instead of one-off collectors.** Instead of:

```text
lode/
  ebay_api.py
  random web fallback
  maybe browser later
```

the acquisition surface becomes a set of WEIR engines:

```text
WEIR
  ebay.api.search
  ebay.api.item
  ebay.page.read
  ebay.browser.observe
```

Lode asks WEIR by intent, not by engine:

```text
intent: marketplace_search
source: ebay
query: Keychron C2 Pro
constraints:
  switch: red
  max_total_cost: 40
evidence_required: true
```

WEIR selects the eBay Browse API because it is the highest-quality available interface — consistent with the capability ladder (connector/API before compact reader before rendered browser).

**2. Enrichment via the capability ladder.** When the API returns a suspiciously incomplete listing, WEIR — not Lode, and not an LLM — escalates to acquire the actual item page:

```text
eBay API says:
  title
  $27.99
  $8.45 shipping
  condition: used

Lode:
  total = $36.44
  potentially qualifies (candidate)

WEIR enrichment:
  retrieve listing page (ebay.page.read)
  capture description
  capture structured condition
  maybe inspect photos separately (ebay.browser.observe)

Lode:
  classify candidate
  compare against known value (yield / grade)
  determine strike / not-strike
```

This is the first concrete instance of WEIR's engine-fallback and evidence-preservation claims running against a real workload rather than a benchmark corpus.

## Chron watches: broaden the source, keep the loop deterministic

For routine watches — a *vein* like "Keychron C2 Pro under $40" — do **not** put Hermes in the loop. The loop is cheap deterministic machinery, exactly what Lode was built around:

```text
schedule
  -> eBay query
  -> new/change detection
  -> total-cost filter
  -> product-specific rules
  -> alert
```

Hermes there would only add latency and nondeterminism. Where WEIR materially improves Chron is by broadening the *collection* layer beyond a single marketplace:

```text
Chron
  "red switch keyboard deal"

WEIR
  ├─ eBay Browse API
  ├─ Newegg / public search
  ├─ manufacturer clearance page
  ├─ Slickdeals
  ├─ Reddit deal thread
  └─ arbitrary supplied URL
             |
             v
      normalized evidence
             |
             v
       Chron / Lode rules
```

A Chron finder then stops being an "eBay finder" and becomes a deal-finding *policy* operating over whatever sources WEIR can provide.

## Where Hermes belongs

Hermes is the durable-specialist layer: multi-step autonomy, memory, learned procedures. It earns its place only when the task stops being deterministic:

- "Go investigate this weird listing."
- "Figure out whether this workstation is actually a deal."
- "Research this seller and comparable systems."
- "Try several search phrasings — sellers call this thing five different names."
- "Look outside eBay too and tell me what you conclude."

```text
Hermes specialist
      |
      | needs external evidence
      v
     WEIR
   /   |    \
 eBay Reddit manufacturer
      |
      v
 evidence bundle
      |
      v
 Hermes reasoning
```

Hermes should consume WEIR evidence, never browse independently.

## The provider-parity payoff

This fixes a real weakness in the current Lode plan. Lode's Phase 1 states that *"Providers cannot silently collect different evidence in Phase 1"* — the correct constraint, because otherwise Claude and Codex could score different pages and their evaluations would not be comparable. Today that is enforced by forbidding providers from browsing at all:

```text
WRONG
Claude -> browses whatever
Codex  -> browses whatever
       -> compare answers
```

With WEIR producing one immutable evidence bundle, the constraint can later be relaxed safely rather than removed:

```text
BETTER
          WEIR
            |
       evidence bundle
        /         \
     Claude       Codex
        \         /
       compare evaluations
```

Both providers review the same captured listing, comps, and source material. WEIR's `WebCapture` (content hash + provenance + immutable artifact refs) is exactly the object that makes "same evidence, different evaluators" verifiable rather than assumed.

## Why this is a good first slice for WEIR

Deal finding is not attractive because scraping eBay search pages with `oc` is easy — that would be the wrong build. It is attractive because implementing an **eBay acquisition engine that prefers the Browse API** forces WEIR to build, against a real consumer, the parts of the abstraction that actually matter:

- structured search results and pagination (not just single-page reads)
- a connector/API engine occupying rung 1 of the capability ladder, which currently has no adapter
- provenance and immutable normalized captures
- deterministic enrichment and engine fallback
- caching by URL and content hash
- a normalized listing shape independent of engine syntax

Lode is already built to consume normalized listings, so it is a ready-made test of whether the WEIR abstraction is useful or merely architectural. See `docs/marketplace-slice.md` for how this slice maps onto WEIR's contracts, engines, and roadmap.
