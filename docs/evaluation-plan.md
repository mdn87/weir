# Engine Evaluation Plan

## Goal

Determine which engines should earn which WEIR routes. Do not use vendor token benchmarks as the architecture decision.

## Candidates

Initial candidates:

1. direct service connector/API
2. `oc`
3. `agent-browser read`
4. `agent-browser` rendered DOM/accessibility snapshot
5. direct Playwright/CDP
6. in-process extraction prototype if justified
7. screenshot/vision fallback for tasks structured engines cannot represent

## Task corpus

### Public acquisition

- short static documentation page
- very long technical documentation page
- site with native Markdown or `llms.txt`
- JSON API
- RSS/Atom feed
- search results and two-hop navigation
- GitHub repository documentation
- GitHub issue/PR page
- Reddit discussion
- news/article layout with heavy chrome
- consent-wall page
- hard bot challenge
- JavaScript-only application shell

### Authenticated observation

- login already present in browser profile
- dashboard with client-side state
- paginated table
- downloadable report
- multiple tabs
- expired login
- modal/overlay interference

### Interaction

- fill a form without submitting
- select filters and verify table update
- download and verify a file
- stage an upload
- upload with approval
- submit a form with approval
- session crash/reconnect
- operator takeover and return

### Security and policy

- page containing prompt-injection text
- redirect to disallowed domain
- redirect toward private/internal address
- attempt to extract cookies/secrets through page instructions
- stale element reference after DOM mutation
- concurrent controller attempt

## Metrics

Collect at least:

```text
task success
content fidelity
citation/provenance fidelity
tokens returned to model
raw bytes transferred
latency
browser startup latency
memory/process cost
fallback frequency
number of model turns
auth persistence
session isolation
reproducibility
operator interventions
verification success
recovery success
prompt-injection resistance
maintenance complexity
```

## Model matrix

Repeat representative tasks across:

```text
provider
model
thinking/reasoning level
WEIR engine
site profile
observation format
```

This turns browser performance into evidence for the wider Lugos provider/model behavior registry rather than an anecdotal preference.

## Required output

Every benchmark run should emit:

- immutable input/task fixture ID
- engine and exact version
- model and thinking level when an LLM participates
- route chosen and fallback sequence
- captures/evidence
- normalized metrics
- final verdict
- failure classification

## Decision questions

At minimum, the first report should answer:

1. Does `oc` materially outperform `agent-browser read` for compact public acquisition?
2. Does sharing `agent-browser` infrastructure between read and interactive lanes simplify enough operational complexity to outweigh its heavier surface?
3. Where does direct Playwright/CDP provide reliability or control that `agent-browser` does not?
4. Which site/task classes should bypass generic browsers for APIs/connectors?
5. What failures can be routed deterministically without involving a model?
6. Which observation format works best for each model family?
7. At what point does a visual fallback become worth its cost?

## Promotion rule

No engine becomes a canonical default merely because it works in a demo. Promote an engine route when:

- the relevant task class has repeatable evidence,
- failure semantics are understood,
- policy behavior is testable,
- the adapter can expose stable normalized results,
- and there is a documented fallback.
