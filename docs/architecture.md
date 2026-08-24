# Architecture

## 1. Design goal

WEIR makes web access a capability plane rather than a collection of agent-specific browser tools.

The system should remain correct if any individual engine disappears. `oc`, `agent-browser`, Playwright, Chromium, and future service connectors are replaceable implementation choices behind stable Lugos contracts.

## 2. Logical architecture

```text
                           +----------------------+
                           | user / CLI / HUD     |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | task-router/profile  |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Autowork campaign    |
                           +----------+-----------+
                                      |
                                      v
+-------------------------------------------------------------------+
| WEIR                                                              |
|                                                                   |
| request classifier -> policy envelope -> engine router            |
|                           |                                       |
|              +------------+------------+                          |
|              |                         |                          |
|       public acquisition       authenticated operations           |
|              |                         |                          |
|       connector/readers       browser session broker              |
|              |                         |                          |
|       captures/evidence       observations/proposals              |
|              +------------+------------+                          |
|                           |                                       |
|                      verifier                                     |
+---------------------------+---------------------------------------+
                            |
             +--------------+----------------+
             |                               |
             v                               v
      read-only result                action proposal
                                             |
                                             v
                                     Fade / approval
                                             |
                                             v
                                      execution receipt
                                             |
             +-------------------------------+-------------------+
             |                    |                    |           |
             v                    v                    v           v
         Validation            Sulis                 AITU         HUD
```

## 3. Public acquisition plane

Characteristics:

- credential-free
- safe to fan out to workers
- aggressively cacheable when policy allows
- source and provenance oriented
- optimized for compact model context
- no ability to inherit authenticated browser state

Potential engines:

- direct connector/API
- Markdown or `llms.txt`
- feeds and JSON endpoints
- `oc`
- `agent-browser read`
- an eventual in-process extractor

The acquisition plane should return immutable captures. A reader's mutable navigation session is an optimization, not the evidence record.

## 4. Authenticated operations plane

Characteristics:

- browser profile is explicit
- credentials are never embedded in the request object
- session has one controller lease
- domain policy remains active after redirects and navigation
- observations and actions are separated
- side effects require typed risk classification
- post-action state is captured and verified

Potential engines:

- `agent-browser`
- Playwright
- direct CDP
- app-specific browser integrations

A browser process is transport. It is not the orchestrator or policy authority.

## 5. Routing dimensions

Engine routing should consider at least:

```text
operation mode
URL/site profile
data classification
auth requirement
JavaScript requirement
interaction requirement
side-effect class
worker capabilities
engine health/version
run-profile cost/depth constraints
model behavior profile
benchmark evidence
```

A static priority list is acceptable for bootstrapping but is not the intended final router.

## 6. Capture model

Every meaningful observation should be capturable as immutable evidence.

A `WebCapture` binds:

- requested URL
- final/canonical URL
- capture timestamp
- engine and version
- authentication scope identifier, never credentials
- content hash
- retained artifact references
- trust label
- normalized blocks or summary

The capture ID is safe to reference later. Engine-local element IDs are not.

## 7. Session model

`BrowserSession` is live mutable state.

It should include:

- session ID
- owning run
- worker/host
- browser engine
- profile ID
- trust/data class
- allowed domains
- controller lease
- active URL/tab metadata
- creation and expiry
- state such as active, paused, lost, or closed

A session must not be silently reused between unrelated runs simply because the same browser profile is available.

## 8. Observation and semantic locators

A structured browser observation should prioritize accessibility/DOM state:

```json
{
  "url": "https://portal.example/uploads",
  "title": "Uploads",
  "elements": [
    {
      "ref": "obs-local-e17",
      "role": "button",
      "label": "Submit 12 files",
      "state": "enabled"
    }
  ]
}
```

The observation-local ref can be used immediately. Durable recipes should instead store a semantic locator:

```json
{
  "role": "button",
  "name": "Submit 12 files",
  "near": "Pending files"
}
```

The runtime re-resolves the locator against a fresh observation before acting.

## 9. Action lifecycle

```text
observe
  -> resolve semantic target
  -> propose action
  -> classify risk
  -> check policy
  -> request approval if required
  -> reacquire/confirm state
  -> execute
  -> capture post-state
  -> verify expected result
  -> issue receipt
```

No step should infer success solely from having sent input.

## 10. Visual fallback

When structured state is insufficient:

```text
DOM/accessibility failure
  -> screenshot or targeted crop
  -> Argus/vision interpretation
  -> typed observation candidate
  -> bounded action proposal
```

Pixels can enrich an observation. They should not erase the action policy or approval boundary.

## 11. Worker placement

Public-reader workers may run on general Lugos nodes.

Authenticated browser workers should be placed according to profile and data class. Home, business, test, and restricted profiles should remain isolated. Worker inventory belongs in the Lugos capability/target registry rather than hard-coded into WEIR.

## 12. Engine-specific notes

### `oc`

Useful properties:

- compact numbered page representation
- JSON mode
- saved page state for cheap `read/find/next`
- explicit no-readable-content outcome
- browser-like request impersonation
- private/internal-target blocking

Integration rule: isolate each Lugos run with its own state directory/session name and copy useful output into immutable WEIR captures. Do not treat the `oc` session file as durable evidence.

### `agent-browser`

Useful properties:

- non-browser `read` mode
- rendered active-tab reading
- accessibility snapshots and refs
- Chromium interaction
- cookies/storage/profile state
- tabs, network inspection, screenshots, HAR, CDP, streaming

Integration rule: keep its broad feature set behind WEIR's narrower capability and authority contracts. Do not expose an unrestricted arbitrary-browser CLI to every seat merely because the backend supports it.

## 13. Architectural questions still open

1. Does WEIR become a Lugos submodule service, a library plus worker protocol, or both?
2. Is Fade definitively the executor for every side-effectful web action?
3. Which browser worker owns user-attached sessions and manual takeover?
4. What artifact store retains HTML, screenshots, and HAR files?
5. Which capture classes may be persisted under each data classification?
6. Which engine wins each acquisition route after benchmarking?
7. How much routing intelligence belongs in WEIR versus the wider APU/COGIN model-behavior layer?
