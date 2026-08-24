# First route comparison — oc vs agent-browser read

- Date: 2026-08-24
- Corpus: `benchmarks/tasks/public-acquisition.json` (9 public-acquisition tasks)
- Runs: `first-comparison` (invalidated by adapter bugs, kept for the failure
  record), `second-comparison` (clean; raw JSONL under `benchmarks/results/`,
  local-only by design)
- Host: Windows 11, Python 3.14
- Engines: `@only-cli/oc` 0.4.0; `agent-browser` 0.34.0
- Caveat: single host, single run per task, no fidelity scoring yet. This is
  a harness shakeout with directional evidence, not a promotion decision.

## Summary (second-comparison)

| engine | success | failure | mean latency | notes |
|---|---|---|---|---|
| oc | 9/9 | 0 | 0.57 s | |
| agent-browser-read | 8/9 | 1 | 0.77 s | exit 1 on `js-app-shell` (react.dev) |

## Per-task returned-content size (chars of normalized JSON)

| task | oc | agent-browser-read |
|---|---|---|
| static-short | 375 | 611 |
| docs-long | 87,807 | 57,246 |
| markdown-native | 1,562 | 2,292 |
| json-api | **464** | 6,972 |
| rss-feed | 12,519 | 16,065 |
| github-repo-docs | 33,642 | 13,255 |
| github-issue | 13,079 | 4,624 |
| news-article | 51,347 | 20,263 |
| js-app-shell | 17,263 | failed |

## Observations

1. Both engines are viable public readers; latencies are comparable and
   sub-second for most tasks.
2. **Compactness is not one-directional.** oc is smaller on simple/API-shaped
   pages; agent-browser's markdown-first strategy returns less on
   chrome-heavy pages (GitHub issue, Wikipedia article). Neither dominates.
3. **Fidelity flag: oc returned 464 chars for a ~7 KB JSON API response**
   (its render budget appears to truncate JSON). If confirmed, JSON APIs
   should route to a direct HTTP/connector engine, never through oc's
   renderer — consistent with the capability ladder putting connector/API
   above compact readers.
4. agent-browser's one failure (react.dev) exits 1 without a machine-readable
   reason on the read path; the adapter can only classify it as
   `engine_failure`. Deterministic fallback reasons (P1) will need better
   engine-side signals or response probing.
5. Harness shakeout value: the first run surfaced two real adapter bugs
   (Windows cp1252 decoding of UTF-8 stdout; daemon-held temp-file handles).
   Both fixed; the invalid run is retained as evidence that unknown-class
   failures were harness bugs, not engine behavior.

## Gaps before a routing decision

- oc does not expose a `--version`; probe records `null`. Version must come
  from the package manifest until upstream adds one.
- No fidelity scoring (content correctness vs source) — sizes alone cannot
  rank engines.
- No token counting; `content_chars` is a proxy.
- Single run per task; no variance data.
- Consent-wall / bot-challenge / search tasks from the evaluation plan are
  not yet in the corpus.
