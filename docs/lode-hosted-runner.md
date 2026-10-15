# WEIR on Lode's hosted scout runner

Lode's `WeirCollector` shells out to two commands:

```text
weir search QUERY --source ebay --pages N
weir enrich LISTING_URL
```

The hosted scout runs on an ephemeral `ubuntu-latest` GitHub Actions runner with
Python 3.12. This page is the contract for installing and running WEIR there. Lode
keeps scheduling, evaluation, valuation, persistence and notification; WEIR only
acquires and returns evidence.

## Install

Install a full commit SHA into its own virtual environment, and expose only the
`weir` entry point. Branch names and tags can move, but a commit SHA cannot. A
separate venv keeps WEIR's dependencies (`PyYAML`, `cryptography`) out of Lode's
environment.

```bash
python -m venv "$RUNNER_TEMP/weir-venv"
"$RUNNER_TEMP/weir-venv/bin/python" -m pip install \
  "lugos-weir @ git+https://github.com/mdn87/weir.git@<40-char commit sha>"
mkdir -p "$RUNNER_TEMP/bin"
ln -s "$RUNNER_TEMP/weir-venv/bin/weir" "$RUNNER_TEMP/bin/weir"
echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"
```

Do not put the venv's whole `bin/` on `PATH`. Its `python` would then shadow the
interpreter Lode is installed into. The consumer (Lode) records the pinned SHA and
the exact dependency versions. The `lode-contract` CI job here builds the same
non-editable install on Python 3.12 and runs the CLI from outside the checkout. That
proves the packaged site profiles resolve without a source tree.

`weir engines` is a network-free readiness check. On a correctly configured runner,
`ebay` reports `available: true` with `credentials configured (production, EBAY_US)`.
`oc` and `agent-browser-read` report unavailable.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `EBAY_CLIENT_ID` / `EBAY_CLIENT_SECRET` | yes | eBay application keyset (client-credentials grant, `api_scope` only). These are the names Lode already uses. `WEIR_EBAY_CLIENT_ID` / `WEIR_EBAY_CLIENT_SECRET` take precedence when set. |
| `EBAY_MARKETPLACE_ID` | no | Sent as `X-EBAY-C-MARKETPLACE-ID` on every Browse call. Defaults to `EBAY_US`, the same header Lode's direct collector sends. `WEIR_EBAY_MARKETPLACE_ID` takes precedence. |
| `WEIR_EBAY_ENV` | no | `production` (default) or `sandbox`. |
| `WEIR_TRACE_FILE` | no | Append metadata-only JSONL spans: route, engine, outcome, failure class and duration. The spans never include page content, queries or credentials, so they are safe to upload as a run artifact. |
| `WEIR_STATE_DIR` | no, leave unset | Durable capture store and cache. Not useful on an ephemeral runner. Lode persists what it consumes. |

Runner permissions: none beyond the scout's existing `contents: read`. The WEIR
repository is public, so the install needs no token. Credentials come only from the
two existing eBay secrets. Nothing reads browser profiles, cookies, `~/.config` or
any other local authentication state, and nothing prompts for a login. Authenticated
or unsupported sources stay behind their existing approval boundaries. WEIR on the
runner can reach only the public eBay Browse API.

## CLI contract

- **Success:** exit `0`, one JSON envelope on stdout, empty stderr.
- **Failure:** exit `2`, empty stdout, one JSON object on stderr:
  `{"ok": false, "class": ..., "error": ..., "attempts": [...]}`.

| Situation | Exit | `class` |
| --- | --- | --- |
| Credentials missing | 2 | `engine_unavailable`. The error text contains `credentials not configured`, which Lode maps to a configuration error. |
| Token or Browse API refused (401/403) | 2 | `auth_required` |
| Throttled or server error after 3 attempts (429/5xx) | 2 | `network_failure` |
| Timeout, DNS failure, dropped connection | 2 | `network_failure` (retried within the same 3-attempt bound) |
| Non-JSON or wrongly typed API body | 2 | `engine_failure` |
| Listings reported but none usable, or a nonzero/missing `total` with no listings | 2 | `engine_failure` |
| eBay reports `total: 0` | 0 | Success with `listings: []`. This is the only empty success. |
| `enrich` with no page-reader CLI installed | 2 | `engine_unavailable`. This is the hosted runner's normal state. |
| `enrich` page reader returns a blank page | 2 | `cannot_read` |

A run either returns every page it fetched or fails as a whole. A failure on page 2
discards page 1, so there is no partial success. Listings that cannot be normalized
are dropped. If some listings survive, the search still succeeds, and the dropped
count appears only in engine diagnostics. If none survive, the search fails.

### Evidence a search returns

`capture` carries `capture_id`, `captured_at`, `content_hash` (the SHA-256 of the
canonical content), `engine` (`ebay`), `engine_version` (`browse-v1`) and
`auth_scope` (`app:ebay-app`). `request.run_id` echoes `--run-id`. Each entry in
`capture.content.listings` has these fields:

- `source_item_id`: the Browse `itemId`, for example `v1|316000000001|0`. This is
  the same id Lode's direct collector keys on.
- `canonical_url`: the item URL with tracking query and fragment removed. The
  untouched `itemWebUrl` stays in `raw`.
- `price` / `shipping`: `{amount, currency}` with the amount as a decimal string,
  or the literal `"unknown"`. Calculated or absent shipping is `"unknown"` and is
  never assumed to be zero.
- `condition`: `{raw, condition_id}` or `"unknown"`.
- `observed_at`: one UTC timestamp per search call, taken before the first page.
- `content_hash`: covers only the state-bearing fields, so an unchanged listing
  hashes the same across runs.
- `enrichment`: always `none` in a search result.
- `raw`: the unmodified Browse item summary, including `buyingOptions`,
  `itemEndDate` for auctions, `itemCreationDate`, images and seller.

## What enrichment does and does not verify

| Path | Current availability | Current price | Ended status | Timestamp |
| --- | --- | --- | --- | --- |
| `weir search` (Browse item summary) | Not stated per item. Search returns live listings only. | Yes, as of `observed_at`. An auction's price is its current bid. | No. `raw.itemEndDate` is the scheduled end for auctions. | `observed_at` and `captured_at` |
| `weir enrich` (page reader, rung 2) | **No** | **No.** Page text is not normalized. | **No** | `captured_at` is when the page was read. eBay supplies no timestamp. |
| `weir read URL --engine ebay` (Browse item detail; Lode does not call it today) | Evidence only: `raw.estimatedAvailabilities[].estimatedAvailabilityStatus`. WEIR does not interpret it. | Yes, normalized as of `observed_at` | Not interpreted. A 404 is `cannot_read` ("item not found"), and WEIR does not distinguish ended, removed or invalid items. | `observed_at` |

A page capture is never verified availability. It can show an ended listing or an
interstitial page, and only its text reaches Lode, as the listing description. A
listing re-check before an actionable alert should use the Browse item read:
`weir read <canonical_url> --engine ebay`. Lode owns interpreting
`estimatedAvailabilities`, `itemEndDate` and the verification timestamp.

A runner without a page reader returns `engine_unavailable` for `enrich`. Lode's
reader-install follow-up pins `agent-browser` and enables its public URL text-read
path; this does not launch Chrome or reuse authenticated browser state. Keep
`enrich_candidates = false` until a permitted listing read succeeds on that runner.
A configured reader does not guarantee site access or useful listing evidence.

## Tests

- **Offline contract:**
  `python -m unittest tests.test_lode_cli_contract tests.test_ebay_connector`.
  It runs `weir.cli.main` in-process against a stubbed Browse API and stubbed
  readers. It needs no network, credentials or reader CLIs.
- **Transcripts for Lode:** `python scripts/export_lode_cli_transcripts.py OUT_DIR`
  writes the exact argv, exit code, stdout and stderr Lode's runner receives, one
  file per scenario. Lode vendors these under `tests/fixtures/weir/`. Regenerate
  them whenever the pinned SHA changes.
- **Live smoke (opt-in):**
  `WEIR_LIVE_SMOKE=1 python -m unittest -v tests.test_live_ebay_smoke`, run with
  the eBay keyset in the environment. It makes about four read-only Browse calls: a
  real search with schema validation, a re-read of the first item, a no-match query
  that must report `total: 0`, and a check that `enrich` fails cleanly when no reader
  is installed.

## Search ordering

Lode passes `--constraints '{"sort":"newlyListed"}'` for its newest-first watches.
The eBay adapter forwards this supported sort to Browse, so a bounded watch does
not repeatedly inspect only relevance-ranked listings. Supported explicit sorts
are `newlyListed`, `endingSoonest`, `price`, and `-price`; omitting the constraint
preserves eBay's default order. Unsupported values fail before acquisition.
