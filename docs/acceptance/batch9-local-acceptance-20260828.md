# Batch 9 Local Acceptance — 2026-08-28

Status: **local/source acceptance passed**. Deployment readback remains part of the
later Mission Control/HUD and APU/Dias rollout steps because the operator requested
the remaining work in reverse order.

## Live Fade/WEIR canary

The reusable runner [`scripts/run_fade_weir_action_canary.py`](../../scripts/run_fade_weir_action_canary.py)
started an ephemeral HTTP loopback form, a real headless Playwright fixture worker,
WEIR's authenticated loopback service, and Fade's authenticated loopback authority
service. It performed one public `fill` action under `risk=unknown` and retained raw
stores under ignored `artifacts/` state.

Evidence: [`batch9-local-canary-20260828.json`](batch9-local-canary-20260828.json),
report basis digest
`sha256:6e1c1bc50e565e78b8f53fdb503f32014bacfede070f6af5cc8c2198033b6131`.

The runner deliberately discarded WEIR's first successful execution response. Fade
reconciled the terminal status, a same-process replay returned the same receipt, a
conflicting replay returned HTTP 409, and a Fade/WEIR service restart returned the same
receipt again. Playwright observed exactly one DOM input effect and WEIR restored the
session to `active`. Public Fade records and events contained neither the marker value
nor a `parameters` field.

## Correlation-chain proof

The live run produced one immutable WorkContext hash:

`sha256:616a1cf2bd585394faaa287a50fb1febdd1cf48d4eecbe8c681f7b2f51067dff`

That exact context document and hash were accepted by:

- WEIR's action proposal, permit, and receipt path;
- lugos-mcp `BoundWorkContext` and a disabled fixture `DispatchContext`;
- Autowork's DispatchRequest v5 `BoundWorkContext` consumer; and
- HUD's `lugos-hud-weir/v1` projector for the actual completed action event.

The fixture DispatchContext does not select RF7's production provider and grants no
runtime authority.

## Contract and negative gates

| Component | Gate | Result |
| --- | --- | --- |
| Fade | `tests/test_weir_authority.py` | 31 passed |
| lugos-mcp | dispatch context, WEIR adapter, and disabled wiring tests | 25 passed |
| Autowork | sealed-evidence DispatchRequest v5 tests | 16 passed |
| HUD | WEIR snapshot/delta projection contract | 5 passed |
| Mission Control | operator contract, routes, and WEIR tolerance | 20 passed |
| APU | exact selection, typed `no_attribution`, and behavior evidence | 28 passed |

Together these gates cover forged context, changed evidence, stale or mismatched focus,
ambiguous attribution, wrong-session or replayed permits, response loss, conflicting
replay, parameter leakage, `outcome_unknown`, and restart recovery.

The final repository gates also passed against the landed source basis:

- WEIR: 307 passed, 1 skipped;
- Fade: 247 passed; and
- the Lugos parent suite, including Autowork: 3,571 passed, 31 skipped.

## Deferred deployment readback

This evidence does not claim that Mission Control's deployed process already accepts
`weir`, that HUD has registered the projection, or that the installed APU watcher is
running the new selector. Those checks occur in the later rollout steps and must reuse
the context and receipt bindings recorded here. Batch 8 relay implementation remains
disabled; its review recommendation is independent of this local acceptance result.
