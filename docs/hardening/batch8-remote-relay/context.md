# Batch 8 Remote Relay Evidence Context

This is a derived design review. It does not authorize or implement the remote relay.
The inspected source root was the local Lugos portfolio at revisions listed below.

## Source identity

| Component | Revision |
| --- | --- |
| WEIR | `0b15034360125b64446061e0cb656fa62143e105` |
| Fade | `18a48202f9f5dabb16df70c3ff33a32bc4a3473e` |
| Mission Control | `67d4e8fbac5c208dac842940dd09e818b8332221` |
| Lugos parent, including HUD and lugos-link | `cc3d796a89b907e03ab1e0261f679e8c39222479` |

The deterministic SHA-256 of the sorted `path<TAB>sha256` inventory below is
`0adaa84674645b675db556bca854a32a5e44d0f34cf454b295e4f963f2b1bfa6`.

## Evidence inventory

| ID | Evidence | SHA-256 |
| --- | --- | --- |
| `E1` | WEIR sibling integration decisions (`weir/docs/sibling-integration-plan.md`) | `44a1f9bb6136f29b8390928e2bf5e7c80d8120b86148ec9b6beacda0a56e53bb` |
| `E2` | Remaining integration sequencing (`weir/docs/remaining-integration-plan.md`) | `dbd46da0432f47f29c7127fc9f83751747b860dc85a6d1089204fcc632380798` |
| `E3` | Fade WEIR authority implementation (`fade/fade/weir_authority.py`) | `3b8576866741f9e421845bc845870b04570b537fd805b6f9f6c8177be91c2183` |
| `E4` | Fade authority startup configuration (`fade/fade/cli.py`) | `250a9732997d4f787dbff9b3fc192721b46588cde70c20d2ba4dce6f1d36cddb` |
| `E5` | HUD operator HTTP boundary (`lugos-hud/src/operatorApi/http.mjs`) | `30b827cc3314a9345db2e9e54c18e7e3368a7bf3e59cb019c055dfa88fb94563` |
| `E6` | HUD command gateway and receipt behavior (`lugos-hud/src/operatorApi/commands.mjs`) | `94386dbeb54e700154500a6da57182d947a336eded70aa47f0fb8211aabd0980` |
| `E7` | HUD live registry (`lugos-hud/src/operatorApi/live.mjs`) | `4e87185ddb479d2f4c1e934767835efb325841bd492022ee6297346c3648eb1e` |
| `E8` | HUD redacted WEIR projection (`lugos-hud/src/operatorApi/weirProjection.mjs`) | `e47db99bb1dd11bb0cf4136e8a3cf1a55d2c429c15bbb193c2ed47900fc856c5` |
| `E9` | Mission Control operator command route (`mission-control/src/app/api/lugos/commands/route.ts`) | `3d5710f8b6ff4a763ce752c0614b8ab8f4555e0acebe066d6f28bd8f98fe1af0` |
| `E10` | Mission Control server-side HUD client (`mission-control/src/integrations/lugos/operator-client.ts`) | `929be5db1374aea6e189f2b77dbc8ea855c4ef5c4e823f6c7217a0bb439fc2e3` |
| `E11` | Mission Control network, session, and CSRF edge (`mission-control/src/proxy.ts`) | `ecbc7fcfd0434c3bd6b6ce3063807bb0dfbeaa26638add50202b5b3de0a893fd` |
| `E12` | Mission Control/HUD boundary documentation (`mission-control/docs/lugos-operator-integration.md`) | `5985bc2718b1676dcbc6d2334bc09acae65f774526bb034f0a7d5b2f443fdf0c` |
| `E13` | Existing Tailscale connectivity notes (`lugos-link/docs/cloud-session-lan-access.md`) | `48071ab77f5b15bb70baccb3287400bc3755b9f5fdde57a352ddb75431229994` |

## Evidence limitations

- The requested reverse ordering means the local Batch 9 canary had not run when this
  review was written. The recommendation therefore remains gated on that canary.
- No live deployment, network path, queue implementation, or operator device was
  inspected. Latency, availability, and queue-volume statements are hypotheses with
  explicit validation work, not measurements.
- Mission Control authenticates operators, but the current HUD command hop forwards a
  shared server credential and does not propagate the human principal. Fade currently
  records its authenticated transport principal as the decision actor.

