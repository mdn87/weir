# Linux enrolled-field adapter qualification

On November 22, 2026, Fade submitted one approved fill to WEIR on `lugos-host`. A real Chromium process entered `WEIR-CANARY` in a disposable field. An independently authenticated observer read the value from the pinned document and node. A second browser opened the same enrolled bytes and found the field empty. [Run evidence](linux-enrolled-fill-20261122.json)

| Check | Observed result |
| --- | --- |
| HTTPS source | The default trust store rejected the disposable certificate before the first GET. With the private test CA mounted only in the isolated reader, the fixture received two GETs and zero writes. |
| Browser authority | Separate dynamic Linux users issued the read and fill operations. The controller denied a fill request from the observer and a read request from the effect principal. |
| Isolation through exit | Both service cgroups disappeared. Each had eight observed processes, including the pinned browser and renderer. All six network and Unix-socket receivers passed their controls and recorded zero unexpected deliveries. The receipt binds the saved shutdown evidence. |
| Lost response and restart | Fade issued one execute request. After losing the response it recovered the receipt by status. A restarted WEIR service returned the same receipt without opening a browser. |
| Grant storage | A disposable ext4 filesystem in a private mount namespace exercised the production trust loader. The loader rejected a rewindable witness, accepted the kernel append-only witness and rejected the fixture signer. |

The Linux regression suite exercised process death before and after the ledger and witness writes, concurrent status and execute requests, stale or withdrawn authority, replaced documents, storage rollback and uncertain shutdown. A reservation interrupted before dispatch stayed spent and cancelled. An interrupted dispatch produced a quarantined unknown receipt with only its pre-effect capture. [Regression tests](../../tests/test_enrolled_driver.py) · [Native qualification](../../scripts/verify_enrolled_fill.py)

The qualification used disposable signing keys and a private HTTPS page. The owner has authorized rehearsal only. The live canary still needs a commissioned Linux grant, an eligible owner-controlled page, the owner's enrollment decision and a separate passkey approval for the proposed fill. The grant authorizes a transient local browser edit. Publishing a saved change is a separate board item. [Linux action policy](../linux-first-action-policy.md)
