# Review a private Linux field with a passkey

Mission Control can enroll a textbox on WEIR's private test page and approve one temporary fill. Open **Lugos Operations** in Full mode using the designated local operator account. The card shows the page, the accessible field name, the test ID, the change from empty to `WEIR-CANARY`, and how WEIR checks discard.

1. Choose **Approve enrollment with passkey** for that field.
2. When WEIR publishes its observed proposal, check the field again and choose **Approve fill with passkey**. A canceled or expired review grants no permission. Start a fresh rehearsal if the review expires.
3. Fade submits the signed approval to WEIR. WEIR verifies the value, closes the browser and checks an empty copy in a new browser. The action receipt remains available after a restart.

## Run the rehearsal

Install the WEIR and Fade wheels in the host’s dedicated application environment. `weir-canary readiness` inspects local commissioning inputs. `weir-canary template` emits the eligible static page and required headers. Both commands work without a session or grant. The installed browser driver uses the sealed Playwright and Chromium distribution on the Linux rehearsal host.

Use a separate root-owned rehearsal exchange with a protected parent, a private read group and the following directories. Set the setgid bit on shared directories so records inherit the reader group. Each publisher needs write access only to its own directory.

| Directory | Publisher | Contents |
| --- | --- | --- |
| `config` | root | Private `pins.json` with the rehearsal issuer’s Ed25519 public key as base64, `actor_id`, `device_id`, `issuer`, `key_id`, `web_uid` and `issuer_uid`. The two service UIDs must be distinct and unprivileged. |
| `review` | WEIR supervisor (root) | The current field and decision digest. Mission Control and the issuer can read this directory. |
| `stepups` | Mission Control | A receipt for each verified passkey assertion. The issuer and WEIR can read it. |
| `decisions` | Dedicated rehearsal issuer | One signed decision for each review. Fade and WEIR can read it. |

Set `MC_WEIR_FIELD_REHEARSAL_ENABLED=true`, `MC_WEIR_FIELD_OWNER`, `MC_WEIR_FIELD_DEVICE`, `MC_WEIR_FIELD_REVIEW_DIR` and `MC_WEIR_FIELD_STEPUP_DIR` on **both** the private Mission Control instance and its dedicated issuer. Mission Control also needs its normal HTTPS WebAuthn origin, relying-party ID, enabled verifier and an enrolled operator. Give the issuer `MC_WEIR_FIELD_STEPUP_UID`, `MC_WEIR_FIELD_DECISIONS_DIR`, `MC_WEIR_FIELD_ISSUER`, `MC_WEIR_FIELD_KEY_ID` and its own `weir-field-signing-key` in `CREDENTIALS_DIRECTORY`. The web process must have no access to that key. Start the compiled issuer with `node dist-relay/relay/field-issuer.js --watch`.

Mission Control is the trusted passkey verifier in this rehearsal. It verifies user presence and verification, binds its one-time challenge to the review in its database, and publishes the receipt under its own Linux account. The issuer trusts that account. Fade verifies the issuer signature and WEIR compares the separate records. A compromise of the web process could authorize a private rehearsal. This trust decision requires a new review before any production use.

Run `scripts/verify_enrolled_fill.py NEW_PRIVATE_RUN --owner-exchange ABSOLUTE_EXCHANGE` from a trusted installation on the Linux verification host. The supervisor creates its own disposable HTTPS page, revocation source, authority and one-use witness. It publishes each review and waits for both protected records before proceeding. To qualify without a human passkey, run the Mission Control field ceremony test against that exchange using its isolated in-memory account and Chromium virtual authenticator. Its test origin is fixed to `field-owner.test`.

To inspect a signed review during its validity window, use `FADE_WEIR_FIELD_REHEARSAL_ENABLED=true fade-field-review verify --exchange ABSOLUTE_EXCHANGE` from an account with read access. WEIR creates signable reviews only for the private rehearsal audience. The commissioned host command prints a local, unsigned preview. Commissioning an actual grant and enabling any live action require a separate deployment decision.

## Acceptance on November 22, 2026

An installed WEIR 0.7.0 and Fade 0.9.1 completed the private run on `lugos-host`. Mission Control verified two Chromium virtual-authenticator assertions for a disposable operator account, including a 32-second pause before fill approval. The dedicated issuer signed both receipts. Fade dispatched once. A fresh browser found the field empty, and both replay and restart returned the original receipt. The page received two reads and zero writes. The live host readiness check reported every commissioning input missing. [Recorded run](acceptance/linux-field-owner-review-20261122.json)

Independent implementation review `20261122-101121-cross-review` identified the human approval delay, the trust placed in Mission Control, and the production preview boundary. The final native run exercised the corrected path. Matt's passkey and public website were outside this rehearsal.
