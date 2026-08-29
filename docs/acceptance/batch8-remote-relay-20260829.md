# Batch 8 Remote Relay Production Acceptance — 2026-08-29

Status: **live production activation passed**. The Mission Control and relay server
path remains enabled; workstation polling still requires explicit process-local
arming. The deployed path is limited to the reviewed `4070pc` workstation identity,
`lugos-host` relay, Mission Control passkey origin, and disabled-by-default source
contracts. The positive canary used only public synthetic data on an ephemeral
workstation loopback page; it touched no production account.

## Reviewed release and identity

- Target: known-good SSH alias `lugos-host`, confirmed as `matt@10.0.1.33`.
- Lugos parent release: `ee1a2350c9a64340e4273925dc7d66b2cdf3e9f2`.
- Mission Control child: `9f1f43439128b1081f57dad83515a96ec4677537`.
- Fade source: `72a695cf9c5aab6a30a8a2634dc32fd34b654eb0`.
- WEIR canary source: `bf38c1f06ec2a42169a98da28fc56181b41fc040`.
- Future canary event summaries use Fade's `type` field after WEIR fix
  `9aaa8242d7193683c447750cb614ab251f078464`.
- Mission Control security scans `9fb4eb20-0ab8-4895-9413-2d1cdafa2303` and
  `b877d1f8-16de-4f35-88ed-c3aeaef92271` both completed with zero findings.

The host release marker exactly matched the parent revision. Mission Control,
`lugos-remote-relay`, and `lugos-event-ingest` were active after the canary, and the
relay was enabled for restart. All three units had zero error-priority journal lines
from 09:30 UTC through the acceptance audit.

## Deployed boundary

- Runtime flags were `MC_REMOTE_DECISIONS_ENABLED=true`,
  `MC_REMOTE_WEBAUTHN_ENABLED=true`, `MC_REMOTE_ACTOR_FORMAT=mc-user-numeric-v1`,
  and `LUGOS_RELAY_ISSUER_ENABLED=true`.
- The relay listened only on `127.0.0.1:8792` for issuer operations and
  `10.0.1.33:8793` for workstation pull operations.
- UFW exposed port 8793 through exactly
  `allow from 10.0.1.30 to 10.0.1.33 port 8793 proto tcp`.
- A fresh external health request negotiated TLS 1.3 and authenticated as device
  `workstation-4070pc` with transport principal `relay-device:4070pc`.
- The workstation private key ACL grants full control only to SYSTEM and local
  Administrators, and read access only to `MATT\Matt`.
- Mission Control retained one passkey. Across the browser retry, two authentication
  challenges were consumed, one step-up grant was consumed, and no live challenge or
  grant remained.

## One-effect canary

The retained report is
[`batch8-remote-relay-canary-20260829.json`](batch8-remote-relay-canary-20260829.json).
It ran from 09:45:46 to 09:49:26 UTC as
`batch8-remote-canary-1d6d687b2770630f`. Its canonical pre-self-hash basis is
`sha256:d428d933b6b977227b7bc3c3918963b98dc3ddec65b4402171675438e92a1f5e`;
the original Windows raw file's byte hash is
`sha256:236f8b62c83baf4fbbe0a50b9b40aec9132c990642ce6a2eceb7f92f990b080a`,
and the repository's LF-normalized copy has byte hash
`sha256:347df67f811d32ae34b3069556a1dc8f6832af27db40b13bfd6c85832673f349`.

Immediately before the run, `C:\Users\Matt\.local\bin\apu-watch.exe` reported APU
0.9.0, provider `codex`, strict selection, zero ambiguity, and a fresh successful
attribution. The canary then proved:

- one real Playwright fill and exactly one worker apply call;
- a single-use permit, durable reservation before dispatch, final revocation check,
  and semantic postcondition verification;
- one completed receipt, an active final browser session, and no second effect after
  restarting the relay poller;
- a signed capsule bound to the passkey actor and mTLS transport principal; and
- no action parameter or synthetic value in the public Fade, relay, event, or Mission
  Control records.

The immutable correlation anchors were:

| Record | Value |
| --- | --- |
| WorkContext | `sha256:3ce454d9766c70a38c6d63bdd4ad24340f2af0fa42d2abbb74a58b65cafd4d0b` |
| Proposal | `sha256:c9656d0c0207908379d5501887040a3b27058fa8f6200f0a9421e4af21a02de3` |
| Command | `mc-remote-approve-c9656d0c0207908379d5501887040a3b` |
| Capsule | `capsule-5a719e72f31af3064b6b6e5b4069cbb4f263` |
| Receipt | `receipt-afbe9e14ac370f869f34049a45d821f806852fdb` |
| Receipt hash | `sha256:9baa8fd79f7317860c689364a1a8d405075715816858ac4d9d1dc12c7787f6e0` |
| Acknowledgement | `sha256:74c0fcaa92149f79ab9e1c74b02ccb045ae56392c3d7ee08b10a25a9316769eb` |

An initial invocation stopped during local directory preflight because the run and
state paths overlapped. Its retained directory is empty, and it created no proposal,
permit, relay command, or effect. The corrected invocation above was the only live
canary.

## Independent terminal and redaction readback

Fade's isolated ingress ledger contained one capsule and the ordered transitions
`reserved -> dispatching -> settled`, all bound to the expected device principal.
WEIR's browser store contained one completed execution reservation and one verified
receipt. The host relay row reached `acknowledged`, revision 3, outcome `completed`,
with the expected acknowledgement hash. After the bounded retention interval, relay
maintenance reported zero live and zero unpurged entries; the row retained its audit
anchors with `body_purged=1` and `capsule_json IS NULL`.

The canonical event journal independently contained exactly these two canary records:

- `weir.action.proposed` / `proposed`; and
- `weir.action.completed` / `completed`.

Both came from `10.0.1.30`, carried the exact correlation and proposal hashes, and
contained zero full-authority fields and no synthetic fill value. Mission Control's
live Lugos page then showed cursor `weir-action-completed-1d6d687b2770630f`, one
passkey, and no WEIR proposal awaiting a decision.

The retained runner report displays `event_types: ["None"]`. This was a diagnostic
summary bug: Fade emits authority-event names in `type`, while the runner queried
`event_type`. It did not participate in any pass assertion or mutate relay behavior.
The canonical journal readback above proves both WEIR projection events, and
`9aaa8242d7193683c447750cb614ab251f078464` corrects future reports and fails closed
on malformed Fade events. The report's JSON values are retained without correcting
the historical field; only line endings are normalized by repository policy.

## Final disposition

Batch 8's Mission Control and relay server path remains active on the reviewed target.
No persistent or generic Fade poller was installed; workstation pull authority still
requires the explicitly armed, bounded client process. Source defaults and the
activation script's rollback path remain unchanged. No credential, passkey identifier,
bearer, capsule body, action parameter, or browser profile content is included in this
acceptance record.
