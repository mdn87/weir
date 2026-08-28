# Browser store schema v2

Schema v2 keeps browser sessions, controller fences, host-global credential
reservations, action reservations, receipts, and unknown-outcome quarantines in one
SQLite transaction boundary. A fresh database is created directly at v2. Opening an
existing v1 database fails closed; WEIR never migrates it during startup.

No migration was run as part of the source implementation. Migrating an operator
database remains a separate approved maintenance action.

## Trusted credential identity

`StaticProfileStateRegistry` is the first concrete trusted profile-state registry. A
deployment provisioner populates it from an ACL-protected configuration source and
assigns a stable, opaque `credential_binding_id` to each real credential state. The
identifier is not derived from cookies, tokens, profile paths, or caller labels, and
WEIR never persists the credential material.

Session admission reserves that binding before browser OPEN dispatch. A partial unique
index permits only one `active` or `quarantined` reservation for a binding, even when
worker IDs and local profile labels differ. Recovery is limited to the exact live
worker instance recorded on the reservation.

There are exactly two release paths:

1. The recorded worker instance completes the close protocol and attests cleanup while
   no death evidence exists for that instance.
2. An authenticated operator references already-persisted process-tree death evidence
   and submits the exact session epoch, worker ID, worker instance, binding ID, and
   `release_after_confirmed_worker_death` disposition.

A closed-context event alone cannot release a binding. Changed, stale, incomplete, or
ambiguous retirement input leaves it quarantined. Direct database edits are unsupported.

## Offline v1-to-v2 procedure

Stop the WEIR service and every browser worker before starting. Prepare a JSON mapping
that exactly covers every non-closed v1 session:

```json
{
  "contract_version": "0.1",
  "sessions": {
    "session-example": {
      "credential_binding_id": "credential-binding-example",
      "worker_instance_id": "worker-instance-example"
    }
  }
}
```

The mapping contains identifiers only, never cookies or tokens. First run the read-only
validation:

```powershell
python -m weir.browser.store_migration `
  --database <browser-store.sqlite3> `
  --bindings <migration-bindings.json> `
  --dry-run
```

After separate operator approval, choose a new, nonexisting backup path and run the
offline migration:

```powershell
python -m weir.browser.store_migration `
  --database <browser-store.sqlite3> `
  --bindings <migration-bindings.json> `
  --backup <browser-store.v1.backup.sqlite3>
```

The command verifies v1 integrity, creates and verifies the backup, obtains an
exclusive database lock, aborts if the source changed during backup, adds the v2 tables
transactionally, and creates quarantined reservations for all non-closed sessions.
It does not silently choose bindings.

Before enabling any v2 writer, compare the migrated database with the backup:

```powershell
python -m weir.browser.store_migration `
  --database <browser-store.sqlite3> `
  --bindings <migration-bindings.json> `
  --backup <browser-store.v1.backup.sqlite3> `
  --readback
```

Readback is repeatable and read-only. It runs integrity checks, verifies every original
v1 table byte-for-value at the SQLite row level, and checks each migrated reservation
against the trusted mapping.

Rollback may restore the verified v1 backup only before a v2 writer is enabled. After
that point, preserve the v2 store and disable new routes; do not discard reservation,
receipt, retirement, or quarantine history.

## Action crash boundary

Before any future browser effect, WEIR reserves the exact permit hash, proposal hash,
action ID, request digest, command ID, session epoch, and controller generation. An
action and proposal can have only one reservation even if a caller presents a second
permit. Exact replay
returns the stored reservation even after permit expiry; changed content fails.
Terminal receipts update that reservation in the same transaction.

If an effect may have happened but cannot be proved, the receipt, active quarantine,
lost session state, invalidated lease, and quarantined credential are committed
atomically as `outcome_unknown`. Clearing the action quarantine appends one
operator-authored successor; it does not release the credential or resume automation.
