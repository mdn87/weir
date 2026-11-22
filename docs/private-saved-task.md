# Approve a private task edit

WEIR can save a title to a disposable Mission Control task and check what the site recorded. The task lives in a fresh rehearsal database. Live website changes are disabled.

In the private Mission Control instance, open **Lugos → Private task rehearsal**. If prompted, skip initial setup and choose **Switch to Full**. Use the signed-in fixture owner account.

1. Set up the rehearsal passkey with the current rehearsal password. Enter a new title and choose **Review change**.
2. Check both titles, the workspace, task, revision and expiry. Choose **Approve with passkey** or **Decline**. You can withdraw an approval until the destination commits.
3. A verified result shows the saved title and revision. **Link to this job** reopens the same receipt in a later session. If someone has since edited the task, the job shows both the historical save and the current title.
4. **Review undo** prepares a new decision to restore the original title. It needs a fresh passkey approval. An intervening edit prevents that reversal.

## Run the browser check

Use Linux with Node, a built Mission Control checkout, an installed WEIR 0.9.0 and Fade 0.10.0 in the same Python environment, Playwright and sandboxed Chromium. The check requires a private network namespace containing only loopback and a new private directory. The full command starts the site, opens it over HTTPS, uses its normal browser controls and restarts the server. The browser registers a virtual authenticator at the dedicated rehearsal origin.

~~~sh
python scripts/verify_saved_task_rehearsal.py /var/tmp/new-weir-saved-task \
  --mission-control /path/to/built/mission-control \
  --node /path/to/node --chromium /path/to/chromium
~~~

For an operator session, the companion launcher provides `init` and `serve` with the same private directory, Mission Control checkout and Node executable. The fixture owner's username is `fixture-owner`. Initialization writes its generated password to the owner-only `login` file. Serve listens only on loopback. The owner browser needs private HTTPS at `https://saved-task.test`. The browser check supplies this origin without changing host DNS or trust settings.

## What verifies the save

Mission Control binds a fresh WebAuthn assertion to the exact displayed decision and stable owner. Its issuer signs that decision. Fade verifies it and signs a permit for the same command. WEIR checks both signatures and records its attempt before contacting the writer. The destination rechecks both signatures, the owner's current grant, the task revision and any withdrawal in its write transaction. One transaction saves the title and an owner-only receipt.

A separate site process opens the database read-only. WEIR reports success only after checking its receipt against the approved edit. If dispatch loses its response, WEIR consults that reader. It never repeats an ambiguous write. A failed witness leaves the stored decision visible, with verification unavailable.

The standalone launcher runs role-specific processes under one private development account. The task and receipts belong exclusively to the rehearsal tables. The launcher creates no jobs or credentials for a production deployment. A live destination still needs separate operating-system identities, account enrollment and delivery tests against its actual subscribers and integrations. [Saved-change policy](saved-task-change-policy.md)

The Linux browser run exercised passkey registration, save, reopen, undo, withdrawal and independent readback. It included overlapping execution requests, corrupt signatures, a lost writer response and attempts to reopen the evidence from another account. [Native acceptance results](acceptance/private-saved-task-20261122.json)
