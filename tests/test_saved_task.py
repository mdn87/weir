from copy import deepcopy

import pytest
from weir.contract import canonical_digest
from weir.saved_task import SavedTaskError, check_receipt, check_view, workflow


def view():
    scope = {
        "deployment": "example-private-deployment",
        "tenant_id": 1,
        "workspace_id": 2,
        "actor_id": "mc:user:3",
        "command_id": "saved-" + "b" * 32,
    }
    return {
        **scope,
        "schema": "weir.saved-task-review/v1",
        "action_id": "rename-private-task-v1",
        "task_id": "rehearsal-task",
        "generation": "a" * 32,
        "revision": 1,
        "before": "Initial title",
        "after": "Revised title",
        "undo_of": None,
        "delivery": "private-task-and-owner-receipt",
        "data_class": "internal",
        "use_limit": 1,
        "issued_at": 1800000000,
        "expires_at": 1800000300,
        "work_context_hash": canonical_digest(scope),
    }


def test_source_and_readback_bind_the_exact_saved_edit():
    proposal = view()
    digest = canonical_digest(proposal)
    check_view(
        proposal,
        digest,
        owner="mc:user:3",
        deployment="example-private-deployment",
        tenant=1,
        workspace=2,
    )
    receipt = {k: proposal[k] for k in ("command_id", "generation", "before", "after")}
    receipt.update(proposal_hash=digest, revision=2, saved_at=1800000010)
    observation = {
        "receipt": receipt,
        "task": {"generation": proposal["generation"], "revision": 2, "title": "Revised title"},
    }
    assert check_receipt(proposal, observation)["current"] is True
    other = deepcopy(observation)
    other["task"]["title"] = "A different value"
    with pytest.raises(SavedTaskError):
        check_receipt(proposal, other)
    other["task"]["revision"] = 3
    assert check_receipt(proposal, other)["current"] is False
    with pytest.raises(SavedTaskError):
        check_view(
            {**proposal, "after": "Another title"},
            digest,
            owner="mc:user:3",
            deployment="example-private-deployment",
            tenant=1,
            workspace=2,
        )


@pytest.mark.parametrize(
    "text", ["e\u0301", "ends ", "\u034f", "x\ufe0fy", "x\u200dy", "x" * 501, "\ud800"]
)
def test_ambiguous_titles_cannot_be_approved(text):
    item = {**view(), "after": text}
    with pytest.raises(ValueError):
        check_view(
            item,
            canonical_digest(item),
            owner="mc:user:3",
            deployment="example-private-deployment",
            tenant=1,
            workspace=2,
        )


def test_crash_after_reserving_an_attempt_never_dispatches_again(tmp_path):
    item = view()
    digest = canonical_digest(item)
    pins = dict(owner="mc:user:3", deployment="example-private-deployment", tenant=1, workspace=2)
    (tmp_path / item["command_id"]).write_text(digest)
    ops = []

    def reader(role, args):
        ops.append(role)
        assert role == "reader" and args == {"command_id": item["command_id"]}
        return {"view": item, "proposal_hash": digest, "receipt": None, "state": "approved"}

    for operation in ("execute", "verify"):
        assert workflow(
            {"operation": operation, "command_id": item["command_id"]}, pins, reader, tmp_path
        ) == {"state": "outcome_unknown"}
    assert ops == ["reader", "reader"]
