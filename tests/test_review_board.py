import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from weir.operator_rpc import dispatch


class ReviewBoardTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        override = patch.dict(os.environ, {"WEIR_REPORT_DIR": str(self.root)})
        override.start()
        self.addCleanup(override.stop)
        self.owner = "mission-control:1:3:4"
        self.request = {"owner": self.owner, "action": "task_review", "args": {},
                        "permitted_jobs": ["dias", "marketplace", "task_review"]}

    def test_grant_is_private_to_acquisition_and_missing_authority_fails(self):
        with self.assertRaises(PermissionError):
            dispatch(self.request)
        with self.assertRaises((PermissionError, ValueError)):
            dispatch({**self.request, "args": {"review_grant": "c" * 64}})
        with self.assertRaises(PermissionError):
            dispatch({**self.request, "permitted_jobs": ["dias"], "review_grant": "a" * 64})

    def test_report_and_original_source_reopen_after_source_is_gone(self):
        from weir.review_board import ReviewObservation

        grant = "e" * 64
        observed = "2026-11-22T05:30:00Z"
        html = '<main data-weir-review-board="1" data-workspace-id="3" data-total="1"><li data-task-id="17"><span data-task-title>Seat &amp; board</span></li></main>'
        row = {"id": 17, "title": "Seat & board"}
        result = ReviewObservation("http://127.0.0.1:3230/api/lugos/review-board", observed,
                                   html, 3, 1, [row])
        with patch("weir.review_board.observe_board", return_value=result) as observer:
            report = dispatch({**self.request, "review_grant": grant})
            observer.assert_called_once_with(self.owner, grant)
        self.assertEqual(report["tasks"], [row])
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["observed_at"], observed)
        access = {**self.request, "action": "open", "args": {"report_id": report["report_id"]}}
        self.assertEqual(dispatch(access), report)
        source = dispatch({**access, "action": "source"})
        self.assertEqual(source["content"], html)
        self.assertEqual(source["captured_at"], observed)
        self.assertEqual(source["auth_scope"], "browser_profile")
        for file in self.root.rglob("*"):
            if file.is_file():
                self.assertNotIn(grant.encode(), file.read_bytes())
        with self.assertRaises(FileNotFoundError):
            dispatch({**access, "owner": "mission-control:1:3:8"})

    def test_different_workspace_or_incomplete_capture_cannot_be_archived(self):
        from weir.review_board import ReviewObservation

        for workspace, total, rows in [(9, 0, []), (3, 1, []), (3, 2, [{"id": 4, "title": "x"}] * 2)]:
            result = ReviewObservation("http://127.0.0.1:3230/api/lugos/review-board",
                                       "2026-11-22T05:30:00Z", "<main></main>", workspace, total, rows)
            with self.subTest(workspace=workspace, total=total), patch("weir.review_board.observe_board", return_value=result):
                with self.assertRaises((ValueError, OSError)):
                    dispatch({**self.request, "review_grant": "d" * 64})
        self.assertEqual(dispatch({**self.request, "action": "list"})["reports"], [])
