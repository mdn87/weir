import sys
import unittest
from pathlib import Path
from unittest.mock import patch


with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "scripts"), *sys.path]):
    from verify_linux_first_action import FieldObserver, MARKER, URL


class SnapshotSession:
    def __init__(self):
        self.frame = {"id": "main-frame", "loaderId": "first-loader", "url": URL}
        self.strings = ["INPUT", "type", "text", "aria-label", "Fixture value",
                        "data-testid", "fixture-value", URL, "main-frame", MARKER]
        self.nodes = {"nodeName": [0], "backendNodeId": [17], "attributes": [[1, 2, 3, 4, 5, 6]],
                      "inputValue": {"index": [0], "value": [-1]}}

    def send(self, method, params=None):
        if method == "Page.getFrameTree" and params is None:
            return {"frameTree": {"frame": self.frame}}
        if method != "DOMSnapshot.captureSnapshot" or params != {"computedStyles": []}:
            raise AssertionError("Observer requested an unapproved protocol method")
        return {"strings": self.strings, "documents": [
            {"documentURL": 7, "frameId": 8, "nodes": self.nodes},
        ]}


class FieldObserverTests(unittest.TestCase):
    def test_empty_sentinel_then_exact_value_from_the_same_field(self):
        cdp = SnapshotSession()
        observer = FieldObserver(cdp)
        self.assertEqual(observer.value(), "")
        cdp.nodes["inputValue"]["value"] = [9]
        self.assertEqual(observer.value(), MARKER)
        cdp.nodes["inputValue"]["value"] = [-2]
        with self.assertRaises(RuntimeError):
            observer.value()

    def test_new_loader_or_backend_node_at_same_url_invalidates_the_observation(self):
        for changed in ("loader", "node"):
            with self.subTest(changed=changed):
                cdp = SnapshotSession()
                observer = FieldObserver(cdp)
                observer.value()
                if changed == "loader":
                    cdp.frame["loaderId"] = "second-loader"
                else:
                    cdp.nodes["backendNodeId"] = [18]
                with self.assertRaisesRegex(RuntimeError, "replaced"):
                    observer.value()

    def test_different_field_and_extra_frame_are_rejected(self):
        for changed in ("label", "frame"):
            with self.subTest(changed=changed):
                cdp = SnapshotSession()
                if changed == "label":
                    cdp.strings[4] = "Another field"
                else:
                    cdp.strings[8] = "child-frame"
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    FieldObserver(cdp).value()
