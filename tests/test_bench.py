import json
import tempfile
import unittest
from pathlib import Path

from weir.bench import BenchTask, load_corpus, run_benchmark, summarize
from weir.engines import FakeReader

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks" / "tasks" / "fake-smoke.json"


class BenchTests(unittest.TestCase):
    def test_load_corpus(self):
        tasks = load_corpus(CORPUS)
        self.assertEqual([t.task_id for t in tasks], ["fake-ok", "fake-cannot-read", "fake-failure"])

    def test_run_benchmark_normalizes_outcomes(self):
        tasks = load_corpus(CORPUS)
        with tempfile.TemporaryDirectory() as tmp:
            out_path, records = run_benchmark([FakeReader()], tasks, Path(tmp), run_id="bench-test")
            lines = out_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)
        by_task = {r.task_id: r for r in records}

        ok = by_task["fake-ok"]
        self.assertEqual(ok.verdict, "success")
        self.assertTrue(ok.content_hash.startswith("sha256:"))
        self.assertIsNone(ok.failure_class)

        self.assertEqual(by_task["fake-cannot-read"].verdict, "failure")
        self.assertEqual(by_task["fake-cannot-read"].failure_class, "cannot_read")
        self.assertEqual(by_task["fake-failure"].failure_class, "engine_failure")

    def test_records_are_valid_jsonl(self):
        tasks = [BenchTask(task_id="t1", url="fake://ok/one")]
        with tempfile.TemporaryDirectory() as tmp:
            out_path, _ = run_benchmark([FakeReader()], tasks, Path(tmp), run_id="bench-jsonl")
            record = json.loads(out_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(record["engine"], "fake")
        self.assertEqual(record["run_id"], "bench-jsonl")

    def test_summarize_counts_by_engine(self):
        tasks = load_corpus(CORPUS)
        with tempfile.TemporaryDirectory() as tmp:
            _, records = run_benchmark([FakeReader()], tasks, Path(tmp))
        summary = summarize(records)
        self.assertEqual(summary["fake"]["success"], 1)
        self.assertEqual(summary["fake"]["failure"], 2)
        self.assertEqual(summary["fake"]["failure_classes"], {"cannot_read": 1, "engine_failure": 1})


if __name__ == "__main__":
    unittest.main()
