from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import uuid

from weir.bench import load_corpus, run_benchmark, summarize
from weir.engines.base import WeirEngineError
from weir.models import DataClass, RequestMode, WebCapture, WebRequest
from weir.router import EngineRegistry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weir", description="WEIR - Web Evidence, Interaction & Retrieval")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="show reader-engine availability")

    read = sub.add_parser("read", help="read one public URL through an explicit engine")
    read.add_argument("url")
    read.add_argument("--engine", choices=["oc", "agent-browser-read", "fake"], required=True)
    read.add_argument("--run-id", default=None)

    bench = sub.add_parser("bench", help="run a task corpus through one or more engines")
    bench.add_argument("--corpus", required=True, help="path to a JSON task corpus")
    bench.add_argument("--engines", required=True, help="comma-separated engine ids")
    bench.add_argument("--out", default="benchmarks/results", help="output directory for JSONL records")
    bench.add_argument("--run-id", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    registry = EngineRegistry()

    if args.command == "engines":
        probes = [asdict(engine.probe()) for engine in registry.all()]
        print(json.dumps(probes, indent=2))
        return 0

    if args.command == "read":
        run_id = args.run_id or f"local-{uuid.uuid4().hex}"
        request = WebRequest(
            request_id=f"webreq-{uuid.uuid4().hex}",
            run_id=run_id,
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url=args.url,
            preferred_engine=args.engine,
            evidence_required=True,
            side_effects_allowed=False,
        )
        try:
            result = registry.get(args.engine).read(request)
        except (WeirEngineError, ValueError, KeyError) as exc:
            print(json.dumps({"ok": False, "engine": args.engine, "error": str(exc)}), file=sys.stderr)
            return 2
        capture = WebCapture.from_reader_result(result, request)
        print(json.dumps({"ok": True, "request": request.to_dict(), "capture": capture.to_dict()}, indent=2))
        return 0

    if args.command == "bench":
        try:
            engines = [registry.get(engine_id.strip()) for engine_id in args.engines.split(",") if engine_id.strip()]
            tasks = load_corpus(Path(args.corpus))
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
            return 2
        out_path, records = run_benchmark(engines, tasks, Path(args.out), run_id=args.run_id)
        print(json.dumps({"ok": True, "records": str(out_path), "summary": summarize(records)}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
