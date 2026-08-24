from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import uuid

from weir.bench import load_corpus, run_benchmark, summarize
from weir.engines.base import EnginePolicyBlocked, WeirEngineError
from weir.engines.http_connector import check_target_policy
from weir.models import DataClass, RequestMode, WebCapture, WebRequest
from weir.router import EngineRegistry, classify


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weir", description="WEIR - Web Evidence, Interaction & Retrieval")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="show reader-engine availability")

    read = sub.add_parser("read", help="read one public URL; --engine auto routes via the classifier")
    read.add_argument("url")
    read.add_argument("--engine", choices=["auto", "http", "oc", "agent-browser-read", "fake"], default="auto")
    read.add_argument("--run-id", default=None)

    route = sub.add_parser("route", help="show the route decision for a URL without fetching")
    route.add_argument("url")

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

    if args.command == "route":
        request = WebRequest(
            request_id=f"webreq-{uuid.uuid4().hex}",
            run_id=f"local-{uuid.uuid4().hex}",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url=args.url,
        )
        print(json.dumps({"url": args.url, "decision": classify(request).to_dict()}, indent=2))
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
            preferred_engine=None if args.engine == "auto" else args.engine,
            evidence_required=True,
            side_effects_allowed=False,
        )
        if args.engine != "fake":
            # Boundary policy: the public lane rejects private/internal targets
            # before any engine runs, instead of trusting engine-local blocking.
            try:
                check_target_policy(args.url, request.allowed_domains)
            except EnginePolicyBlocked as exc:
                print(json.dumps({"ok": False, "class": "policy_blocked", "error": str(exc)}), file=sys.stderr)
                return 2

        if args.engine == "auto":
            decision = classify(request)
            candidates = decision.engine_candidates
        else:
            decision = None
            candidates = [args.engine]

        fallbacks: list[dict[str, str]] = []
        result = None
        for engine_id in candidates:
            try:
                result = registry.get(engine_id).read(request)
                break
            except EnginePolicyBlocked as exc:
                fallbacks.append({"engine": engine_id, "error": str(exc), "class": "policy_blocked"})
                break  # a policy block must not be laundered through another engine
            except (WeirEngineError, ValueError, KeyError) as exc:
                fallbacks.append({"engine": engine_id, "error": str(exc)})
        if result is None:
            print(
                json.dumps({"ok": False, "attempts": fallbacks, "error": "all candidate engines failed"}),
                file=sys.stderr,
            )
            return 2

        capture = WebCapture.from_reader_result(result, request)
        envelope: dict = {"ok": True, "request": request.to_dict(), "capture": capture.to_dict()}
        if decision is not None:
            envelope["route"] = decision.to_dict()
        if fallbacks:
            envelope["fallbacks"] = fallbacks
        print(json.dumps(envelope, indent=2))
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
