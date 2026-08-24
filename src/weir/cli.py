from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import sys
import uuid

from weir.engines.base import WeirEngineError
from weir.models import DataClass, RequestMode, WebRequest
from weir.router import EngineRegistry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="weir", description="WEIR - Web Evidence, Interaction & Retrieval")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="show reader-engine availability")

    read = sub.add_parser("read", help="read one public URL through an explicit engine")
    read.add_argument("url")
    read.add_argument("--engine", choices=["oc", "agent-browser-read"], required=True)
    read.add_argument("--run-id", default=None)
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
        print(json.dumps({"ok": True, "request": request.to_dict(), "result": result.to_dict()}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
