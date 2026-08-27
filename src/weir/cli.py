from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from weir.bench import load_corpus, run_benchmark, summarize
from weir.broker import AcquisitionBroker, AcquisitionFailed
from weir.browser.agent_browser_observer import AgentBrowserObserverWorker
from weir.browser.playwright_observer import PlaywrightObserverWorker
from weir.engines.base import FailureClass, WeirEngineError
from weir.engines.ebay_connector import is_ebay_item_url
from weir.models import DataClass, RequestMode, WebRequest
from weir.persistence import CaptureStore, FileCaptureCache
from weir.profiles import SiteProfileRegistry
from weir.router import EngineRegistry, RouteDecision, classify
from weir.telemetry import JsonlTraceSink


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _json_object(value: str) -> dict:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("constraints must be a JSON object")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="weir", description="WEIR - Web Evidence, Interaction & Retrieval"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="show reader-engine availability")
    sub.add_parser(
        "browser-engines", help="show contained browser-worker availability and capabilities"
    )

    read = sub.add_parser(
        "read", help="read one public URL; --engine auto routes via the classifier"
    )
    read.add_argument("url")
    read.add_argument(
        "--engine",
        choices=["auto", "http", "ebay", "oc", "agent-browser-read", "fake"],
        default="auto",
    )
    read.add_argument("--run-id", default=None)

    route = sub.add_parser("route", help="show the route decision for a URL without fetching")
    route.add_argument("url")

    search = sub.add_parser(
        "search", help="structured marketplace search through a source connector"
    )
    search.add_argument("query")
    search.add_argument("--source", default="ebay")
    search.add_argument(
        "--pages", type=_positive_int, default=1, help="maximum result pages to fetch"
    )
    search.add_argument(
        "--constraints",
        type=_json_object,
        default={},
        help="opaque intent constraints as a JSON object",
    )
    search.add_argument("--run-id", default=None)

    enrich = sub.add_parser(
        "enrich", help="rung-2 page enrichment for a listing URL (compact reader chain)"
    )
    enrich.add_argument("url")
    enrich.add_argument("--run-id", default=None)

    bench = sub.add_parser("bench", help="run a task corpus through one or more engines")
    bench.add_argument("--corpus", required=True, help="path to a JSON task corpus")
    bench.add_argument("--engines", required=True, help="comma-separated engine ids")
    bench.add_argument(
        "--out", default="benchmarks/results", help="output directory for JSONL records"
    )
    bench.add_argument("--run-id", default=None)
    return parser


def _profile_registry() -> SiteProfileRegistry:
    configured = os.environ.get("WEIR_PROFILE_DIR")
    if configured:
        directory = Path(configured)
        if not directory.is_dir():
            raise ValueError(f"WEIR_PROFILE_DIR is not a directory: {directory}")
        return SiteProfileRegistry.from_directory(directory)
    packaged = files("weir").joinpath("data", "profiles")
    if packaged.is_dir():
        return SiteProfileRegistry.from_resource_directory(packaged)
    # Source checkouts keep the canonical files at repository root; wheels copy
    # the same files under weir/data during build.
    source_profiles = Path(__file__).resolve().parents[2] / "profiles"
    if source_profiles.is_dir():
        return SiteProfileRegistry.from_directory(source_profiles)
    raise ValueError(
        "WEIR has no packaged site profiles; configure an explicit WEIR_PROFILE_DIR"
    )


def _broker(registry: EngineRegistry, allow_test_engine: bool = False) -> AcquisitionBroker:
    state_value = os.environ.get("WEIR_STATE_DIR")
    state_dir = Path(state_value) if state_value else None
    trace_value = os.environ.get("WEIR_TRACE_FILE")
    return AcquisitionBroker(
        registry=registry,
        profiles=_profile_registry(),
        store=CaptureStore(state_dir) if state_dir else None,
        cache=FileCaptureCache(state_dir / "cache") if state_dir else None,
        trace_sink=JsonlTraceSink(Path(trace_value)) if trace_value else None,
        allow_test_engine=allow_test_engine,
    )


def _error_envelope(exc: Exception) -> dict:
    if isinstance(exc, AcquisitionFailed):
        return exc.to_envelope()
    if isinstance(exc, WeirEngineError):
        return {"ok": False, "class": exc.failure_class.value, "error": str(exc)}
    return {"ok": False, "class": FailureClass.UNKNOWN.value, "error": str(exc)}


def _print_error(exc: Exception) -> int:
    print(json.dumps(_error_envelope(exc)), file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    registry = EngineRegistry()

    if args.command == "engines":
        probes = [asdict(engine.probe()) for engine in registry.all()]
        print(json.dumps(probes, indent=2))
        return 0

    if args.command == "browser-engines":
        workers = [AgentBrowserObserverWorker(), PlaywrightObserverWorker()]
        probes = []
        try:
            for worker in workers:
                probe = asdict(worker.probe())
                probe["worker_id"] = worker.descriptor.worker_id
                probe["capabilities"] = sorted(
                    capability.value for capability in worker.descriptor.capabilities
                )
                probes.append(probe)
        finally:
            for worker in workers:
                shutdown = getattr(worker, "shutdown", None)
                if shutdown is not None:
                    shutdown()
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
        try:
            decision = classify(request)
            candidates, profile = _profile_registry().apply(
                request, list(decision.engine_candidates)
            )
            decision = RouteDecision(decision.route_class, candidates, decision.reasons)
        except (WeirEngineError, ValueError, OSError) as exc:
            return _print_error(exc)
        envelope = {"url": args.url, "decision": decision.to_dict()}
        if profile is not None:
            envelope["site_profile"] = profile.id
        print(json.dumps(envelope, indent=2))
        return 0

    if args.command == "search":
        source = args.source.lower()
        request = WebRequest(
            request_id=f"webreq-{uuid.uuid4().hex}",
            run_id=args.run_id or f"local-{uuid.uuid4().hex}",
            mode=RequestMode.SEARCH,
            data_class=DataClass.PUBLIC,
            auth_context="app",
            query=args.query,
            source=source,
            constraints=args.constraints,
            profile_id=f"{source}-app",
            maximum_depth=max(args.pages - 1, 0),
            evidence_required=True,
            side_effects_allowed=False,
        )
        try:
            result = _broker(registry).search(request)
        except (AcquisitionFailed, WeirEngineError, ValueError, OSError) as exc:
            return _print_error(exc)
        print(json.dumps(result.to_envelope(), indent=2))
        return 0

    if args.command == "enrich":
        request = WebRequest(
            request_id=f"webreq-{uuid.uuid4().hex}",
            run_id=args.run_id or f"local-{uuid.uuid4().hex}",
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="none",
            url=args.url,
            evidence_required=True,
            side_effects_allowed=False,
        )
        try:
            result = _broker(registry).enrich(request)
        except (AcquisitionFailed, WeirEngineError, ValueError, OSError) as exc:
            return _print_error(exc)
        envelope = result.to_envelope()
        envelope["enrichment"] = "page"
        print(json.dumps(envelope, indent=2))
        return 0

    if args.command == "read":
        run_id = args.run_id or f"local-{uuid.uuid4().hex}"
        use_ebay_profile = args.engine == "ebay" or (
            args.engine == "auto" and is_ebay_item_url(args.url)
        )
        request = WebRequest(
            request_id=f"webreq-{uuid.uuid4().hex}",
            run_id=run_id,
            mode=RequestMode.READ,
            data_class=DataClass.PUBLIC,
            auth_context="app" if use_ebay_profile else "none",
            url=args.url,
            profile_id="ebay-app" if use_ebay_profile else None,
            preferred_engine=None if args.engine == "auto" else args.engine,
            evidence_required=True,
            side_effects_allowed=False,
        )
        try:
            result = _broker(registry, allow_test_engine=args.engine == "fake").read(
                request, args.engine
            )
        except (AcquisitionFailed, WeirEngineError, ValueError, OSError) as exc:
            return _print_error(exc)
        print(json.dumps(result.to_envelope(), indent=2))
        return 0

    if args.command == "bench":
        try:
            engines = [
                registry.get(engine_id.strip())
                for engine_id in args.engines.split(",")
                if engine_id.strip()
            ]
            tasks = load_corpus(Path(args.corpus))
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
            return 2
        out_path, records = run_benchmark(engines, tasks, Path(args.out), run_id=args.run_id)
        print(
            json.dumps(
                {"ok": True, "records": str(out_path), "summary": summarize(records)}, indent=2
            )
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
