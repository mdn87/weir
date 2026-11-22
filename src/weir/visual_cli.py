"""Operator commands for interpreting and reopening retained evidence."""

import json
import os
import sqlite3
import sys
from pathlib import Path

from weir.browser.store import SQLiteSessionStore
from weir.engines.base import WeirEngineError
from weir.persistence import CaptureStore
from weir.visual import Region, ValueQuery
from weir.visual_evidence import VisualReadings


def add_visual_parser(subparsers) -> None:
    visual = subparsers.add_parser(
        "visual", help="read a labelled value from retained browser evidence"
    )
    commands = visual.add_subparsers(dest="visual_command", required=True)
    read = commands.add_parser("read", help="use accessible text or a selected screenshot region")
    read.add_argument("--capture", required=True, help="browser observation capture ID")
    read.add_argument("--label", required=True, help="visible label preceding the count or state")
    read.add_argument(
        "--choice", action="append", default=[], help="permitted text state, repeatable"
    )
    read.add_argument(
        "--region",
        type=int,
        nargs=4,
        metavar=("X", "Y", "WIDTH", "HEIGHT"),
        help="rectangle in the original screenshot, measured in pixels from the top left",
    )
    show = commands.add_parser(
        "show", help="verify a past reading against its original observation"
    )
    show.add_argument("--reading", required=True, help="visual reading ID")
    show.add_argument("--export-crop", type=Path, help="write the verified crop to a new PNG file")
    for command in (read, show):
        command.add_argument(
            "--store",
            type=Path,
            default=os.environ.get("WEIR_STATE_DIR"),
            help="capture store directory",
        )
        command.add_argument(
            "--sessions", type=Path, required=True, help="existing browser session ledger"
        )


def execute_visual(args, get_profiles) -> int:
    try:
        if not args.store:
            raise ValueError("supply --store or set WEIR_STATE_DIR to the retained capture store")
        with SQLiteSessionStore(
            args.sessions, existing=True, read_only=args.visual_command == "show"
        ) as ledger:
            readings = VisualReadings(ledger, CaptureStore(Path(args.store)), get_profiles())
            if args.visual_command == "show":
                result = readings.show(args.reading, args.export_crop)
            else:
                region = Region(*args.region) if args.region is not None else None
                result = readings.read(
                    args.capture, ValueQuery(args.label, tuple(args.choice)), region
                )
        print(json.dumps(result, indent=2))
        if result["status"] == "reader_unavailable":
            print(
                "Check the local Aire installation, OCR language and model files.",
                file=sys.stderr,
            )
        return 0 if result["status"] == "answered" else 3
    except ImportError as exc:
        print(f"Visual reading requires the visual extra: {exc}", file=sys.stderr)
    except (sqlite3.Error, OSError, KeyError, TypeError, ValueError, WeirEngineError) as exc:
        print(f"Visual reading failed: {exc}", file=sys.stderr)
    return 2
