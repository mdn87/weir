"""Launch the eBay connector or remote relay canary with scoped BWS secrets."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("consumer", choices=("ebay", "relay"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    manifest = ROOT / "config" / f"glas.{options.consumer}.local.json"
    if not manifest.is_file():
        parser.error(f"Create the BWS reference manifest at {manifest}")
    args = options.args[1:] if options.args[:1] == ["--"] else options.args
    if options.consumer == "ebay":
        if not args or args[0] not in ("engines", "search", "read", "enrich"):
            parser.error("The eBay consumer accepts engines, search, read, or enrich")
        command = [sys.executable, "-c", "from weir.cli import main; raise SystemExit(main())", *args]
    else:
        command = [sys.executable, str(ROOT / "scripts" / "run_remote_relay_canary.py"), *args]

    env = os.environ.copy()
    for name in (
        "BWS_ACCESS_TOKEN", "EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET",
        "WEIR_EBAY_CLIENT_ID", "WEIR_EBAY_CLIENT_SECRET", "LUGOS_EVENT_INGEST_TOKEN",
    ):
        env.pop(name, None)
    sources = [str(ROOT / "src")]
    if os.environ.get("GLAS_ROOT"):
        sources.append(str(Path(os.environ["GLAS_ROOT"]) / "src"))
    if env.get("PYTHONPATH"):
        sources.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(sources)
    glas_python = os.environ.get("GLAS_PYTHON", sys.executable)
    return subprocess.call(
        [glas_python, "-m", "glas", "run", "--manifest", str(manifest), "--", *command],
        cwd=ROOT,
        env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
