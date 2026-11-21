"""Build a project-local isolated Windows runtime; never changes the base Python."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def configure_appcontainer_pipes(runtime: Path) -> None:
    """Use the Windows AppContainer pipe namespace in the copied browser runtime."""
    module = runtime / "Lib" / "asyncio" / "windows_utils.py"
    source = module.read_bytes()
    prefix = rb"prefix=r'\\.\pipe\python-pipe-"
    local = rb"prefix=r'\\.\pipe\LOCAL\python-pipe-"
    if source.count(local) == 1 and prefix not in source:
        return
    if source.count(prefix) != 1 or local in source:
        raise ValueError("Unrecognized asyncio pipe prefix in the copied Windows runtime")
    module.write_bytes(source.replace(prefix, local, 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--browser-proof", action="store_true",
                        help="bundle Playwright and its matching Chromium headless shell for the fixed-field diagnostic")
    parser.add_argument("--browser-node-dir", type=Path,
                        help="use node.exe and LICENSE from this Node distribution in the browser proof runtime")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("build on the target Windows interpreter")
    if args.browser_node_dir and (not args.browser_proof or not all(
        (args.browser_node_dir / name).is_file() for name in ("node.exe", "LICENSE")
    )):
        parser.error("--browser-node-dir requires --browser-proof and a directory containing node.exe and LICENSE")
    project = Path(__file__).resolve().parents[1]
    destination = args.output.resolve()
    if not destination.is_relative_to(project) or destination.exists():
        parser.error("output must be a new directory inside the repository")
    runtime, wheels = destination / "runtime", destination / "wheels"
    runtime.mkdir(parents=True)
    wheels.mkdir()
    base = Path(sys.base_prefix)
    for pattern in ("python.exe", "python*.dll", "vcruntime*.dll", "LICENSE.txt"):
        for path in base.glob(pattern):
            shutil.copy2(path, runtime / path.name)
    for directory in ("DLLs", "Lib"):
        shutil.copytree(base / directory, runtime / directory, ignore=shutil.ignore_patterns("site-packages", "__pycache__", "*.pyc"))
    if args.browser_proof:
        configure_appcontainer_pipes(runtime)
    version = f"{sys.version_info.major}{sys.version_info.minor}"
    (runtime / f"python{version}._pth").write_text(".\nDLLs\nLib\nLib/site-packages\n", encoding="utf-8")
    dependencies = ["PyYAML", "cryptography"]
    pins = [f"{name}=={importlib.metadata.version(name)}" for name in dependencies]
    if args.browser_proof:
        # Chromium 159 passed the offline field read under the Windows Job limits.
        pins.append("playwright==1.65.2")
    subprocess.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(wheels), *pins], check=True)
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheels), str(project)], check=True)
    package = next(wheels.glob("lugos_weir-*.whl"))
    python = str(runtime / "python.exe")
    requirement = str(package) + ("[browser]" if args.browser_proof else "")
    subprocess.run([sys.executable, "-m", "pip", "--python", python, "install", "--no-index", "--find-links", str(wheels), requirement], check=True)
    subprocess.run([python, "-I", "-B", "-c", "import weir, yaml, cryptography, multiprocessing; print('isolated runtime imports passed')"], cwd=destination, check=True)
    if args.browser_proof:
        driver = runtime / "Lib" / "site-packages" / "playwright" / "driver"
        if args.browser_node_dir:
            shutil.copy2(args.browser_node_dir / "node.exe", driver / "node.exe")
            shutil.copy2(args.browser_node_dir / "LICENSE", driver / "NODE-LICENSE.txt")
        env = {**os.environ, "PLAYWRIGHT_BROWSERS_PATH": "0"}
        env["PLAYWRIGHT_NODEJS_PATH"] = str(driver / "node.exe")
        subprocess.run([python, "-I", "-B", "-m", "playwright", "install", "--only-shell", "chromium"],
                       cwd=destination, env=env, check=True)
        subprocess.run([python, "-I", "-B", "-m", "weir.windows_browser_probe", "--desktop-control"],
                       cwd=destination, env=env, check=True)
    entries = [{"path": str(p.relative_to(runtime)).replace("\\", "/"), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(runtime.rglob("*")) if p.is_file()]
    (destination / "runtime-manifest.json").write_text(json.dumps({"schema_version": 1, "python": sys.version, "files": entries}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"runtime": str(runtime), "files": len(entries), "dependencies": pins}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
