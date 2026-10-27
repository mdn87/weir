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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("build on the target Windows interpreter")
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
    version = f"{sys.version_info.major}{sys.version_info.minor}"
    (runtime / f"python{version}._pth").write_text(".\nDLLs\nLib\nLib/site-packages\n", encoding="utf-8")
    pins = [f"{name}=={importlib.metadata.version(name)}" for name in ("PyYAML", "cryptography")]
    subprocess.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(wheels), *pins], check=True)
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheels), str(project)], check=True)
    package = next(wheels.glob("lugos_weir-*.whl"))
    subprocess.run([sys.executable, "-m", "pip", "--python", str(runtime / "python.exe"), "install", "--no-index", "--find-links", str(wheels), str(package)], check=True)
    subprocess.run([str(runtime / "python.exe"), "-I", "-c", "import weir, yaml, cryptography, multiprocessing; print('isolated runtime imports passed')"], cwd=destination, check=True)
    entries = [{"path": str(p.relative_to(runtime)).replace("\\", "/"), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(runtime.rglob("*")) if p.is_file()]
    (destination / "runtime-manifest.json").write_text(json.dumps({"schema_version": 1, "python": sys.version, "files": entries}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"runtime": str(runtime), "files": len(entries), "dependencies": pins}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
