#!/usr/bin/python3
"""Source-checkout launcher used by the original isolated rehearsal."""

from pathlib import Path
from runpy import run_path

if __name__ == "__main__":
    run_path(str(Path(__file__).resolve().parents[1] / "src/weir/linux_field/launcher.py"), run_name="__main__")
