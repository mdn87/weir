from __future__ import annotations

from pathlib import Path
from shutil import copy2

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ROOT = Path(__file__).parent


class build_py(_build_py):
    """Copy public contracts and default profiles into the installed package."""

    def run(self) -> None:
        super().run()
        package_data = Path(self.build_lib) / "weir" / "data"
        for directory, pattern in (("contracts", "*.json"), ("profiles", "*.y*ml")):
            destination = package_data / directory
            destination.mkdir(parents=True, exist_ok=True)
            for source in sorted((ROOT / directory).glob(pattern)):
                copy2(source, destination / source.name)


setup(cmdclass={"build_py": build_py})
