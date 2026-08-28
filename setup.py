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
        for directory, patterns in (
            ("contracts", ("*.json", "*.sha256")),
            ("profiles", ("*.yaml", "*.yml")),
        ):
            source_root = ROOT / directory
            for pattern in patterns:
                for source in sorted(source_root.rglob(pattern)):
                    destination = package_data / directory / source.relative_to(
                        source_root
                    )
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    copy2(source, destination)


setup(cmdclass={"build_py": build_py})
