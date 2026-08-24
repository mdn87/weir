from __future__ import annotations

import re
import shutil
from pathlib import Path

from weir.engines.base import EngineFailure

# cmd.exe metacharacters that survive subprocess list quoting and get
# re-parsed when the target is a .cmd/.bat script (BatBadBut class).
CMD_METACHARACTERS = set('&|<>^%!"')

_SHIM_SCRIPT_PATTERN = re.compile(r'"%dp0%\\([^"]+\.js)"')


def _unwrap_npm_shim(shim_path: str) -> list[str] | None:
    """Resolve an npm .cmd shim to a direct [node, script] invocation."""
    try:
        text = Path(shim_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _SHIM_SCRIPT_PATTERN.search(text)
    if not match:
        return None
    script = (Path(shim_path).parent / match.group(1)).resolve()
    node = shutil.which("node")
    if not node or not script.is_file():
        return None
    return [node, str(script)]


def safe_argv(binary: str, args: list[str]) -> list[str]:
    """Build an argv that cannot be re-parsed by cmd.exe.

    Windows runs .cmd/.bat files through cmd.exe, which re-splits the
    command line, so an argument like an eBay URL containing "&hash=item..."
    breaks the call (or worse). npm shims are unwrapped to a direct node
    invocation; anything else with metacharacter arguments is refused
    rather than passed through unsafely.
    """
    if not binary.lower().endswith((".cmd", ".bat")):
        return [binary, *args]
    unwrapped = _unwrap_npm_shim(binary)
    if unwrapped is not None:
        return unwrapped + args
    if any(ch in CMD_METACHARACTERS for arg in args for ch in arg):
        raise EngineFailure(
            f"refusing to pass cmd metacharacters through batch shim {Path(binary).name}"
        )
    return [binary, *args]
