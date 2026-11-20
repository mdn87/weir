"""The privileged installer has a fixed GLAS command and ignores parent secrets."""

import importlib.util
from pathlib import Path


def test_windows_installer_launch_uses_glas_and_discards_parent_tokens(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "with_glas.py"
    spec = importlib.util.spec_from_file_location("weir_with_glas", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = tmp_path / "config" / "glas.windows-install.local.json"
    manifest.parent.mkdir()
    manifest.write_text("{}")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "WINDOWS", True)
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "untrusted-parent-token")
    monkeypatch.setenv("WEIR_LUGOS_MCP_CALLER_TOKEN", "untrusted-parent-caller")
    monkeypatch.setenv("WEIR_FADE_WEIR_AUTHORITY_CALLER_TOKEN", "untrusted-parent-caller-2")
    observed = {}

    def capture(command, *, cwd, env):
        observed.update(command=command, cwd=cwd, env=env)
        return 0

    monkeypatch.setattr(module.subprocess, "call", capture)
    assert module.main(["windows-install", "--", "-Mode", "Apply"]) == 0
    command = observed["command"]
    assert command[1:5] == ["-m", "glas", "run", "--manifest"]
    assert command[5] == str(manifest)
    assert command[6:10] == ["--", "pwsh", "-NoProfile", "-File"]
    assert command[-2:] == ["-Mode", "Apply"]
    for name in (
        "BWS_ACCESS_TOKEN",
        "WEIR_LUGOS_MCP_CALLER_TOKEN",
        "WEIR_FADE_WEIR_AUTHORITY_CALLER_TOKEN",
    ):
        assert name not in observed["env"]
