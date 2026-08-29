from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
SCRIPT_PATH = SCRIPT_DIR / "run_remote_relay_canary.py"


def _module():
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec = importlib.util.spec_from_file_location("weir_remote_relay_canary", SCRIPT_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPT_DIR))


def test_event_ingest_is_pinned_to_the_reviewed_lan_origin() -> None:
    module = _module()
    assert module._event_ingest_url("http://10.0.1.33:8787") == (
        "http://10.0.1.33:8787"
    )
    for value in (
        "https://10.0.1.33:8787",
        "http://10.0.1.33:8788",
        "http://127.0.0.1:8787",
        "http://10.0.1.33:8787/events",
        "http://user@10.0.1.33:8787",
    ):
        with pytest.raises(ValueError):
            module._event_ingest_url(value)


def test_disabled_canary_creates_no_state_or_network_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    run_dir = tmp_path / "run"
    report = tmp_path / "report.json"
    monkeypatch.delenv("FADE_REMOTE_RELAY_ENABLED", raising=False)
    monkeypatch.delenv("FADE_WEIR_RELAY_INGRESS_ENABLED", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--run-dir",
            str(run_dir),
            "--report",
            str(report),
        ],
    )
    with pytest.raises(SystemExit, match="requires both Fade flags"):
        module.main()
    assert not run_dir.exists()
    assert not report.exists()


def _apu_payload(now: datetime) -> dict[str, object]:
    timestamp = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "watchers": [
            {
                "watcher": "primary-agent-autonomy-loss",
                "enabled": True,
                "provider": "codex",
                "selector_mode": "strict",
                "ambiguity_count": 0,
                "background_service": False,
                "package_version": "0.9.0",
                "build_revision": "sha256:" + "a" * 64,
                "last_successful_attribution": timestamp,
                "service_heartbeat": timestamp,
            }
        ]
    }


def test_apu_watch_requires_fresh_successful_strict_attribution() -> None:
    module = _module()
    now = datetime(2026, 8, 29, 6, 0, tzinfo=timezone.utc)
    payload = _apu_payload(now)

    assert module._apu_watch_payload(payload, now=now)["selector_mode"] == "strict"

    stale = _apu_payload(now - timedelta(seconds=301))
    with pytest.raises(RuntimeError, match="unhealthy"):
        module._apu_watch_payload(stale, now=now)

    missing_attribution = _apu_payload(now)
    missing_attribution["watchers"][0]["last_successful_attribution"] = None
    with pytest.raises(RuntimeError, match="invalid"):
        module._apu_watch_payload(missing_attribution, now=now)

    ambiguous = _apu_payload(now)
    ambiguous["watchers"][0]["ambiguity_count"] = 1
    with pytest.raises(RuntimeError, match="unhealthy"):
        module._apu_watch_payload(ambiguous, now=now)

    invalid_build = _apu_payload(now)
    invalid_build["watchers"][0]["build_revision"] = "unverified"
    with pytest.raises(RuntimeError, match="unhealthy"):
        module._apu_watch_payload(invalid_build, now=now)


def test_apu_watch_path_is_pinned_in_the_activation_parser() -> None:
    module = _module()
    args = module._parser().parse_args(
        ["--run-dir", "run", "--report", "report.json"]
    )

    assert args.apu_watch == Path(r"C:\Users\Matt\.local\bin\apu-watch.exe")


def test_failure_state_never_requeries_a_possibly_broken_browser() -> None:
    module = _module()

    assert module._failure_event_state(None).value == "blocked"
    assert module._failure_event_state(SimpleNamespace(apply_calls=0)).value == "blocked"
    assert (
        module._failure_event_state(SimpleNamespace(apply_calls=1)).value
        == "outcome_unknown"
    )
