import sys
from pathlib import Path

import scan_watcher
from src.config import ExitCode


def test_setup_logging_runs():
    # Should not raise; configures the module logger.
    scan_watcher.setup_logging("DEBUG")


def test_setup_logging_unknown_level_defaults():
    scan_watcher.setup_logging("NOPE")


def test_parse_args(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "cfg.yaml", "--force"])
    config_path, env_prefix, force, log_level = scan_watcher.parse_args()
    assert config_path == Path("cfg.yaml")
    assert env_prefix == ""
    assert force is True
    assert log_level == "INFO"


def test_parse_args_env_prefix_and_log_level(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["prog", "cfg.yaml", "--env-prefix=RUN1__", "--log-level=DEBUG"]
    )
    config_path, env_prefix, force, log_level = scan_watcher.parse_args()
    assert env_prefix == "RUN1__"
    assert force is False
    assert log_level == "DEBUG"


def test_main_returns_zero(monkeypatch):
    monkeypatch.setattr(
        scan_watcher, "parse_args", lambda: (Path("cfg.yaml"), "", True, "INFO")
    )
    monkeypatch.setattr(scan_watcher, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_watcher.Application, "run", lambda self, *a, **k: ExitCode.SUCCESS
    )
    assert scan_watcher.main() == 0


def test_main_handles_systemexit(monkeypatch):
    def raise_exit():
        raise SystemExit(2)

    monkeypatch.setattr(scan_watcher, "parse_args", raise_exit)
    monkeypatch.setattr(scan_watcher, "setup_logging", lambda *a, **k: None)
    assert scan_watcher.main() == 2
