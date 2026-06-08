import os
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from src import config


def _base_raw():
    return {
        "project": {"name": "p"},
        "target": "example.com",
        "monitoring": {"health_check_url": "https://x/health"},
    }


def test_rps_bounds():
    raw = _base_raw()
    raw["project"]["rps"] = 500
    assert config.ScanConfig(**raw).project.rps == 500
    for bad in (29, 10001):
        raw["project"]["rps"] = bad
        with pytest.raises(ValidationError):
            config.ScanConfig(**raw)


def test_rps_unset_is_none():
    assert config.ScanConfig(**_base_raw()).project.rps is None


def test_resolve_env_value_prefix(monkeypatch):
    monkeypatch.setenv("RUN1__AUTH", "secret")
    assert config.resolve_env_value("env::AUTH", "RUN1__") == "secret"


def test_resolve_env_value_missing():
    with pytest.raises(ValueError):
        config.resolve_env_value("env::NOPE", "")


def test_load_config_missing_token(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: p}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
    """))
    monkeypatch.delenv("SF_TOKEN", raising=False)
    monkeypatch.setenv("SF_APP_URL", "https://api")
    with pytest.raises(ValueError):
        config.load_config(cfg, "")


def test_load_config_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        config.load_config(tmp_path / "nope.yaml", "")


def test_lifecycle_flags_default_false():
    p = config.ScanConfig(**_base_raw()).project
    assert (
        p.delete_on_completion,
        p.datetime_name_postfix,
        p.reuse_existing_project,
    ) == (False, False, False)


@pytest.mark.parametrize("conflict", ["delete_on_completion", "datetime_name_postfix"])
def test_reuse_conflicts_rejected(conflict):
    raw = _base_raw()
    raw["project"]["reuse_existing_project"] = True
    raw["project"][conflict] = True
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def test_reuse_alone_is_ok():
    raw = _base_raw()
    raw["project"]["reuse_existing_project"] = True
    assert config.ScanConfig(**raw).project.reuse_existing_project is True


def test_datetime_postfix_format_constant():
    assert config.DATETIME_POSTFIX_FORMAT == "%d %B %Y %H:%M:%S"


def test_report_schema_defaults():
    r = config.ScanConfig(**_base_raw()).report
    assert r.pdf.enabled is True
    assert r.html.enabled is False
    assert r.severity == [10, 8, 5]


def test_report_severity_validation():
    raw = _base_raw()
    raw["report"] = {"severity": [10, 99]}
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def test_report_severity_dedup_desc():
    raw = _base_raw()
    raw["report"] = {"severity": [5, 10, 5, 8]}
    assert config.ScanConfig(**raw).report.severity == [10, 8, 5]


def test_report_severity_empty_rejected():
    raw = _base_raw()
    raw["report"] = {"severity": []}
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def test_ensure_list_values_string_coerced_to_list():
    # webauth value given as a plain string -> coerced to a single-element list (150-151)
    raw = _base_raw()
    raw["webauth"] = {"Cookie": "session=abc"}
    cfg = config.ScanConfig(**raw)
    assert cfg.webauth == {"Cookie": ["session=abc"]}


def test_ensure_list_values_list_stringified():
    # list values are stringified (152-153)
    raw = _base_raw()
    raw["webauth"] = {"X-Num": [1, 2]}
    cfg = config.ScanConfig(**raw)
    assert cfg.webauth == {"X-Num": ["1", "2"]}


def test_ensure_list_values_non_str_non_list_coerced():
    # int value -> coerced via str into a single-element list (154-155)
    raw = _base_raw()
    raw["webauth"] = {"X-Num": 7}
    cfg = config.ScanConfig(**raw)
    assert cfg.webauth == {"X-Num": ["7"]}


def test_ensure_list_values_non_dict_returned_as_is():
    # non-dict webauth returned as-is (146-147) -> pydantic then rejects it
    raw = _base_raw()
    raw["webauth"] = "not-a-dict"
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def test_resolve_webauth_env_values_dict(monkeypatch):
    # resolve a dict with an env:: value (178 / 185-188)
    monkeypatch.setenv("MY_TOKEN", "secret-value")
    resolved = config.resolve_webauth_env_values(
        {"Cookie": ["env::MY_TOKEN", "static"]}, ""
    )
    assert resolved == {"Cookie": ["secret-value", "static"]}


def test_load_config_success_yaml(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: p}
        target: example.com
        webauth: {Cookie: "env::WEBAUTH_TOK"}
        monitoring: {health_check_url: "https://x/health"}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok123")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setenv("WEBAUTH_TOK", "resolved-cookie")
    config_obj, token, url = config.load_config(cfg, "")
    assert token == "tok123"
    assert url == "https://api.example.com"
    assert config_obj.project.name == "p"
    # env:: inside webauth resolved during load_config (line 214)
    assert config_obj.webauth == {"Cookie": ["resolved-cookie"]}


def test_load_config_success_json(tmp_path: Path, monkeypatch):
    import json as _json

    cfg = tmp_path / "c.json"
    cfg.write_text(
        _json.dumps(
            {
                "project": {"name": "jp"},
                "target": "example.com",
                "monitoring": {"health_check_url": "https://x/health"},
            }
        )
    )
    monkeypatch.setenv("SF_TOKEN", "tok-json")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    config_obj, token, _ = config.load_config(cfg, "")
    assert config_obj.project.name == "jp"
    assert token == "tok-json"


def test_load_config_missing_url(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: p}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.delenv("SF_APP_URL", raising=False)
    with pytest.raises(ValueError):
        config.load_config(cfg, "")
