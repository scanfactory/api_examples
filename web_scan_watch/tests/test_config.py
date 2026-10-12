import logging
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


def test_monitoring_enabled_defaults_true():
    assert config.ScanConfig(**_base_raw()).monitoring.enabled is True


def test_monitoring_disabled_allows_missing_url():
    raw = _base_raw()
    raw["monitoring"] = {"enabled": False}  # no health_check_url
    cfg = config.ScanConfig(**raw)
    assert cfg.monitoring.enabled is False
    assert cfg.monitoring.health_check_url == ""


def test_monitoring_enabled_requires_url():
    raw = _base_raw()
    raw["monitoring"] = {}  # enabled defaults True, but no health_check_url
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


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


def test_no_tasks_timeout_default_and_bounds():
    raw = _base_raw()
    # Disabled by default: old configs keep running until max_runtime_hours.
    assert config.ScanConfig(**raw).monitoring.no_tasks_timeout_minutes == 0
    raw["monitoring"]["no_tasks_timeout_minutes"] = 60
    assert config.ScanConfig(**raw).monitoring.no_tasks_timeout_minutes == 60
    raw["monitoring"]["no_tasks_timeout_minutes"] = -1
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def _targets_raw(targets):
    raw = _base_raw()
    del raw["target"]
    raw["targets"] = targets
    return raw


def test_legacy_target_maps_to_targets():
    assert config.ScanConfig(**_base_raw()).targets == ["example.com"]


def test_targets_list_keeps_order():
    raw = _targets_raw(["b.example.com", "10.0.0.5", "a.example.com"])
    assert config.ScanConfig(**raw).targets == [
        "b.example.com",
        "10.0.0.5",
        "a.example.com",
    ]


def test_target_and_targets_together_rejected():
    raw = _base_raw()
    raw["targets"] = ["a.example.com"]
    with pytest.raises(ValidationError, match="both 'target' and 'targets'"):
        config.ScanConfig(**raw)


def test_missing_target_and_targets_rejected():
    raw = _base_raw()
    del raw["target"]
    with pytest.raises(ValidationError):
        config.ScanConfig(**raw)


def test_legacy_target_mapping_does_not_mutate_input():
    raw = _base_raw()
    config.ScanConfig.model_validate(raw)
    assert raw["target"] == "example.com"
    assert "targets" not in raw


def test_targets_empty_list_rejected():
    with pytest.raises(ValidationError):
        config.ScanConfig(**_targets_raw([]))


@pytest.mark.parametrize("blank_target", ["", "   "])
def test_targets_blank_item_rejected(blank_target):
    raw = _targets_raw(["a.example.com", blank_target])
    with pytest.raises(ValidationError, match=r"targets\[1\] is empty"):
        config.ScanConfig(**raw)


def test_legacy_blank_target_rejected():
    raw = _base_raw()
    raw["target"] = "  "
    with pytest.raises(ValidationError, match=r"targets\[0\] is empty"):
        config.ScanConfig(**raw)


def test_targets_items_stripped_and_deduplicated():
    raw = _targets_raw([" a.example.com ", "10.0.0.5", "a.example.com", "10.0.0.5"])
    assert config.ScanConfig(**raw).targets == ["a.example.com", "10.0.0.5"]


@pytest.mark.parametrize(
    ("targets", "webauth", "expect_warning"),
    [
        (["a.example.com", "b.example.com"], {"Host": ["a.example.com"]}, True),
        (["a.example.com", "b.example.com"], {"host": ["a.example.com"]}, True),
        (["a.example.com"], {"Host": ["a.example.com"]}, False),
        (["a.example.com", "b.example.com"], {"Cookie": ["session=1"]}, False),
    ],
)
def test_warn_if_host_header_shared(caplog, targets, webauth, expect_warning):
    raw = _targets_raw(targets)
    raw["webauth"] = webauth
    with caplog.at_level(logging.WARNING, logger="scan_watcher"):
        config.warn_if_host_header_shared(config.ScanConfig(**raw))
    assert ("webauth header 'Host'" in caplog.text) is expect_warning


def test_load_config_warns_on_shared_host_header(tmp_path: Path, monkeypatch, caplog):
    config_path = tmp_path / "c.yaml"
    config_path.write_text(textwrap.dedent("""
        project: {name: p}
        targets: [a.example.com, b.example.com]
        webauth: {Host: a.example.com}
        monitoring: {health_check_url: "https://x/health"}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    with caplog.at_level(logging.WARNING, logger="scan_watcher"):
        config.load_config(config_path, "")
    assert "webauth header 'Host'" in caplog.text


@pytest.mark.parametrize("config_problem", ["both_target_keys", "no_target_key"])
def test_config_error_hides_webauth_secret(config_problem):
    raw = {"project": {"name": "p"}, "monitoring": {"enabled": False}}
    if config_problem == "both_target_keys":
        raw["target"] = "a.example.com"
        raw["targets"] = ["b.example.com"]
    # webauth is the last key: the tail of the input repr holds its value.
    raw["webauth"] = {"Cookie": ["session=FAKESECRET0123456789abcdef"]}
    with pytest.raises(ValidationError) as error_info:
        config.ScanConfig(**raw)
    assert "0123456789abcdef" not in str(error_info.value)


@pytest.mark.parametrize("legacy_value", [["a.example.com", "b.example.com"], None, 42])
def test_legacy_target_must_be_one_string(legacy_value):
    raw = _base_raw()
    raw["target"] = legacy_value
    with pytest.raises(ValidationError, match="'target' must be one string"):
        config.ScanConfig(**raw)


def test_targets_deduplicated_case_insensitively():
    raw = _targets_raw(["Example.com", "10.0.0.5", "example.com", "EXAMPLE.COM"])
    assert config.ScanConfig(**raw).targets == ["Example.com", "10.0.0.5"]
