from __future__ import annotations

import json
import logging
import os
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("scan_watcher")


class ExitCode(IntEnum):
    SUCCESS = 0
    AUTH_FAILURE = 1
    CONFIG_ERROR = 2
    API_ERROR = 3


DEFAULT_CHECK_INTERVAL_MINUTES = 5
MIN_CHECK_INTERVAL_MINUTES = 1
MAX_CHECK_INTERVAL_MINUTES = 60
MAX_RUNTIME_DAYS = 10
MAX_RUNTIME_HOURS = MAX_RUNTIME_DAYS * 24

MIN_RPS = 30
MAX_RPS = 10000

DATETIME_POSTFIX_FORMAT = "%d %B %Y %H:%M:%S"

ALLOWED_SEVERITIES = (2, 3, 5, 8, 10)
DEFAULT_SEVERITIES = [10, 8, 5]


class ProjectConfig(BaseModel):
    name: str = Field(..., min_length=1, description="Project name")
    one_time: bool = Field(default=True, description="One-time scan flag")
    priority: int = Field(default=0, ge=-1, le=3, description="Scan priority (-1 to 3)")
    scan_agent: str = Field(default="", description="Scan agent (qtag)")
    rps: int | None = Field(
        default=None,
        ge=MIN_RPS,
        le=MAX_RPS,
        description=(
            "Requests per second limit for the scan "
            f"({MIN_RPS}-{MAX_RPS}). If unset, RPS is not limited and "
            "the field is not sent to the API."
        ),
    )
    delete_on_completion: bool = Field(
        default=False,
        description="Delete the project after a successful scan (DELETE /api/projects/{id}).",
    )
    datetime_name_postfix: bool = Field(
        default=False,
        description="Append the UTC start date/time to the project name.",
    )
    reuse_existing_project: bool = Field(
        default=False,
        description="Find the project by name and reuse it (create if missing).",
    )

    @model_validator(mode="after")
    def _validate_exclusive_modes(self) -> "ProjectConfig":
        if self.reuse_existing_project and (
            self.delete_on_completion or self.datetime_name_postfix
        ):
            raise ValueError(
                "reuse_existing_project is mutually exclusive with "
                "delete_on_completion and datetime_name_postfix"
            )
        return self


class MonitoringConfig(BaseModel):
    health_check_url: str = Field(..., description="URL for health check")
    check_interval_minutes: int = Field(
        default=DEFAULT_CHECK_INTERVAL_MINUTES,
        ge=MIN_CHECK_INTERVAL_MINUTES,
        le=MAX_CHECK_INTERVAL_MINUTES,
        description="Check interval in minutes",
    )
    max_runtime_hours: float = Field(
        default=24.0,
        gt=0,
        le=MAX_RUNTIME_HOURS,
        description="Maximum runtime in hours",
    )
    health_check_allowed_http_codes: list[int] = Field(
        default=[200],
        description="HTTP status codes considered as successful health check",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify TLS certificate of the health check URL",
    )
    health_check_retries: int = Field(
        default=2,
        ge=0,
        le=20,
        description=(
            "Retries for the target health check before treating it as auth "
            "loss. Smooths transient network/TLS errors (e.g. a flapping VPN)."
        ),
    )
    health_check_retry_delay_seconds: float = Field(
        default=5.0,
        ge=0,
        le=300,
        description="Delay between health-check retries (seconds)",
    )


class ReportFormatConfig(BaseModel):
    enabled: bool = Field(default=False)
    output_path: Path = Field(default=Path("./report.out"))


class ReportConfig(BaseModel):
    language: Literal["en", "ru"] = Field(default="en")
    severity: list[int] = Field(default_factory=lambda: list(DEFAULT_SEVERITIES))
    pdf: ReportFormatConfig = Field(
        default_factory=lambda: ReportFormatConfig(
            enabled=True, output_path=Path("./report.pdf")
        )
    )
    html: ReportFormatConfig = Field(
        default_factory=lambda: ReportFormatConfig(output_path=Path("./report.html"))
    )
    alerts_json: ReportFormatConfig = Field(
        default_factory=lambda: ReportFormatConfig(output_path=Path("./alerts.json"))
    )
    alerts_grouped_json: ReportFormatConfig = Field(
        default_factory=lambda: ReportFormatConfig(
            output_path=Path("./alerts-grouped.json")
        )
    )

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("severity must not be empty")
        bad = [s for s in v if s not in ALLOWED_SEVERITIES]
        if bad:
            raise ValueError(
                f"invalid severity {bad}; allowed: {list(ALLOWED_SEVERITIES)}"
            )
        return sorted(set(v), reverse=True)


class ScanConfig(BaseModel):
    project: ProjectConfig
    target: str = Field(..., min_length=1, description="Target domain or IP to scan")
    webauth: dict[str, list[str]] = Field(
        default_factory=dict, description="Headers for target authorization"
    )
    monitoring: MonitoringConfig
    report: ReportConfig = Field(default_factory=ReportConfig)

    @field_validator("webauth", mode="before")
    @classmethod
    def ensure_list_values(cls, v: dict[str, Any]) -> dict[str, list[str]]:
        if not isinstance(v, dict):
            return v
        result = {}
        for key, value in v.items():
            if isinstance(value, str):
                result[key] = [value]
            elif isinstance(value, list):
                result[key] = [str(item) for item in value]
            else:
                result[key] = [str(value)]
        return result


def resolve_env_value(value: str, env_prefix: str = "") -> str:
    """
    Resolve environment variable if value has env:: prefix.

    Args:
        value: The value to resolve
        env_prefix: Environment variable prefix (e.g., "RUN1__")

    Examples:
        "env::AUTH_TOKEN" with prefix "RUN1__" -> os.environ["RUN1__AUTH_TOKEN"]
        "Bearer token123" -> "Bearer token123" (unchanged)
    """
    if value.startswith("env::"):
        env_name = value[5:]
        full_env_name = f"{env_prefix}{env_name}"
        env_value = os.environ.get(full_env_name)
        if env_value is not None:
            return env_value
        raise ValueError(f"Environment variable '{full_env_name}' is not set")
    return value


def resolve_webauth_env_values(
    webauth: dict[str, list[str]], env_prefix: str = ""
) -> dict[str, list[str]]:
    """Resolve all env:: prefixed values in webauth headers."""
    result = {}
    for key, values in webauth.items():
        result[key] = [resolve_env_value(v, env_prefix) for v in values]
    return result


def load_config(config_path: Path, env_prefix: str = "") -> tuple[ScanConfig, str, str]:
    """Загрузает конфиг из файла и окружения"""

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, encoding="utf-8") as f:
        if config_path.suffix.lower() in (".yaml", ".yml"):
            raw_config = yaml.safe_load(f)
        else:
            raw_config = json.load(f)

    sf_token = os.environ.get(f"{env_prefix}SF_TOKEN", "")
    sf_app_url = os.environ.get(f"{env_prefix}SF_APP_URL", "")

    if not sf_token:
        raise ValueError(f"Environment variable {env_prefix}SF_TOKEN is required")
    if not sf_app_url:
        raise ValueError(f"Environment variable {env_prefix}SF_APP_URL is required")
    if not sf_app_url.startswith(("http://", "https://")):
        raise ValueError(
            f"Environment variable {env_prefix}SF_APP_URL must start with "
            f"'http://' or 'https://' (got: {sf_app_url!r})"
        )

    config = ScanConfig(**raw_config)

    # Resolve env::
    config.webauth = resolve_webauth_env_values(config.webauth, env_prefix)

    return config, sf_token, sf_app_url
