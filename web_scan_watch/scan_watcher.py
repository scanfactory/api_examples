#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from pydantic import BaseModel, Field, field_validator


DEFAULT_CHECK_INTERVAL_MINUTES = 5
MIN_CHECK_INTERVAL_MINUTES = 1
MAX_CHECK_INTERVAL_MINUTES = 60
MAX_RUNTIME_DAYS = 10
MAX_RUNTIME_HOURS = MAX_RUNTIME_DAYS * 24

FIXED_SCOPE_SETTINGS = {
    "exclude_private_ips": True,
    "ip_whitelist": [],
    "strict_mode": False,
    "manual_ip_approve": False,
}


class ExitCode(IntEnum):
    SUCCESS = 0
    AUTH_FAILURE = 1
    CONFIG_ERROR = 2
    API_ERROR = 3


logger = logging.getLogger("scan_watcher")


def setup_logging(level: str = "INFO") -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.setLevel(log_level)


class ProjectConfig(BaseModel):
    name: str = Field(..., min_length=1, description="Project name")
    one_time: bool = Field(default=True, description="One-time scan flag")
    priority: int = Field(default=0, ge=-1, le=3, description="Scan priority (-1 to 3)")


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


class ScanConfig(BaseModel):
    project: ProjectConfig
    target: str = Field(..., min_length=1, description="Target domain or IP to scan")
    webauth: dict[str, list[str]] = Field(
        default_factory=dict, description="Headers for target authorization"
    )
    monitoring: MonitoringConfig

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


class TokenInfo(BaseModel):
    raw_value: str
    is_jwt: bool = False
    expiration: datetime | None = None
    is_expired: bool = False
    hours_until_expiry: float | None = None


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None


def extract_jwt_from_value(value: str) -> str | None:
    """
    Extract JWT token from a header value.

    Handles these formats:
    - "Bearer xxx.yyy.zzz"
    - "xxx.yyy.zzz"
    - "session=xxx.yyy.zzz; other=value"
    """
    if value.lower().startswith("bearer "):
        potential_jwt = value[7:].strip()
        if len(potential_jwt.split(".")) == 3:
            return potential_jwt

    if len(value.split(".")) == 3:
        return value

    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            cookie_value = part.split("=", 1)[1]
            if len(cookie_value.split(".")) == 3:
                return cookie_value

    return None


def analyze_token(value: str) -> TokenInfo:
    """
    Analyze a token value for JWT content and expiration.

    Args:
        value: Token or header value to analyze

    Returns:
        TokenInfo with analysis results
    """
    info = TokenInfo(raw_value=value)
    jwt_token = extract_jwt_from_value(value)

    if not jwt_token:
        return info

    payload = decode_jwt_payload(jwt_token)
    if not payload:
        return info

    info.is_jwt = True

    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_timestamp = float(exp)
            info.expiration = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            delta = info.expiration - now
            info.hours_until_expiry = delta.total_seconds() / 3600
            info.is_expired = info.hours_until_expiry <= 0
        except (ValueError, OSError):
            pass

    return info


def validate_tokens(
    webauth: dict[str, list[str]],
    sf_token: str,
    max_runtime_hours: float,
    force: bool = False,
) -> bool:
    """
    Validate all tokens and check expiration against max runtime.

    Args:
        webauth: WebAuth headers configuration
        sf_token: API authentication token
        max_runtime_hours: Maximum runtime in hours
        force: Skip confirmation prompts

    Returns:
        True if validation passed and should continue, False otherwise
    """
    warnings: list[str] = []
    has_expired = False
    needs_confirmation = False

    sf_token_info = analyze_token(sf_token)
    if sf_token_info.is_jwt and sf_token_info.expiration:
        if sf_token_info.is_expired:
            logger.error("API token (SF_TOKEN) has already expired!")
            has_expired = True
        elif (
            sf_token_info.hours_until_expiry is not None
            and sf_token_info.hours_until_expiry < max_runtime_hours
        ):
            warnings.append(
                f"API token (SF_TOKEN) expires in {sf_token_info.hours_until_expiry:.1f} hours, "
                f"but max_runtime_hours is {max_runtime_hours}"
            )
            needs_confirmation = True

    # ПРОВЕРКА WEBAUTH ТОКЕНОВ, ЕСЛИ ОНИ ТАМ ЕСТЬ НА ВРЕМЯ ИХ ЖИЗНИ
    for header_name, values in webauth.items():
        for value in values:
            token_info = analyze_token(value)
            if token_info.is_jwt and token_info.expiration:
                if token_info.is_expired:
                    logger.error(f"Token in webauth.{header_name} has already expired!")
                    has_expired = True
                elif (
                    token_info.hours_until_expiry is not None
                    and token_info.hours_until_expiry < max_runtime_hours
                ):
                    warnings.append(
                        f"Token in webauth.{header_name} expires in {token_info.hours_until_expiry:.1f} hours"
                    )
                    needs_confirmation = True

    if has_expired:
        return False

    if warnings and needs_confirmation:
        print("\n" + "=" * 60)
        print("⚠️  WARNING: Token Expiration Risk")
        print("=" * 60)
        for warning in warnings:
            print(f"\n• {warning}")
        print(f"\nmax_runtime_hours is set to {max_runtime_hours} hours.")
        print("\nThis means the scanner may lose access before the scan completes.")
        print(
            "The scan will be stopped when auth check fails, but scan time will be wasted."
        )
        print("\nRecommendations:")
        print("  - Reduce max_runtime_hours to match token lifetime")
        print("  - Use longer-lived tokens")
        print("=" * 60)

        if not force:
            try:
                response = input("\nContinue anyway? [y/N]: ").strip().lower()
                if response not in ("y", "yes"):
                    logger.info("User chose not to continue due to token warnings")
                    return False
            except (EOFError, KeyboardInterrupt):
                print()
                return False

    return True


class SFAPIClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        """
        Initialize SF API client.

        Args:
            base_url: Base URL for API (e.g., https://api.example.com)
            token: Authentication token
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")

        token = re.sub(r"^[Bb]earer\s+", "", token).strip()
        self.client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    def close(self) -> None:
        self.client.close()

    @staticmethod
    def _is_ip_address(target: str) -> bool:
        import ipaddress

        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def _build_scope_settings(target: str) -> dict[str, list[str]]:
        if SFAPIClient._is_ip_address(target):
            return {"root_domains": [], "root_ips": [target]}
        return {"root_domains": [target], "root_ips": []}

    def create_project(self, config: ScanConfig) -> dict[str, Any]:
        """
        Создает новый проект в ЛК SF

        Args:
            config: Scan config

        Returns:
            Created project data

        Raises:
            httpx.HTTPStatusError: If API request fails
        """
        payload = self._build_project_payload(config)

        response = self.client.post(f"{self.base_url}/api/projects/", json=payload)
        response.raise_for_status()
        project = response.json()

        project_id = project.get("id") or project.get("_id")
        if project_id:
            response = self.client.patch(
                f"{self.base_url}/api/projects/{project_id}",
                json=payload,
            )
            response.raise_for_status()
            return response.json()

        return project

    def _build_project_payload(self, config: ScanConfig) -> dict[str, Any]:
        return {
            "name": config.project.name,
            "preset": "web",
            "one_time": config.project.one_time,
            "qtag": "",
            "scan_settings": {
                "priority": config.project.priority,
                "webauth": config.webauth,
                "time_windows": [],
            },
            "scope_settings": {
                **self._build_scope_settings(config.target),
                **FIXED_SCOPE_SETTINGS,
            },
        }

    def update_project_status(
        self, project_id: str, status: Literal["running", "paused"]
    ) -> dict[str, Any]:
        response = self.client.patch(
            f"{self.base_url}/api/projects/{project_id}",
            json={"status": status},
        )
        response.raise_for_status()
        return response.json()

    def start_project(self, project_id: str) -> dict[str, Any]:
        return self.update_project_status(project_id, "running")

    def stop_project(self, project_id: str) -> dict[str, Any]:
        return self.update_project_status(project_id, "paused")

    def get_project(self, project_id: str) -> dict[str, Any]:
        response = self.client.get(
            f"{self.base_url}/api/projects/{project_id}?task_stats=1"
        )
        response.raise_for_status()
        return response.json()


def check_authorization_health(
    health_check_url: str,
    webauth: dict[str, list[str]],
    allowed_http_codes: list[int],
    timeout: float = 30.0,
) -> bool:
    """
    Проверяет, если авторизация в целевом приложении все еще валидна
    Возвращает True если авторизация валидна и False, если нет
    """
    headers = [(name, value) for name, values in webauth.items() for value in values]

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(health_check_url, headers=headers)
            if response.status_code in allowed_http_codes:
                logger.debug(f"Health check passed: {health_check_url}")
                return True
            else:
                logger.warning(
                    f"Health check failed with status {response.status_code}: {health_check_url}"
                )
                return False
    except httpx.RequestError as e:
        logger.error(f"Health check request error: {e}")
        return False


class ScanWatcher:
    def __init__(
        self,
        api_client: SFAPIClient,
        config: ScanConfig,
        project_id: str,
    ):
        self.api_client = api_client
        self.config = config
        self.project_id = project_id
        self.start_time = datetime.now(tz=timezone.utc)
        self._shutdown_requested = False

    def request_shutdown(self) -> None:
        """Элегантный шатдаун"""
        self._shutdown_requested = True

    def _check_runtime_exceeded(self) -> bool:
        elapsed = datetime.now(tz=timezone.utc) - self.start_time
        max_runtime_seconds = self.config.monitoring.max_runtime_hours * 3600
        return elapsed.total_seconds() > max_runtime_seconds

    def _check_project_completed(self) -> bool:
        try:
            project = self.api_client.get_project(self.project_id)
            status = project.get("status", "").lower()
            if status == "paused":
                logger.info(f"Project scan completed with status: {status}")
                return True

            tasks_total = project.get("tasks_total", 0)
            tasks_finished = project.get("tasks_finished", 0)
            all_tasks_finished = project.get("all_tasks_finished", False)

            if (
                tasks_total is not None
                and tasks_finished is not None
                and tasks_total > 0
                and tasks_finished > 0
                and tasks_total == tasks_finished
                and all_tasks_finished is True
            ):
                logger.info(f"All tasks completed: {tasks_finished}/{tasks_total}")
                return True

            return False
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get project status: {e}")
            return False

    def run(self) -> ExitCode:
        check_interval_seconds = self.config.monitoring.check_interval_minutes * 60
        logger.info(
            f"Starting monitoring loop (interval: {self.config.monitoring.check_interval_minutes} min, "
            f"max runtime: {self.config.monitoring.max_runtime_hours} hours)"
        )

        while not self._shutdown_requested:
            if not check_authorization_health(
                self.config.monitoring.health_check_url,
                self.config.webauth,
                self.config.monitoring.health_check_allowed_http_codes,
            ):
                logger.error("Authorization check failed! Stopping scan.")
                try:
                    self.api_client.stop_project(self.project_id)
                    logger.info("Scan stopped successfully")
                except httpx.HTTPStatusError as e:
                    logger.error(f"Failed to stop scan: {e}")
                return ExitCode.AUTH_FAILURE

            if self.config.project.one_time and self._check_project_completed():
                logger.info("One-time scan completed successfully. Stopping project.")
                try:
                    self.api_client.stop_project(self.project_id)
                    logger.info("Project stopped successfully")
                except httpx.HTTPStatusError as e:
                    logger.error(f"Failed to stop project: {e}")
                return ExitCode.SUCCESS

            if self._check_runtime_exceeded():
                logger.info("Maximum runtime exceeded. Stopping scan.")
                try:
                    self.api_client.stop_project(self.project_id)
                except httpx.HTTPStatusError as e:
                    logger.error(f"Failed to stop scan: {e}")
                return ExitCode.SUCCESS

            logger.debug(
                f"Waiting {self.config.monitoring.check_interval_minutes} minutes until next check"
            )

            sleep_end = time.time() + check_interval_seconds
            while time.time() < sleep_end and not self._shutdown_requested:
                time.sleep(min(5, sleep_end - time.time()))

        logger.info("Shutdown requested. Stopping scan.")
        try:
            self.api_client.stop_project(self.project_id)
            logger.info("Scan stopped successfully")
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to stop scan: {e}")
        return ExitCode.SUCCESS


def load_config(config_path: Path, env_prefix: str = "") -> tuple[ScanConfig, str, str]:
    """Загрузает конфиг из файла и окружения"""

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
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

    config = ScanConfig(**raw_config)

    # Resolve env::
    config.webauth = resolve_webauth_env_values(config.webauth, env_prefix)

    return config, sf_token, sf_app_url


class Application:
    def __init__(self) -> None:
        self.shutdown_requested = False
        self.watcher: ScanWatcher | None = None

    def request_shutdown(self, signum: int) -> None:
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, initiating shutdown...")
        self.shutdown_requested = True
        if self.watcher:
            self.watcher.request_shutdown()

    def setup_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, lambda s, f: self.request_shutdown(s))
        signal.signal(signal.SIGTERM, lambda s, f: self.request_shutdown(s))

    def run(self, config_path: Path, env_prefix: str, force: bool) -> int:
        try:
            config, sf_token, sf_app_url = load_config(config_path, env_prefix)
        except FileNotFoundError as e:
            logger.error(str(e))
            return ExitCode.CONFIG_ERROR
        except (yaml.YAMLError, ValueError) as e:
            logger.error(f"Configuration error: {e}")
            return ExitCode.CONFIG_ERROR

        logger.info(f"Configuration loaded: project={config.project.name}")

        logger.info("Validating tokens...")
        if not validate_tokens(
            config.webauth,
            sf_token,
            config.monitoring.max_runtime_hours,
            force=force,
        ):
            return ExitCode.CONFIG_ERROR

        self.setup_signal_handlers()

        if self.shutdown_requested:
            return ExitCode.SUCCESS

        api_client = SFAPIClient(sf_app_url, sf_token)

        try:
            logger.info("Creating scanning project...")
            try:
                project = api_client.create_project(config)
                project_id = project.get("id") or project.get("_id")
                if not project_id:
                    logger.error("Project created but no ID returned")
                    return ExitCode.API_ERROR
                logger.info(f"Project created: {project_id}")
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"Failed to create project: {e.response.status_code} - {e.response.text}"
                )
                return ExitCode.API_ERROR

            if self.shutdown_requested:
                logger.info("Shutdown requested before starting scan")
                return ExitCode.SUCCESS

            logger.info("Starting scan...")
            try:
                api_client.start_project(project_id)
                logger.info("Scan started successfully")
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"Failed to start scan: {e.response.status_code} - {e.response.text}"
                )
                return ExitCode.API_ERROR

            self.watcher = ScanWatcher(api_client, config, project_id)
            return self.watcher.run()

        finally:
            api_client.close()


def parse_args() -> tuple[Path, str, bool, str]:
    import argparse

    parser = argparse.ArgumentParser(
        description="Web Application Scan Watcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - Success (scan completed or graceful shutdown)
  1 - Authorization failure
  2 - Configuration error
  3 - API error

Environment variables:
  {PREFIX}SF_TOKEN   - API authentication token (required)
  {PREFIX}SF_APP_URL - API base URL (required)

Example:
  %(prog)s config.yaml
  %(prog)s config.yaml --env-prefix=RUN1__
  RUN1__SF_TOKEN=xxx RUN1__SF_APP_URL=https://api.example.com %(prog)s config.yaml --env-prefix=RUN1__
        """,
    )

    parser.add_argument(
        "config",
        type=Path,
        help="Path to YAML/JSON configuration file",
    )
    parser.add_argument(
        "--env-prefix",
        default="",
        help="Environment variable prefix (e.g., RUN1__)",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Skip confirmation prompts for token warnings",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()
    return args.config, args.env_prefix, args.force, args.log_level


def main() -> int:
    try:
        config_path, env_prefix, force, log_level = parse_args()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else ExitCode.CONFIG_ERROR

    setup_logging(log_level)
    logger.info(f"Loading configuration from {config_path}")

    app = Application()
    return app.run(config_path, env_prefix, force)


if __name__ == "__main__":
    sys.exit(main())
