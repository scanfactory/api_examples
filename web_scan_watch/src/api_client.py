from __future__ import annotations

import logging
import re
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import httpx

from src.config import ScanConfig

logger = logging.getLogger("scan_watcher")


class AmbiguousProjectError(Exception):
    """More than one project matched a name lookup."""


FIXED_SCOPE_SETTINGS = {
    "exclude_private_ips": True,
    "ip_whitelist": [],
    "strict_mode": False,
    "manual_ip_approve": False,
}


class TaskStatus(IntEnum):
    HIDDEN = 0
    PAUSED = 10
    READY = 100
    PUBLISHED = 110
    WORKING = 120
    FINISHED = 130
    FAILED = 140


ACTIVE_TASK_STATUSES = {
    TaskStatus.READY,
    TaskStatus.PUBLISHED,
    TaskStatus.WORKING,
}
TERMINAL_TASK_STATUSES = {TaskStatus.FINISHED, TaskStatus.FAILED}

ALERTS_LIMIT = 1000
ALERTS_SORT = "-status,-ai_risk,-severity,-last_seen"


class SFAPIClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ):
        """
        Initialize SF API client.

        Args:
            base_url: Base URL for API (e.g., https://api.example.com)
            token: Authentication token
            timeout: Request timeout in seconds
            transport: Optional httpx transport (for testing/mocking)
        """
        self.base_url = base_url.rstrip("/")
        token = re.sub(r"^[Bb]earer\s+", "", token).strip()
        self.client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
            transport=transport,
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
        scan_settings: dict[str, Any] = {
            "priority": config.project.priority,
            "qtag": config.project.scan_agent,
            "webauth": config.webauth,
            "time_windows": [],
        }
        # RPS is optional: send it only when explicitly configured.
        if config.project.rps is not None:
            scan_settings["rps"] = config.project.rps

        return {
            "name": config.project.name,
            "preset": "web",
            "one_time": config.project.one_time,
            "scan_settings": scan_settings,
            "scope_settings": {
                **self._build_scope_settings(config.target),
                **FIXED_SCOPE_SETTINGS,
            },
        }

    def patch_project_settings(
        self, project_id: str, config: ScanConfig
    ) -> dict[str, Any]:
        # Used only when reusing an existing project: refresh scan_settings/scope
        # AND set status=running so a paused/finished project is un-paused before
        # the rescan
        payload = self._build_project_payload(config)
        payload["status"] = "running"
        response = self.client.patch(
            f"{self.base_url}/api/projects/{project_id}", json=payload
        )
        response.raise_for_status()
        return response.json()

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

    def rescan_project(self, project_id: str) -> None:
        """Trigger a new scan on an existing project (POST .../rescan -> 204)."""
        response = self.client.post(f"{self.base_url}/api/projects/{project_id}/rescan")
        response.raise_for_status()

    def get_project(self, project_id: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/projects/{project_id}?task_stats=1"
        logger.debug(f"GET {url}")
        response = self.client.get(url)
        response.raise_for_status()
        return response.json()

    def list_project_tasks(self, project_id: str) -> list[dict[str, Any]]:
        """
        Возвращает все задачи (tasks) проекта (без пагинации).
        """
        url = f"{self.base_url}/api/tasks/"
        params = {"project_id": project_id, "all": "true"}
        logger.debug(f"GET {url} params={params}")
        response = self.client.get(url, params=params)
        response.raise_for_status()
        return response.json().get("items", [])

    def list_projects(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/api/projects/"
        response = self.client.get(url, params={"all": "true"})
        response.raise_for_status()
        data = response.json()
        return data.get("items", data if isinstance(data, list) else [])

    def find_project_by_name(self, name: str) -> dict[str, Any] | None:
        matches = [p for p in self.list_projects() if p.get("name") == name]
        if len(matches) > 1:
            raise AmbiguousProjectError(
                f"{len(matches)} projects named {name!r}; expected at most one"
            )
        return matches[0] if matches else None

    def delete_project(self, project_id: str) -> None:
        response = self.client.delete(f"{self.base_url}/api/projects/{project_id}")
        response.raise_for_status()

    def download_report(
        self,
        project_id: str,
        output_path: Path,
        fmt: Literal["pdf", "html"],
        from_ts: int,
        severity: list[int],
        language: str = "en",
    ) -> None:
        accept = "application/pdf" if fmt == "pdf" else "text/html"
        url = f"{self.base_url}/api/projects/{project_id}/report"
        headers = {"Accept": accept, "Accept-Language": language}
        params = [("from", from_ts)] + [("severity", s) for s in severity]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.client.stream("GET", url, params=params, headers=headers) as response:
            response.raise_for_status()
            with open(output_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)

    def get_alerts(
        self,
        project_id: str,
        gt_last_seen: int,
        lt_last_seen: int,
        severity: list[int],
        grouped: bool,
    ) -> Any:
        url = f"{self.base_url}/api/alerts/"
        params = [
            ("limit", ALERTS_LIMIT),
            ("sort", ALERTS_SORT),
            ("grouped", "true" if grouped else "false"),
            ("$gt-last_seen", gt_last_seen),
            ("$lt-last_seen", lt_last_seen),
            ("active", 1),
            ("masked", 0),
            ("project_id", project_id),
        ] + [("severity", s) for s in severity]
        response = self.client.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        if isinstance(items, list) and len(items) >= ALERTS_LIMIT:
            logger.warning(
                "Alerts response hit the limit of %s — results may be truncated",
                ALERTS_LIMIT,
            )
        return data


def check_authorization_health(
    health_check_url: str,
    webauth: dict[str, list[str]],
    allowed_http_codes: list[int],
    timeout: float = 30.0,
    verify_ssl: bool = True,
) -> bool:
    """
    Проверяет, если авторизация в целевом приложении все еще валидна
    Возвращает True если авторизация валидна и False, если нет
    """
    headers = [(name, value) for name, values in webauth.items() for value in values]

    try:
        with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
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
