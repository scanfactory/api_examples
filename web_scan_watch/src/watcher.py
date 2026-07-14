from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import httpx

from src.api_client import (
    ACTIVE_TASK_STATUSES,
    TERMINAL_TASK_STATUSES,
    SFAPIClient,
    check_authorization_health,
)
from src.config import ExitCode, ScanConfig

logger = logging.getLogger("scan_watcher")


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
        self.should_download_report = True
        # Reuse mode: number of tasks the (reused) project already had when this
        # run started, and whether new tasks from the rescan have appeared yet.
        self._baseline_task_count = 0
        self._new_tasks_seen = False

    def request_shutdown(self) -> None:
        """Элегантный шатдаун"""
        self._shutdown_requested = True

    def _check_runtime_exceeded(self) -> bool:
        elapsed = datetime.now(tz=timezone.utc) - self.start_time
        max_runtime_seconds = self.config.monitoring.max_runtime_hours * 3600
        return elapsed.total_seconds() > max_runtime_seconds

    def _interruptible_sleep(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end and not self._shutdown_requested:
            time.sleep(min(1.0, end - time.time()))

    def _auth_check_passed(self) -> bool:
        """Target health check with retries for transient failures.

        `check_authorization_health` logs the concrete error (e.g. a TLS
        handshake timeout from a flapping VPN) on every failed attempt. We retry
        up to `health_check_retries` times so a transient network blip does not
        kill the whole scan; only a persistent failure is treated as auth loss.

        When `monitoring.enabled` is false the check is skipped entirely (no
        request is made) and auth is always considered valid.
        """
        if not self.config.monitoring.enabled:
            return True

        attempts = self.config.monitoring.health_check_retries + 1
        delay = self.config.monitoring.health_check_retry_delay_seconds
        for i in range(1, attempts + 1):
            if self._shutdown_requested:
                break
            if check_authorization_health(
                self.config.monitoring.health_check_url,
                self.config.webauth,
                self.config.monitoring.health_check_allowed_http_codes,
                verify_ssl=self.config.monitoring.verify_ssl,
            ):
                if i > 1:
                    logger.info("Health check recovered on attempt %d/%d", i, attempts)
                return True
            if i < attempts and not self._shutdown_requested:
                logger.warning(
                    "Health check failed (attempt %d/%d) — retrying in %.0fs",
                    i,
                    attempts,
                    delay,
                )
                self._interruptible_sleep(delay)
        if not self._shutdown_requested:
            logger.error(
                "Health check still failing after %d attempt(s) — treating as "
                "authorization loss.",
                attempts,
            )
        return False

    def _check_project_completed(self) -> bool:
        # Reuse mode needs special handling: the reused project already carries
        # finished tasks from previous scans, so we must wait for the rescan to
        # create NEW tasks before declaring completion.
        if self.config.project.reuse_existing_project:
            return self._check_completed_reuse()
        return self._check_completed_default()

    def _check_completed_default(self) -> bool:
        try:
            project = self.api_client.get_project(self.project_id)
            status = project.get("status", "").lower()
            if status == "paused":
                logger.info(f"Project scan completed with status: {status}")
                return True
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to get project status: "
                f"{e.response.status_code} on {e.request.url} - {e.response.text}"
            )
            return False

        try:
            tasks = self.api_client.list_project_tasks(self.project_id)
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to list project tasks: "
                f"{e.response.status_code} on {e.request.url} - {e.response.text}"
            )
            return False

        total = len(tasks)
        if total == 0:
            logger.debug("No tasks returned for project yet")
            return False

        active = sum(1 for t in tasks if t.get("status") in ACTIVE_TASK_STATUSES)
        terminal = sum(1 for t in tasks if t.get("status") in TERMINAL_TASK_STATUSES)

        logger.debug(
            f"Task progress: total={total}, active={active}, "
            f"finished+failed={terminal}"
        )

        if active == 0 and terminal > 0:
            logger.info(f"All tasks completed: {terminal}/{total}")
            return True

        return False

    def _check_completed_reuse(self) -> bool:
        """Completion detection for reuse mode (project restarted via /rescan).

        A reused project already has finished tasks from earlier scans, so we
        must NOT declare completion off those. We wait until the rescan produces
        NEW tasks (task count grows past the baseline captured at run start):

        - while no new tasks have appeared: warn every cycle and keep monitoring
          (the run only ends on max_runtime / shutdown / auth failure);
        - once new tasks have appeared: stop warning and apply the normal
          "all tasks terminal, none active" rule to finish the scan.
        """
        try:
            tasks = self.api_client.list_project_tasks(self.project_id)
        except httpx.HTTPStatusError as e:
            logger.error(
                f"Failed to list project tasks: "
                f"{e.response.status_code} on {e.request.url} - {e.response.text}"
            )
            return False

        total = len(tasks)
        if not self._new_tasks_seen:
            if total > self._baseline_task_count:
                self._new_tasks_seen = True
                logger.info(
                    "Rescan created new tasks: %d (baseline was %d)",
                    total,
                    self._baseline_task_count,
                )
            else:
                logger.warning(
                    "New tasks have NOT been created since the new scan started "
                    "(tasks=%d, baseline=%d) — continuing to monitor until "
                    "max_runtime",
                    total,
                    self._baseline_task_count,
                )
                return False

        active = sum(1 for t in tasks if t.get("status") in ACTIVE_TASK_STATUSES)
        terminal = sum(1 for t in tasks if t.get("status") in TERMINAL_TASK_STATUSES)

        logger.debug(
            f"Task progress (reuse): total={total}, active={active}, "
            f"finished+failed={terminal}"
        )

        if active == 0 and terminal > 0:
            logger.info(f"All (new) tasks completed: {terminal}/{total}")
            return True

        return False

    def run(self) -> ExitCode:
        check_interval_seconds = self.config.monitoring.check_interval_minutes * 60
        logger.info(
            f"Starting monitoring loop (interval: {self.config.monitoring.check_interval_minutes} min, "
            f"max runtime: {self.config.monitoring.max_runtime_hours} hours)"
        )
        if not self.config.monitoring.enabled:
            logger.info(
                "Target authorization health check is DISABLED "
                "(monitoring.enabled=false)"
            )
        elif not self.config.monitoring.verify_ssl:
            logger.warning(
                "TLS certificate verification for health check is DISABLED "
                "(monitoring.verify_ssl=false)"
            )

        if self.config.project.reuse_existing_project:
            try:
                self._baseline_task_count = len(
                    self.api_client.list_project_tasks(self.project_id)
                )
            except httpx.HTTPStatusError:
                self._baseline_task_count = 0
            logger.info(
                "Reuse mode: baseline task count = %d. The scan finishes only "
                "after the rescan creates new tasks AND they all complete; "
                "otherwise it monitors until max_runtime.",
                self._baseline_task_count,
            )

        while not self._shutdown_requested:
            if not self._auth_check_passed():
                if self._shutdown_requested:
                    break  # shutdown requested during retries -> graceful exit
                logger.error("Target authorization check failed! Stopping scan.")
                try:
                    self.api_client.stop_project(self.project_id)
                    logger.info("Scan stopped successfully")
                except httpx.HTTPStatusError as e:
                    logger.error(f"Failed to stop scan: {e}")
                # Reports are still downloaded (best-effort) so results found so
                # far are not lost — should_download_report stays True.
                return ExitCode.AUTH_FAILURE

            if (
                self.config.project.one_time
                or self.config.project.reuse_existing_project
            ) and self._check_project_completed():
                logger.info("Scan completed successfully. Stopping project.")
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
