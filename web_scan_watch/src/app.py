from __future__ import annotations

import logging
import signal
from pathlib import Path

import httpx
import yaml

from src.api_client import SFAPIClient
from src.config import ExitCode, load_config
from src.tokens import validate_tokens
from src.watcher import ScanWatcher

logger = logging.getLogger("scan_watcher")


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

    def _resolve_project(self, api_client, config, start_dt):
        """Return (project_id, should_rescan).

        - reuse_existing_project: find by exact name. If FOUND -> re-PATCH
          settings and return should_rescan=True (the caller triggers
          POST /api/projects/{id}/rescan, regardless of the project's status).
          If NOT found -> create it and return should_rescan=False (the caller
          starts it normally).
        - datetime_name_postfix: append the UTC start datetime to the name on create.
        Always logs the resolved project_id.
        """
        from src.config import DATETIME_POSTFIX_FORMAT

        proj = config.project
        if proj.reuse_existing_project:
            existing = api_client.find_project_by_name(proj.name)
            if existing:
                project_id = existing.get("id") or existing.get("_id")
                api_client.patch_project_settings(project_id, config)
                logger.info("Reusing existing project: %s", project_id)
                return project_id, True
            logger.info("Project %r not found; creating it", proj.name)
            project = api_client.create_project(config)
            project_id = project.get("id") or project.get("_id")
            logger.info("Project created (will be reused next run): %s", project_id)
            return project_id, False

        if proj.datetime_name_postfix:
            postfix = start_dt.strftime(DATETIME_POSTFIX_FORMAT)
            config = config.model_copy(deep=True)
            config.project.name = f"{proj.name} {postfix}"
        project = api_client.create_project(config)
        project_id = project.get("id") or project.get("_id")
        logger.info("Project created: %s", project_id)
        return project_id, False

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
            from datetime import datetime, timezone
            from src.api_client import AmbiguousProjectError

            start_dt = datetime.now(tz=timezone.utc)
            logger.info("Resolving scanning project...")
            try:
                project_id, should_rescan = self._resolve_project(
                    api_client, config, start_dt
                )
            except AmbiguousProjectError as e:
                logger.error("Ambiguous project name: %s", e)
                return ExitCode.CONFIG_ERROR
            except httpx.HTTPStatusError as e:
                logger.error(
                    "Failed to resolve project: %s - %s",
                    e.response.status_code,
                    e.response.text,
                )
                return ExitCode.API_ERROR
            if not project_id:
                logger.error("Project resolved but no ID returned")
                return ExitCode.API_ERROR

            if self.shutdown_requested:
                logger.info("Shutdown requested before starting scan")
                return ExitCode.SUCCESS

            logger.info("Starting scan...")
            try:
                if should_rescan:
                    # Reused existing project: trigger a fresh scan via /rescan
                    # (done in any project status).
                    api_client.rescan_project(project_id)
                    logger.info("Rescan triggered on existing project")
                else:
                    api_client.start_project(project_id)
                    logger.info("Scan started successfully")
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"Failed to start scan: {e.response.status_code} - {e.response.text}"
                )
                return ExitCode.API_ERROR

            self.watcher = ScanWatcher(api_client, config, project_id)
            exit_code = self.watcher.run()

            if (
                config.report.pdf.enabled
                or config.report.html.enabled
                or config.report.alerts_json.enabled
                or config.report.alerts_grouped_json.enabled
            ) and self.watcher.should_download_report:
                from src import reports

                summary = reports.download_reports(
                    api_client,
                    config.report,
                    project_id,
                    self.watcher.start_time,
                    datetime.now(tz=timezone.utc),
                )
                logger.info("Report summary: %s", summary)

            if config.project.delete_on_completion and exit_code == ExitCode.SUCCESS:
                try:
                    api_client.delete_project(project_id)
                    logger.info("Project deleted on completion: %s", project_id)
                except (httpx.HTTPStatusError, httpx.RequestError) as e:
                    logger.error("Failed to delete project: %s", e)

            return exit_code

        finally:
            api_client.close()
