from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from src.config import ReportConfig

logger = logging.getLogger("scan_watcher")


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2))


def download_reports(
    api_client,
    report: ReportConfig,
    project_id: str,
    start_dt: datetime,
    now_dt: datetime,
) -> dict[str, str]:
    """Download every enabled report format for the [start_dt, now_dt] window.

    Each format is independent: a failure is logged and recorded but does not
    abort the others. Returns {format_key: "ok"|"failed"|"skipped"}.
    """
    from_ts = int(start_dt.timestamp())
    to_ts = int(now_dt.timestamp())
    summary: dict[str, str] = {}

    def attempt(key: str, enabled: bool, fn) -> None:
        if not enabled:
            summary[key] = "skipped"
            return
        try:
            fn()
            summary[key] = "ok"
        except Exception as e:  # noqa: BLE001 - report errors must not abort others
            logger.error("Failed to download %s report: %s", key, e)
            summary[key] = "failed"

    attempt(
        "pdf",
        report.pdf.enabled,
        lambda: api_client.download_report(
            project_id,
            report.pdf.output_path,
            "pdf",
            from_ts,
            report.severity,
            report.language,
        ),
    )
    attempt(
        "html",
        report.html.enabled,
        lambda: api_client.download_report(
            project_id,
            report.html.output_path,
            "html",
            from_ts,
            report.severity,
            report.language,
        ),
    )
    attempt(
        "alerts_json",
        report.alerts_json.enabled,
        lambda: _write_json(
            report.alerts_json.output_path,
            api_client.get_alerts(
                project_id, from_ts, to_ts, report.severity, grouped=False
            ),
        ),
    )
    attempt(
        "alerts_grouped_json",
        report.alerts_grouped_json.enabled,
        lambda: _write_json(
            report.alerts_grouped_json.output_path,
            api_client.get_alerts(
                project_id, from_ts, to_ts, report.severity, grouped=True
            ),
        ),
    )

    return summary
