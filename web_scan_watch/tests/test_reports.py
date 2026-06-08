from datetime import datetime, timezone
from pathlib import Path

from src import reports
from src.config import ReportConfig, ReportFormatConfig


class FakeApi:
    def __init__(self):
        self.reports = []
        self.alerts = []

    def download_report(self, pid, out, fmt, from_ts, severity, language):
        self.reports.append((fmt, str(out), from_ts, tuple(severity), language))
        Path(out).write_text(fmt)

    def get_alerts(self, pid, gt_last_seen, lt_last_seen, severity, grouped):
        self.alerts.append((gt_last_seen, lt_last_seen, tuple(severity), grouped))
        return {"items": []}


def cfg(tmp_path, **enabled):
    base = ReportConfig(severity=[10, 8])
    base.pdf = ReportFormatConfig(
        enabled=bool(enabled.get("pdf")), output_path=tmp_path / "r.pdf"
    )
    if enabled.get("html"):
        base.html = ReportFormatConfig(enabled=True, output_path=tmp_path / "r.html")
    if enabled.get("alerts"):
        base.alerts_json = ReportFormatConfig(
            enabled=True, output_path=tmp_path / "a.json"
        )
    if enabled.get("grouped"):
        base.alerts_grouped_json = ReportFormatConfig(
            enabled=True, output_path=tmp_path / "g.json"
        )
    return base


def test_only_enabled_formats_downloaded(tmp_path):
    api = FakeApi()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
    reports.download_reports(
        api, cfg(tmp_path, pdf=True, alerts=True), "pid", start, now
    )
    assert [r[0] for r in api.reports] == ["pdf"]
    assert len(api.alerts) == 1
    assert api.alerts[0][3] is False  # ungrouped


def test_window_passed_through(tmp_path):
    api = FakeApi()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
    reports.download_reports(
        api, cfg(tmp_path, pdf=True, grouped=True), "pid", start, now
    )
    assert api.reports[0][2] == int(start.timestamp())
    assert api.alerts[0][0] == int(start.timestamp())
    assert api.alerts[0][1] == int(now.timestamp())
    assert api.alerts[0][3] is True  # grouped


def test_one_format_failure_isolated(tmp_path):
    api = FakeApi()

    def boom(*a, **k):
        raise RuntimeError("network")

    api.download_report = boom
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
    summary = reports.download_reports(
        api, cfg(tmp_path, pdf=True, alerts=True), "pid", start, now
    )
    assert len(api.alerts) == 1
    assert summary["pdf"] == "failed"
    assert summary["alerts_json"] == "ok"


def test_disabled_formats_marked_skipped(tmp_path):
    api = FakeApi()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, 1, tzinfo=timezone.utc)
    summary = reports.download_reports(api, cfg(tmp_path, pdf=True), "pid", start, now)
    assert summary["pdf"] == "ok"
    assert summary["html"] == "skipped"
    assert summary["alerts_json"] == "skipped"
    assert summary["alerts_grouped_json"] == "skipped"
