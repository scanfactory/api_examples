from pathlib import Path

from src import app
from src.config import ExitCode


def test_run_config_error_on_missing_file(monkeypatch):
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api")
    application = app.Application()
    rc = application.run(Path("/nonexistent/config.yaml"), "", force=True)
    assert rc == ExitCode.CONFIG_ERROR


from datetime import datetime, timezone

from src import app as app_module
from src.api_client import AmbiguousProjectError


class FakeApi:
    def __init__(self, existing=None, ambiguous=False):
        self.existing = existing
        self.ambiguous = ambiguous
        self.created = []
        self.patched = []
        self.deleted = []

    def find_project_by_name(self, name):
        if self.ambiguous:
            raise AmbiguousProjectError("dup")
        return self.existing

    def create_project(self, config):
        self.created.append(config.project.name)
        return {"id": "new-id"}

    def patch_project_settings(self, pid, config):
        self.patched.append(pid)
        return {}

    def delete_project(self, pid):
        self.deleted.append(pid)


def _cfg(**project):
    from src.config import ScanConfig

    return ScanConfig(
        project={"name": "proj", **project},
        target="example.com",
        monitoring={"health_check_url": "https://x/health"},
    )


def test_resolve_create_with_datetime_postfix():
    api = FakeApi()
    application = app_module.Application()
    start = datetime(2026, 6, 13, 12, 44, 7, tzinfo=timezone.utc)
    pid, should_rescan = application._resolve_project(
        api, _cfg(datetime_name_postfix=True), start
    )
    assert pid == "new-id"
    assert should_rescan is False
    assert api.created == ["proj 13 June 2026 12:44:07"]


def test_resolve_reuse_found():
    api = FakeApi(existing={"id": "old-id"})
    application = app_module.Application()
    pid, should_rescan = application._resolve_project(
        api, _cfg(reuse_existing_project=True), datetime.now(timezone.utc)
    )
    assert pid == "old-id"
    assert should_rescan is True
    assert api.patched == ["old-id"]
    assert api.created == []


def test_resolve_reuse_missing_creates():
    api = FakeApi(existing=None)
    application = app_module.Application()
    pid, should_rescan = application._resolve_project(
        api, _cfg(reuse_existing_project=True), datetime.now(timezone.utc)
    )
    assert pid == "new-id"
    assert should_rescan is False
    assert api.created == ["proj"]


import signal
import textwrap

from src.config import ExitCode


def test_request_shutdown_sets_flag_and_notifies_watcher():
    application = app_module.Application()

    class FakeWatcher:
        def __init__(self):
            self.shutdown = False

        def request_shutdown(self):
            self.shutdown = True

    fw = FakeWatcher()
    application.watcher = fw
    application.request_shutdown(signal.SIGINT)
    assert application.shutdown_requested is True
    assert fw.shutdown is True


def test_setup_signal_handlers_runs(monkeypatch):
    recorded = []
    monkeypatch.setattr(signal, "signal", lambda s, h: recorded.append(s))
    application = app_module.Application()
    application.setup_signal_handlers()
    assert signal.SIGINT in recorded and signal.SIGTERM in recorded


class FakeClientForRun:
    def __init__(self):
        self.created = []
        self.started = []
        self.closed = False

    def find_project_by_name(self, name):
        return None

    def create_project(self, config):
        self.created.append(config.project.name)
        return {"id": "x"}

    def start_project(self, pid):
        self.started.append(pid)
        return {}

    def close(self):
        self.closed = True


def _write_cfg(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: false}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    return cfg


def test_run_happy_path_returns_success(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.SUCCESS

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS
    assert fake_client.created == ["proj"]
    assert fake_client.started == ["x"]
    assert fake_client.closed is True


import httpx


def _http_error(status=500):
    request = httpx.Request("POST", "https://api/x")
    response = httpx.Response(status, request=request, text="boom")
    return httpx.HTTPStatusError("err", request=request, response=response)


def test_run_config_error_on_invalid_yaml(tmp_path, monkeypatch):
    # YAML that parses to an int -> ScanConfig(**raw) raises -> ValueError branch (72-74)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("project: {name: }\ntarget:\nmonitoring: []\n")
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.CONFIG_ERROR


def test_run_token_validation_fails(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: False)
    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.CONFIG_ERROR


def test_run_shutdown_before_client_returns_success(tmp_path, monkeypatch):
    # shutdown requested during setup_signal_handlers -> early SUCCESS (89-90)
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)
    application = app_module.Application()

    def fake_setup():
        application.shutdown_requested = True

    monkeypatch.setattr(application, "setup_signal_handlers", fake_setup)
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS


def test_run_ambiguous_project_returns_config_error(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    application = app_module.Application()

    def raise_ambiguous(api, config, start):
        raise AmbiguousProjectError("dup")

    monkeypatch.setattr(application, "_resolve_project", raise_ambiguous)
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.CONFIG_ERROR
    assert fake_client.closed is True


def test_run_resolve_http_error_returns_api_error(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    application = app_module.Application()
    monkeypatch.setattr(
        application,
        "_resolve_project",
        lambda *a, **k: (_ for _ in ()).throw(_http_error()),
    )
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.API_ERROR


def test_run_no_project_id_returns_api_error(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    application = app_module.Application()
    monkeypatch.setattr(application, "_resolve_project", lambda *a, **k: (None, False))
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.API_ERROR


def test_run_shutdown_before_start_returns_success(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    application = app_module.Application()

    def resolve_and_request_shutdown(api, config, start):
        application.shutdown_requested = True
        return "pid", False

    monkeypatch.setattr(application, "_resolve_project", resolve_and_request_shutdown)
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS
    assert fake_client.started == []  # never started (116-117)


def test_run_start_project_http_error_returns_api_error(tmp_path, monkeypatch):
    cfg = _write_cfg(tmp_path)
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    class StartFails(FakeClientForRun):
        def start_project(self, pid):
            raise _http_error()

    fake_client = StartFails()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.API_ERROR
    assert fake_client.closed is True


def test_run_delete_on_completion(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj, delete_on_completion: true}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: false}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    deleted = []

    class DeletingClient(FakeClientForRun):
        def delete_project(self, pid):
            deleted.append(pid)

    fake_client = DeletingClient()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.SUCCESS

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS
    assert deleted == ["x"]


def test_run_delete_skipped_on_auth_failure(tmp_path, monkeypatch):
    # delete_on_completion=true but the scan ends in AUTH_FAILURE -> NOT deleted
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj, delete_on_completion: true}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: false}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    deleted = []

    class DeletingClient(FakeClientForRun):
        def delete_project(self, pid):
            deleted.append(pid)

    fake_client = DeletingClient()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = False
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.AUTH_FAILURE

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.AUTH_FAILURE
    assert deleted == []


def test_run_delete_on_completion_error_logged(tmp_path, monkeypatch):
    # delete_project raises -> caught and logged (153-154); run still returns SUCCESS
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj, delete_on_completion: true}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: false}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    class DeleteFails(FakeClientForRun):
        def delete_project(self, pid):
            raise _http_error()

    fake_client = DeleteFails()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.SUCCESS

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS


def test_run_happy_path_with_reports(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.SUCCESS

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    from src import reports

    called = {}

    def fake_download(api, report, pid, start, now):
        called["pid"] = pid
        return {"pdf": "ok"}

    monkeypatch.setattr(reports, "download_reports", fake_download)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS
    assert called["pid"] == "x"


def test_run_reuse_found_triggers_rescan(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj, reuse_existing_project: true, one_time: false}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: false}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    class ReuseClient(FakeClientForRun):
        def __init__(self):
            super().__init__()
            self.rescanned = []
            self.patched = []

        def find_project_by_name(self, name):
            return {"id": "old-id"}

        def patch_project_settings(self, pid, config):
            self.patched.append(pid)
            return {}

        def rescan_project(self, pid):
            self.rescanned.append(pid)

    fake_client = ReuseClient()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.SUCCESS

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.SUCCESS
    assert fake_client.rescanned == ["old-id"]  # rescan, not start
    assert fake_client.started == []
    assert fake_client.patched == ["old-id"]


def test_run_downloads_reports_on_auth_failure(tmp_path, monkeypatch):
    # auth failure must NOT skip reports anymore (best-effort), exit code stays AUTH_FAILURE
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent("""
        project: {name: proj}
        target: example.com
        monitoring: {health_check_url: "https://x/health"}
        report:
          pdf: {enabled: true, output_path: ./r.pdf}
          html: {enabled: false}
          alerts_json: {enabled: false}
          alerts_grouped_json: {enabled: false}
    """))
    monkeypatch.setenv("SF_TOKEN", "tok")
    monkeypatch.setenv("SF_APP_URL", "https://api.example.com")
    monkeypatch.setattr(app_module, "validate_tokens", lambda *a, **k: True)

    fake_client = FakeClientForRun()
    monkeypatch.setattr(app_module, "SFAPIClient", lambda url, token: fake_client)

    class FakeWatcher:
        def __init__(self, *a, **k):
            self.should_download_report = True
            self.start_time = datetime.now(timezone.utc)

        def run(self):
            return ExitCode.AUTH_FAILURE

    monkeypatch.setattr(app_module, "ScanWatcher", FakeWatcher)

    called = {}
    from src import reports as reports_mod

    monkeypatch.setattr(
        reports_mod,
        "download_reports",
        lambda *a, **k: called.setdefault("yes", True) or {"pdf": "ok"},
    )

    application = app_module.Application()
    rc = application.run(cfg, "", force=True)
    assert rc == ExitCode.AUTH_FAILURE  # exit code unchanged
    assert called.get("yes") is True  # reports still attempted on auth failure
