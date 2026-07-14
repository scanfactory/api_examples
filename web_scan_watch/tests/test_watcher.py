from datetime import datetime, timedelta, timezone

import httpx

from src import watcher
from src.config import ScanConfig


def _http_error():
    request = httpx.Request("GET", "https://x/api")
    response = httpx.Response(500, request=request, text="boom")
    return httpx.HTTPStatusError("err", request=request, response=response)


class FakeClient:
    def __init__(self, project_status="running", tasks=None):
        self._project = {"status": project_status}
        self._tasks = tasks or []
        self.stopped = False

    def get_project(self, pid):
        return self._project

    def list_project_tasks(self, pid):
        return self._tasks

    def stop_project(self, pid):
        self.stopped = True
        return {}


def make_watcher(client):
    cfg = ScanConfig(
        project={"name": "p", "one_time": True},
        target="example.com",
        monitoring={"health_check_url": "https://x/health"},
    )
    return watcher.ScanWatcher(client, cfg, "pid")


def test_completed_when_all_tasks_terminal():
    # 130 = FINISHED
    w = make_watcher(FakeClient(tasks=[{"status": 130}, {"status": 130}]))
    assert w._check_project_completed() is True


def test_not_completed_with_active_tasks():
    # 120 = WORKING (active), 130 = FINISHED
    w = make_watcher(FakeClient(tasks=[{"status": 120}, {"status": 130}]))
    assert w._check_project_completed() is False


def test_runtime_exceeded():
    w = make_watcher(FakeClient())
    w.config.monitoring.max_runtime_hours = 1.0
    w.start_time = datetime.now(tz=timezone.utc) - timedelta(hours=2)
    assert w._check_runtime_exceeded() is True


from src.config import ExitCode


def test_run_auth_failure_stops_and_returns_auth_failure(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: False)
    client = FakeClient()
    w = make_watcher(client)
    w.config.monitoring.health_check_retries = 0  # fail fast (no retry delay)
    rc = w.run()
    assert rc == ExitCode.AUTH_FAILURE
    # reports are still attempted on auth failure (best-effort)
    assert w.should_download_report is True
    assert client.stopped is True


def test_run_one_time_completed_returns_success(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    # all-terminal tasks + project running -> completes on first iteration
    client = FakeClient(
        project_status="running", tasks=[{"status": 130}, {"status": 130}]
    )
    w = make_watcher(client)
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert client.stopped is True


def test_run_shutdown_requested_before_loop_returns_success(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    client = FakeClient()
    w = make_watcher(client)
    w.request_shutdown()
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert client.stopped is True


def test_run_runtime_exceeded_returns_success(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    monkeypatch.setattr(watcher.time, "sleep", lambda *a, **k: None)
    # active task -> not completed; runtime already exceeded
    client = FakeClient(project_status="running", tasks=[{"status": 120}])
    w = make_watcher(client)
    w.config.monitoring.max_runtime_hours = 1.0
    w.start_time = datetime.now(tz=timezone.utc) - timedelta(hours=2)
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert client.stopped is True


def test_check_completed_paused_status_returns_true():
    # project status "paused" -> completed (47-49)
    w = make_watcher(FakeClient(project_status="paused"))
    assert w._check_project_completed() is True


def test_check_completed_no_tasks_returns_false():
    # running, but zero tasks -> not completed (67-69)
    w = make_watcher(FakeClient(project_status="running", tasks=[]))
    assert w._check_project_completed() is False


class ErrorClient:
    """Raises HTTPStatusError from configurable methods."""

    def __init__(self, fail_get=False, fail_tasks=False, tasks=None):
        self.fail_get = fail_get
        self.fail_tasks = fail_tasks
        self._tasks = tasks or []
        self.stopped = False

    def get_project(self, pid):
        if self.fail_get:
            raise _http_error()
        return {"status": "running"}

    def list_project_tasks(self, pid):
        if self.fail_tasks:
            raise _http_error()
        return self._tasks

    def stop_project(self, pid):
        self.stopped = True
        return {}


def test_check_completed_get_project_http_error_returns_false():
    # get_project raises -> caught, returns False (50-55)
    w = make_watcher(ErrorClient(fail_get=True))
    assert w._check_project_completed() is False


def test_check_completed_list_tasks_http_error_returns_false():
    # list_project_tasks raises -> caught, returns False (59-64)
    w = make_watcher(ErrorClient(fail_tasks=True))
    assert w._check_project_completed() is False


def test_run_verify_ssl_disabled_warns(monkeypatch, caplog):
    import logging

    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    client = FakeClient(project_status="paused")
    w = make_watcher(client)
    w.config.monitoring.verify_ssl = False
    with caplog.at_level(logging.WARNING):
        rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert any("verification" in rec.message.lower() for rec in caplog.records)


def test_run_stop_project_error_on_completion_logged(monkeypatch):
    # completion path where stop_project raises HTTPStatusError (118-119)
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)

    class StopFails(FakeClient):
        def stop_project(self, pid):
            raise _http_error()

    client = StopFails(project_status="paused")
    w = make_watcher(client)
    rc = w.run()
    assert rc == ExitCode.SUCCESS


def test_run_sleep_loop_then_shutdown(monkeypatch):
    # Exercise the inner sleep loop (130-136): first iteration not complete,
    # then shutdown is requested via the sleep side-effect.
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    client = FakeClient(project_status="running", tasks=[{"status": 120}])
    w = make_watcher(client)
    w.config.monitoring.check_interval_minutes = 1

    def fake_sleep(_seconds):
        w.request_shutdown()

    monkeypatch.setattr(watcher.time, "sleep", fake_sleep)
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert client.stopped is True


class StopAlwaysFails(FakeClient):
    def stop_project(self, pid):
        raise _http_error()


def test_run_auth_failure_stop_error_logged(monkeypatch):
    # auth fails and stop_project raises -> logged, still AUTH_FAILURE (108-109)
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: False)
    w = make_watcher(StopAlwaysFails())
    w.config.monitoring.health_check_retries = 0
    rc = w.run()
    assert rc == ExitCode.AUTH_FAILURE
    assert w.should_download_report is True


def test_run_runtime_exceeded_stop_error_logged(monkeypatch):
    # runtime exceeded and stop_project raises -> logged, still SUCCESS (126-127)
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    client = StopAlwaysFails(project_status="running", tasks=[{"status": 120}])
    w = make_watcher(client)
    w.config.monitoring.max_runtime_hours = 1.0
    w.start_time = datetime.now(tz=timezone.utc) - timedelta(hours=2)
    rc = w.run()
    assert rc == ExitCode.SUCCESS


def test_run_shutdown_stop_error_logged(monkeypatch):
    # shutdown requested + stop_project raises -> logged, still SUCCESS (142-143)
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    w = make_watcher(StopAlwaysFails())
    w.request_shutdown()
    rc = w.run()
    assert rc == ExitCode.SUCCESS


# --- reuse-mode completion (baseline-aware) ---


def make_reuse_watcher(client, one_time=False):
    cfg = ScanConfig(
        project={"name": "p", "one_time": one_time, "reuse_existing_project": True},
        target="example.com",
        monitoring={"health_check_url": "https://x/health"},
    )
    return watcher.ScanWatcher(client, cfg, "pid")


def test_reuse_no_new_tasks_warns_and_not_complete(caplog):
    import logging

    # 2 old terminal tasks, baseline 2 -> no new tasks created
    w = make_reuse_watcher(FakeClient(tasks=[{"status": 130}, {"status": 130}]))
    w._baseline_task_count = 2
    with caplog.at_level(logging.WARNING):
        assert w._check_project_completed() is False
    assert any("not been created" in r.getMessage().lower() for r in caplog.records)
    assert w._new_tasks_seen is False


def test_reuse_new_tasks_appeared_and_all_terminal_completes():
    # baseline 2, now 3 terminal tasks -> new task appeared and all done
    w = make_reuse_watcher(
        FakeClient(tasks=[{"status": 130}, {"status": 130}, {"status": 130}])
    )
    w._baseline_task_count = 2
    assert w._check_project_completed() is True
    assert w._new_tasks_seen is True


def test_reuse_new_tasks_appeared_but_active_not_complete():
    # baseline 1, now 2 tasks but one is WORKING (120) -> not complete yet
    w = make_reuse_watcher(FakeClient(tasks=[{"status": 130}, {"status": 120}]))
    w._baseline_task_count = 1
    assert w._check_project_completed() is False
    assert w._new_tasks_seen is True  # latched


def test_reuse_latch_persists_after_new_tasks_seen():
    # already latched; even if count <= baseline now, normal rule applies
    w = make_reuse_watcher(FakeClient(tasks=[{"status": 130}]))
    w._baseline_task_count = 5
    w._new_tasks_seen = True
    assert w._check_project_completed() is True  # all terminal -> complete


def test_run_reuse_completes_when_new_tasks_done(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)

    class GrowingClient(FakeClient):
        def __init__(self):
            super().__init__()
            self._calls = 0

        def list_project_tasks(self, pid):
            self._calls += 1
            if self._calls == 1:
                return [{"status": 130}]  # baseline = 1
            return [
                {"status": 130},
                {"status": 130},
            ]  # new task appeared + all terminal

    client = GrowingClient()
    w = make_reuse_watcher(client, one_time=False)  # one_time False on purpose
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert w._new_tasks_seen is True
    assert client.stopped is True


def test_run_reuse_keeps_monitoring_until_runtime_when_no_new_tasks(monkeypatch):
    # No new tasks ever -> never "completes"; ends on max_runtime instead.
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)
    monkeypatch.setattr(watcher.time, "sleep", lambda *a, **k: None)
    client = FakeClient(tasks=[{"status": 130}])  # count stays == baseline
    w = make_reuse_watcher(client, one_time=False)
    w.config.monitoring.max_runtime_hours = 1.0
    w.start_time = datetime.now(tz=timezone.utc) - timedelta(
        hours=2
    )  # already exceeded
    rc = w.run()
    assert rc == ExitCode.SUCCESS  # stopped by max_runtime, not by false completion
    assert w._new_tasks_seen is False


def test_reuse_baseline_capture_handles_error(monkeypatch):
    # If the baseline list_project_tasks call fails, baseline defaults to 0.
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: True)

    class FailBaselineThenOk(FakeClient):
        def __init__(self):
            super().__init__()
            self._n = 0

        def list_project_tasks(self, pid):
            self._n += 1
            if self._n == 1:
                raise _http_error()  # baseline capture fails -> 0
            return [{"status": 130}]  # 1 > 0 -> new task, terminal -> done

    w = make_reuse_watcher(FailBaselineThenOk(), one_time=False)
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert w._baseline_task_count == 0


def test_reuse_check_completed_list_error_returns_false():
    w = make_reuse_watcher(ErrorClient(fail_tasks=True))
    w._baseline_task_count = 0
    assert w._check_project_completed() is False


# --- health check retries (transient network errors) ---


def test_health_check_retries_then_recovers(monkeypatch):
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        return calls["n"] >= 2  # 1st attempt fails (transient), then recovers

    monkeypatch.setattr(watcher, "check_authorization_health", flaky)
    client = FakeClient(project_status="running", tasks=[{"status": 130}])
    w = make_watcher(client)  # one_time=True
    w.config.monitoring.health_check_retries = 3
    w.config.monitoring.health_check_retry_delay_seconds = 0  # no backoff in tests
    rc = w.run()
    assert rc == ExitCode.SUCCESS  # recovered, then completed normally
    assert calls["n"] >= 2  # retried at least once
    assert client.stopped is True


def test_health_check_all_retries_fail_stops(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: False)
    client = FakeClient()
    w = make_watcher(client)
    w.config.monitoring.health_check_retries = 2  # 3 attempts, all fail
    w.config.monitoring.health_check_retry_delay_seconds = 0  # no backoff in tests
    rc = w.run()
    assert rc == ExitCode.AUTH_FAILURE
    assert client.stopped is True
    assert w.should_download_report is True  # reports still attempted


# --- health check disabled (monitoring.enabled=false) ---


def _disabled_watcher(client):
    cfg = ScanConfig(
        project={"name": "p", "one_time": True},
        target="example.com",
        monitoring={"enabled": False},  # no health_check_url required
    )
    return watcher.ScanWatcher(client, cfg, "pid")


def test_auth_check_passed_true_when_disabled(monkeypatch):
    # Disabled -> returns True without ever calling check_authorization_health.
    def boom(*a, **k):
        raise AssertionError("health check must not run when disabled")

    monkeypatch.setattr(watcher, "check_authorization_health", boom)
    w = _disabled_watcher(FakeClient())
    assert w._auth_check_passed() is True


def test_run_health_check_disabled_makes_no_requests(monkeypatch):
    called = {"n": 0}

    def spy(*a, **k):
        called["n"] += 1
        return True

    monkeypatch.setattr(watcher, "check_authorization_health", spy)
    # paused + one_time -> completes on the first iteration
    client = FakeClient(project_status="paused")
    w = _disabled_watcher(client)
    rc = w.run()
    assert rc == ExitCode.SUCCESS
    assert called["n"] == 0  # health check never invoked
    assert client.stopped is True


def test_health_check_shutdown_during_retries_is_graceful(monkeypatch):
    monkeypatch.setattr(watcher, "check_authorization_health", lambda *a, **k: False)
    client = FakeClient()
    w = make_watcher(client)
    w.config.monitoring.health_check_retries = 5

    def fake_sleep(_seconds):
        w.request_shutdown()  # shutdown arrives during the retry backoff

    monkeypatch.setattr(watcher.time, "sleep", fake_sleep)
    rc = w.run()
    assert rc == ExitCode.SUCCESS  # graceful shutdown, NOT AUTH_FAILURE
