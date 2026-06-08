import json

import httpx
import pytest

from src import api_client
from src.config import ScanConfig


def make_client(handler):
    transport = httpx.MockTransport(handler)
    return api_client.SFAPIClient("https://api.example.com", "tok", transport=transport)


def base_config(**project_extra):
    return ScanConfig(
        project={"name": "proj", **project_extra},
        target="example.com",
        monitoring={"health_check_url": "https://x/health"},
    )


def test_build_payload_includes_rps_when_set():
    client = make_client(lambda r: httpx.Response(200, json={}))
    payload = client._build_project_payload(base_config(rps=1000))
    assert payload["scan_settings"]["rps"] == 1000


def test_build_payload_omits_rps_when_unset():
    client = make_client(lambda r: httpx.Response(200, json={}))
    payload = client._build_project_payload(base_config())
    assert "rps" not in payload["scan_settings"]


def test_create_project_posts_then_patches():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(200, json={"id": "abc"})
        return httpx.Response(200, json={"id": "abc", "status": "created"})

    client = make_client(handler)
    result = client.create_project(base_config())
    assert result["id"] == "abc"
    assert calls[0] == ("POST", "/api/projects/")
    assert calls[1] == ("PATCH", "/api/projects/abc")


def test_start_and_stop_project_set_status():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"status": seen["body"]["status"]})

    client = make_client(handler)
    assert client.start_project("abc")["status"] == "running"
    assert client.stop_project("abc")["status"] == "paused"


def test_list_project_tasks_returns_items():
    client = make_client(
        lambda r: httpx.Response(200, json={"items": [{"status": 130}]})
    )
    assert client.list_project_tasks("abc") == [{"status": 130}]


def test_find_project_by_name_single():
    items = [{"id": "1", "name": "alpha"}, {"id": "2", "name": "beta"}]
    client = make_client(lambda r: httpx.Response(200, json={"items": items}))
    assert client.find_project_by_name("beta")["id"] == "2"


def test_find_project_by_name_none():
    client = make_client(lambda r: httpx.Response(200, json={"items": []}))
    assert client.find_project_by_name("ghost") is None


def test_find_project_by_name_ambiguous():
    items = [{"id": "1", "name": "dup"}, {"id": "2", "name": "dup"}]
    client = make_client(lambda r: httpx.Response(200, json={"items": items}))
    with pytest.raises(api_client.AmbiguousProjectError):
        client.find_project_by_name("dup")


def test_delete_project_calls_delete():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(204)

    client = make_client(handler)
    client.delete_project("abc")
    assert calls == [("DELETE", "/api/projects/abc")]


def test_download_report_html_sets_headers_and_params(tmp_path):
    captured = {}

    def handler(request):
        captured["accept"] = request.headers["accept"]
        captured["lang"] = request.headers["accept-language"]
        captured["url"] = str(request.url)
        return httpx.Response(200, content=b"<html></html>")

    client = make_client(handler)
    out = tmp_path / "r.html"
    client.download_report(
        "pid", out, fmt="html", from_ts=1000, severity=[10, 8], language="ru"
    )
    assert out.read_bytes() == b"<html></html>"
    assert captured["accept"] == "text/html"
    assert captured["lang"] == "ru"
    assert "from=1000" in captured["url"]
    assert captured["url"].count("severity=") == 2


def test_get_alerts_params_ungrouped():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["params"] = dict(request.url.params.multi_items())
        return httpx.Response(200, json={"items": []})

    client = make_client(handler)
    client.get_alerts(
        "pid", gt_last_seen=100, lt_last_seen=200, severity=[10, 8, 5], grouped=False
    )
    p = captured["params"]
    assert p["project_id"] == "pid"
    assert p["grouped"] == "false"
    assert p["$gt-last_seen"] == "100"
    assert p["$lt-last_seen"] == "200"
    assert p["active"] == "1" and p["masked"] == "0"
    assert captured["url"].count("severity=") == 3


def test_get_alerts_grouped_true():
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params.multi_items())
        return httpx.Response(200, json={"items": []})

    client = make_client(handler)
    client.get_alerts("pid", 100, 200, [10], grouped=True)
    assert captured["params"]["grouped"] == "true"


def test_get_alerts_warns_on_truncation(caplog):
    items = [{"id": i} for i in range(1000)]
    client = make_client(lambda r: httpx.Response(200, json={"items": items}))
    import logging

    with caplog.at_level(logging.WARNING):
        client.get_alerts("pid", 100, 200, [10], grouped=False)
    assert any("limit" in rec.message.lower() for rec in caplog.records)


def test_close_closes_underlying_client():
    client = make_client(lambda r: httpx.Response(200, json={}))
    client.close()
    assert client.client.is_closed is True


def test_build_scope_settings_ip_target():
    client = make_client(lambda r: httpx.Response(200, json={}))
    payload = client._build_project_payload(_ip_config())
    scope = payload["scope_settings"]
    assert scope["root_ips"] == ["192.168.1.1"]
    assert scope["root_domains"] == []


def _ip_config():
    return ScanConfig(
        project={"name": "proj"},
        target="192.168.1.1",
        monitoring={"health_check_url": "https://x/health"},
    )


def test_build_scope_settings_domain_target():
    client = make_client(lambda r: httpx.Response(200, json={}))
    payload = client._build_project_payload(base_config())
    scope = payload["scope_settings"]
    assert scope["root_domains"] == ["example.com"]
    assert scope["root_ips"] == []


def test_create_project_no_id_returns_post_json_without_patch():
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, json={"foo": "bar"})

    client = make_client(handler)
    result = client.create_project(base_config())
    assert result == {"foo": "bar"}
    assert calls == ["POST"]  # no PATCH (line 124)


def test_patch_project_settings():
    calls = []
    bodies = []

    def handler(request):
        calls.append((request.method, request.url.path))
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"status": "patched"})

    client = make_client(handler)
    result = client.patch_project_settings("pid", base_config())
    assert result == {"status": "patched"}
    assert calls == [("PATCH", "/api/projects/pid")]
    # reuse PATCH must un-pause the project AND carry scan settings
    assert bodies[0]["status"] == "running"
    assert "scan_settings" in bodies[0]
    assert "scope_settings" in bodies[0]


def test_get_project_includes_task_stats():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"id": "pid", "status": "running"})

    client = make_client(handler)
    result = client.get_project("pid")
    assert result["status"] == "running"
    assert "task_stats=1" in captured["url"]


def test_download_report_pdf(tmp_path):
    captured = {}

    def handler(request):
        captured["accept"] = request.headers["accept"]
        return httpx.Response(200, content=b"%PDF-1.4")

    client = make_client(handler)
    out = tmp_path / "sub" / "r.pdf"
    client.download_report(
        "pid", out, fmt="pdf", from_ts=500, severity=[10], language="en"
    )
    assert out.read_bytes() == b"%PDF-1.4"
    assert captured["accept"] == "application/pdf"


def _patch_httpx_client(monkeypatch, handler):
    """Make api_client.httpx.Client(...) use a MockTransport regardless of kwargs."""
    real_client = httpx.Client

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return real_client(
            transport=httpx.MockTransport(handler),
            **{k: v for k, v in kwargs.items() if k in ("timeout", "headers")}
        )

    monkeypatch.setattr(api_client.httpx, "Client", factory)


def test_check_authorization_health_ok(monkeypatch):
    _patch_httpx_client(monkeypatch, lambda r: httpx.Response(200))
    ok = api_client.check_authorization_health(
        "https://target/health", {"Cookie": ["abc"]}, [200]
    )
    assert ok is True


def test_check_authorization_health_unauthorized(monkeypatch):
    _patch_httpx_client(monkeypatch, lambda r: httpx.Response(401))
    ok = api_client.check_authorization_health("https://target/health", {}, [200])
    assert ok is False


def test_check_authorization_health_request_error(monkeypatch):
    def handler(request):
        raise httpx.RequestError("boom", request=request)

    _patch_httpx_client(monkeypatch, handler)
    ok = api_client.check_authorization_health("https://target/health", {}, [200])
    assert ok is False


def test_rescan_project_posts_to_rescan_endpoint():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(204)

    client = make_client(handler)
    client.rescan_project("abc")
    assert calls == [("POST", "/api/projects/abc/rescan")]


def test_rescan_project_raises_on_error():
    client = make_client(lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(httpx.HTTPStatusError):
        client.rescan_project("abc")
