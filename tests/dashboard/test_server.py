import asyncio
import json

from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest
from starlette.requests import Request

from dashboard import server
from simulation.config import settings
from simulation.logging.jsonl import JsonlEventWriter


def test_dashboard_uses_simulated_defense_label() -> None:
    app_js = (server.DASHBOARD_DIR / "app.js").read_text(encoding="utf-8")
    index_html = (server.DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")

    assert "Simulated Defense" in app_js
    assert "Simulated Defense" in index_html
    assert "Autonomous Defense" not in app_js
    assert "Autonomous Defense" not in index_html


def _client(monkeypatch, tmp_path):
    log_file = tmp_path / "events.jsonl"
    monkeypatch.setattr(server, "LOG_FILE", log_file)
    monkeypatch.setattr(settings.dashboard, "api_key", SecretStr("test-dashboard-key"))
    monkeypatch.setattr(
        settings.dashboard,
        "request_rate_limit_per_minute",
        10000,
    )
    server.rate_limiter._sources.clear()
    client = TestClient(server.app)
    session = client.post(
        "/api/session",
        headers={"X-API-Key": "test-dashboard-key"},
    )
    assert session.status_code == 200
    return client, log_file


def _event(**overrides):
    event = {
        "timestamp": "2025-01-01T00:00:00+00:00",
        "drone_id": "test-drone",
        "seq": 7,
        "gps": [13.5, 77.9],
        "altitude": 30,
        "speed": 10,
        "battery": 80,
        "trust_score": 0.9,
        "pattern": "NORMAL",
        "severity": "LOW",
        "response": "CONTINUE",
    }
    event.update(overrides)
    return event


def test_health_version_headers_and_restrictive_cors(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert client.get("/api/version").json()["name"] == "SCOUT-X Dashboard"
    preflight = client.options(
        "/api/events",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_sensitive_read_routes_require_api_key_session(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    client.cookies.clear()

    for path in (
        "/api/events",
        "/api/latest",
        "/api/state",
        "/api/telemetry",
        "/api/hem",
        "/api/ml",
        "/api/stream",
        "/api/report",
        "/api/aircraft",
    ):
        response = client.get(path)
        assert response.status_code == 401, path

    assert (
        client.post(
            "/api/session",
            headers={"X-API-Key": "wrong"},
        ).status_code
        == 401
    )
    session = client.post(
        "/api/session",
        headers={"X-API-Key": "test-dashboard-key"},
    )
    assert session.status_code == 200
    assert session.json() == {"authenticated": True}
    assert "httponly" in session.headers["set-cookie"].lower()
    assert client.get("/api/events").status_code == 200


def test_pipeline_event_log_normalizes_legacy_action_fields(monkeypatch, tmp_path):
    _, log_file = _client(monkeypatch, tmp_path)
    log_file.write_text(
        json.dumps(
            {
                "timestamp": "2025-01-01T00:00:00+00:00",
                "event_id": "event-1",
                "event_type": "SECURITY_RESULT",
                "drone_id": "scout-x-01",
                "severity": "LOW",
                "trust": 0.84,
                "state": "STANDBY",
                "details": {
                    "correlation_id": "session:1",
                    "pattern": None,
                    "enforced": "NONE",
                    "response": "NORMAL_OPERATION",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = server.read_events()

    assert len(events) == 1
    assert events[0].pattern == "SECURITY_RESULT"
    assert events[0].enforced is False
    assert events[0].correlation_id == "session:1"


def test_events_are_paged_filtered_and_malformed_records_are_dropped(
    monkeypatch, tmp_path
):
    client, log_file = _client(monkeypatch, tmp_path)
    records = [
        _event(seq=1, severity="LOW", pattern="NORMAL"),
        _event(seq=2, severity="HIGH", pattern="GPS_SPOOFING"),
        _event(seq=3, severity="HIGH", pattern="GPS_SPOOFING"),
    ]
    log_file.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n{bad json\n",
        encoding="utf-8",
    )
    response = client.get(
        "/api/events",
        params={"severity": "HIGH", "attack_type": "GPS_SPOOFING", "limit": 1},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert response.json()["events"][0]["seq"] == 2
    assert response.json()["has_more"] is True
    assert client.get("/api/events", params={"limit": 101}).status_code == 422


def test_events_unwrap_structured_jsonl_details(monkeypatch, tmp_path):
    client, log_file = _client(monkeypatch, tmp_path)
    JsonlEventWriter(log_file).append(
        event_type="TELEMETRY",
        severity="HIGH",
        trust=0.4,
        state="EVACUATE",
        drone_id="test-drone",
        details={
            "seq": 12,
            "pattern": "GPS_SPOOFING",
            "severity": "HIGH",
            "trust_score": 0.4,
            "gps": {"lat": 10.0, "lon": 20.0},
            "hem": {"hem_phase": "EVACUATE"},
        },
    )

    response = client.get("/api/events")

    assert response.status_code == 200
    event = response.json()["events"][0]
    assert event["event_type"] == "TELEMETRY"
    assert event["seq"] == 12
    assert event["pattern"] == "GPS_SPOOFING"
    assert event["trust_score"] == 0.4
    assert event["hem"]["hem_phase"] == "EVACUATE"


def test_untrusted_event_values_remain_json_strings(monkeypatch, tmp_path):
    client, log_file = _client(monkeypatch, tmp_path)
    log_file.write_text(
        json.dumps(_event(pattern="<img src=x onerror=alert(1)>")),
        encoding="utf-8",
    )
    response = client.get("/api/events")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["events"][0]["pattern"] == "<img src=x onerror=alert(1)>"
    report = client.get("/api/report", params={"format": "markdown"})
    assert report.status_code == 200
    assert "<img" not in report.json()["content"]
    assert "&lt;img" in report.json()["content"]


def test_mutations_require_api_key_and_scenario_start_is_cancellable(
    monkeypatch, tmp_path
):
    client, _ = _client(monkeypatch, tmp_path)
    assert client.post("/api/scenario", json={"scenario": "normal"}).status_code == 401
    assert (
        client.post(
            "/api/scenario",
            json={"scenario": "normal"},
            headers={"X-API-Key": "wrong"},
        ).status_code
        == 401
    )

    def fake_sender(name, stop_event):
        assert not stop_event.is_set()
        with server.scenario_lock:
            server.scenario_state.update(running=True, name=name, last_error=None)

    monkeypatch.setattr(server, "send_scenario", fake_sender)
    headers = {"X-API-Key": "test-dashboard-key"}
    malformed = client.post(
        "/api/scenario",
        content=b'{"scenario":',
        headers={"X-API-Key": "test-dashboard-key", "Content-Type": "application/json"},
    )
    assert malformed.status_code == 422
    started = client.post(
        "/api/scenarios/normal/start",
        headers=headers,
    )
    assert started.status_code == 200
    assert started.json()["accepted"] is True
    stopped = client.post("/api/scenarios/normal/stop", headers=headers)
    assert stopped.status_code == 200
    assert server.scenario_stop_event.is_set()
    with server.scenario_lock:
        server.scenario_state.update(running=False, name=None, last_error=None)
    server.scenario_stop_event.clear()


def test_missing_api_key_configuration_fails_closed(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(settings.dashboard, "api_key", SecretStr(""))
    response = client.post(
        "/api/scenario",
        json={"scenario": "normal"},
        headers={"X-API-Key": "test-dashboard-key"},
    )
    assert response.status_code == 503


def test_api_rate_limiter_rejects_excess_requests(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(settings.dashboard, "request_rate_limit_per_minute", 1)
    server.rate_limiter._sources.clear()
    assert client.get("/api/version").status_code == 200
    assert client.get("/api/version").status_code == 429


def test_stream_broker_bounds_clients_and_discards_old_queue_items(monkeypatch):
    monkeypatch.setattr(settings.dashboard, "event_stream_client_limit", 1)
    monkeypatch.setattr(settings.dashboard, "event_stream_queue_size", 1)
    server.event_broker.queues.clear()
    queue = server.event_broker.subscribe()
    assert queue is not None
    assert server.event_broker.subscribe() is None
    server.event_broker.publish(server.EventResponse(seq=1))
    server.event_broker.publish(server.EventResponse(seq=2))
    assert queue.get_nowait().seq == 2
    server.event_broker.unsubscribe(queue)


def test_request_size_limit(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(settings.dashboard, "max_request_size_bytes", 16)
    response = client.post(
        "/api/scenario",
        content=b'{"scenario":"normal"}',
        headers={
            "X-API-Key": "test-dashboard-key",
            "Content-Length": "128",
        },
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_sse_stream_delivers_event_and_heartbeat(monkeypatch, tmp_path):
    _, log_file = _client(monkeypatch, tmp_path)
    monkeypatch.setattr(settings.dashboard, "event_stream_heartbeat_seconds", 0.01)
    monkeypatch.setattr(settings.dashboard, "event_stream_queue_size", 4)
    server.event_broker.queues.clear()
    monkeypatch.setattr(settings.dashboard, "max_request_size_bytes", 65536)
    log_file.write_text(json.dumps(_event()), encoding="utf-8")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/stream",
        "raw_path": b"/api/stream",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    request = Request(scope, receive)

    async def connected():
        return False

    request.is_disconnected = connected
    response = await server.event_stream(request)
    iterator = response.body_iterator
    try:
        event = await asyncio.wait_for(anext(iterator), timeout=1)
        heartbeat = await asyncio.wait_for(anext(iterator), timeout=1)
    finally:
        await iterator.aclose()
    assert event.startswith("id: ")
    assert "event: telemetry" in event
    assert heartbeat == ": heartbeat\n\n"
