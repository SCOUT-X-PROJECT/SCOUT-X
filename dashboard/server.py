from datetime import datetime, timezone
import html
import json
import logging
import math
import socket
import threading
import time
import asyncio
from collections import OrderedDict, deque
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from hmac import compare_digest
from typing import Any, TypedDict
import urllib.error
import urllib.request

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from simulation.config import PROJECT_ROOT, settings
from simulation.security.telemetry_auth import TelemetryAuthenticator


BASE_DIR = PROJECT_ROOT
DASHBOARD_DIR = BASE_DIR / "dashboard"
LOG_FILE = BASE_DIR / settings.logging.directory / settings.logging.attack_log

RECEIVER_HOST = settings.dashboard.receiver_host or settings.network.host
RECEIVER_PORT = settings.network.udp_port
PACKET_DELAY = settings.dashboard.packet_delay_seconds

AIRCRAFT_API_URL = settings.dashboard.adsb_api_template.format(
    latitude=settings.dashboard.aircraft_center_latitude,
    longitude=settings.dashboard.aircraft_center_longitude,
    range=settings.dashboard.aircraft_range,
)

scenario_lock = threading.Lock()


class ScenarioState(TypedDict):
    running: bool
    name: str | None
    last_error: str | None


scenario_state: ScenarioState = {
    "running": False,
    "name": None,
    "last_error": None,
}
scenario_stop_event = threading.Event()
scenario_thread: threading.Thread | None = None
control_sequence_lock = threading.Lock()
control_sequence = 0


class EventResponse(BaseModel):
    """Expose only the stable, display-safe fields used by dashboard clients."""

    model_config = ConfigDict(extra="ignore")

    timestamp: str = Field(default="", max_length=128)
    correlation_id: str | None = Field(default=None, max_length=128)
    event_id: str | None = Field(default=None, max_length=64)
    event_type: str | None = Field(default=None, max_length=128)
    state: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)
    drone_id: str | None = Field(default=None, max_length=64)
    seq: int | None = None
    gps: list[float] | dict[str, float] | None = None
    altitude: float | None = None
    speed: float | None = None
    battery: float | None = None
    trust_score: float | None = None
    flagged: bool | None = None
    pattern: str = Field(default="UNKNOWN", max_length=128)
    severity: str = Field(default="LOW", max_length=32)
    flags: list[str] = Field(default_factory=list)
    ml_anomaly: bool = False
    ml_score: float | None = None
    response: str | None = Field(default=None, max_length=128)
    action: str | None = Field(default=None, max_length=128)
    enforced: bool | None = None
    hem_phase: str | None = Field(default=None, max_length=64)
    hem_destination: str | None = Field(default=None, max_length=128)
    hem_moved: int = 0
    hem_zeroized: bool = False
    items_lost_to_zeroize: int = 0
    hem: dict[str, Any] = Field(default_factory=dict)

    @field_validator("altitude", "speed", "battery", "trust_score", "ml_score")
    @classmethod
    def finite_measurements(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("measurements must be finite")
        return value

    @field_validator("gps")
    @classmethod
    def finite_gps(
        cls,
        value: list[float] | dict[str, float] | None,
    ) -> list[float] | dict[str, float] | None:
        coordinates = value.values() if isinstance(value, dict) else value or []
        if not all(math.isfinite(coordinate) for coordinate in coordinates):
            raise ValueError("GPS coordinates must be finite")
        return value


class EventPageResponse(BaseModel):
    count: int
    total: int
    offset: int
    limit: int
    has_more: bool
    events: list[EventResponse]


class LatestResponse(BaseModel):
    connected: bool
    event: EventResponse | None


class HealthResponse(BaseModel):
    status: str
    log_exists: bool


class VersionResponse(BaseModel):
    name: str
    version: str


class SessionResponse(BaseModel):
    authenticated: bool


class AircraftItem(BaseModel):
    hex: str | None = None
    flight: str = ""
    lat: float
    lon: float
    altitude: float | str | None = None
    speed: float | None = None
    track: float | None = None
    category: str | None = None
    source: str = "ADS-B"


class AircraftResponse(BaseModel):
    source: str
    count: int
    aircraft: list[AircraftItem]
    fetched_at: str


class ScenarioRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=64)


class ScenarioResponse(BaseModel):
    accepted: bool
    scenario: str
    message: str


class ScenarioStateResponse(BaseModel):
    running: bool
    name: str | None
    last_error: str | None


class StateResponse(BaseModel):
    connected: bool
    latest: EventResponse | None
    scenario: ScenarioStateResponse


class TelemetryResponse(BaseModel):
    event: EventResponse | None


class HemStatusResponse(BaseModel):
    phase: str | None
    destination: str | None
    moved: int
    zeroized: bool
    transfer_status: str | None


class MLStatusResponse(BaseModel):
    status: str
    anomaly: bool
    score: float | None


class ReportResponse(BaseModel):
    format: str
    content: str


class RateLimiter:
    """Bound per-source request state to keep dashboard abuse memory finite."""

    def __init__(self) -> None:
        self._sources: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, source: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        rate = settings.dashboard.request_rate_limit_per_minute / 60
        with self._lock:
            tokens, updated = self._sources.pop(
                source,
                (float(settings.dashboard.request_rate_limit_per_minute), current),
            )
            tokens = min(
                float(settings.dashboard.request_rate_limit_per_minute),
                tokens + (current - updated) * rate,
            )
            allowed = tokens >= 1
            if allowed:
                tokens -= 1
            self._sources[source] = (tokens, current)
            while len(self._sources) > settings.dashboard.request_rate_limit_sources:
                self._sources.popitem(last=False)
            return allowed


class EventBroker:
    """Fan out events without allowing a slow dashboard client to grow memory."""

    def __init__(self) -> None:
        self.queues: set[asyncio.Queue[EventResponse]] = set()

    def subscribe(self) -> asyncio.Queue[EventResponse] | None:
        if len(self.queues) >= settings.dashboard.event_stream_client_limit:
            return None
        queue: asyncio.Queue[EventResponse] = asyncio.Queue(
            maxsize=settings.dashboard.event_stream_queue_size
        )
        self.queues.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[EventResponse]) -> None:
        self.queues.discard(queue)

    def publish(self, event: EventResponse) -> None:
        for queue in tuple(self.queues):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(event)


event_broker = EventBroker()
rate_limiter = RateLimiter()
logger = logging.getLogger(__name__)


async def _watch_event_log() -> None:
    """Publish only newly tailed events while keeping each subscriber bounded."""
    seen: deque[str] = deque(maxlen=settings.dashboard.event_tail_limit)
    while True:
        try:
            for event in read_events():
                fingerprint = f"{event.timestamp}:{event.drone_id}:{event.seq}"
                if fingerprint not in seen:
                    seen.append(fingerprint)
                    event_broker.publish(event)
        except HTTPException as exc:
            logger.error("Dashboard event stream could not read log: %s", exc.detail)
        await asyncio.sleep(settings.dashboard.event_stream_poll_seconds)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    if (
        settings.dashboard.host not in {"127.0.0.1", "localhost", "::1"}
        and not settings.dashboard.public_bind
    ):
        raise RuntimeError(
            "Public dashboard binding requires SCOUTX_DASHBOARD__PUBLIC_BIND=true"
        )
    settings.initialize_runtime_secrets()
    watcher = asyncio.create_task(_watch_event_log())
    try:
        yield
    finally:
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="SCOUT-X Dashboard",
    version="development",
    openapi_tags=[
        {"name": "dashboard", "description": "Dashboard and health endpoints"},
        {"name": "telemetry", "description": "Bounded telemetry and event views"},
        {
            "name": "scenarios",
            "description": "Authenticated simulated scenario controls",
        },
        {"name": "reports", "description": "Bounded event report exports"},
    ],
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.dashboard.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def dashboard_security(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Bound request memory and abuse while applying browser security headers."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.dashboard.max_request_size_bytes:
                response: Response = JSONResponse(
                    {"detail": "Request body too large"},
                    status_code=413,
                )
                return _secure_response(response)
        except ValueError:
            response = JSONResponse(
                {"detail": "Invalid Content-Length"},
                status_code=400,
            )
            return _secure_response(response)
    if request.url.path.startswith("/api/"):
        source = request.client.host if request.client else "unknown"
        if not rate_limiter.allow(source):
            return _secure_response(
                JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
            )
        if request.url.path not in {
            "/api/health",
            "/api/version",
            "/api/session",
        }:
            if not settings.dashboard.api_key.get_secret_value():
                return _secure_response(
                    JSONResponse(
                        {"detail": "Dashboard API key is not configured"},
                        status_code=503,
                    )
                )
            if not _has_dashboard_read_auth(request):
                return _secure_response(
                    JSONResponse(
                        {"detail": "Dashboard API authentication is required"},
                        status_code=401,
                    )
                )
    original_receive = request._receive
    body = bytearray()
    more_body = True
    while more_body:
        message = await request.receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        if len(body) + len(chunk) > settings.dashboard.max_request_size_bytes:
            return _secure_response(
                JSONResponse({"detail": "Request body too large"}, status_code=413)
            )
        body.extend(chunk)
        more_body = message.get("more_body", False)
    buffered_body = bytes(body)
    replayed = False

    async def receive_with_body() -> dict[str, Any]:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {
                "type": "http.request",
                "body": buffered_body,
                "more_body": False,
            }
        return dict(await original_receive())

    request._receive = receive_with_body
    response = await call_next(request)
    return _secure_response(response)


def _secure_response(response: Response) -> Response:
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://unpkg.com 'unsafe-inline'; img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


def _has_dashboard_read_auth(request: Request) -> bool:
    configured = settings.dashboard.api_key.get_secret_value()
    if not configured:
        return False
    header_key = request.headers.get("x-api-key")
    cookie_key = request.cookies.get("scoutx_session")
    return any(
        candidate is not None and compare_digest(candidate, configured)
        for candidate in (header_key, cookie_key)
    )


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Fail closed for mutations unless an operator configured a dashboard key."""
    configured = settings.dashboard.api_key.get_secret_value()
    if not configured:
        raise HTTPException(
            status_code=503, detail="Dashboard API key is not configured"
        )
    if x_api_key is None or not compare_digest(x_api_key, configured):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "dashboard.server:app",
        host=settings.dashboard.host,
        port=settings.dashboard.port,
        reload=settings.dashboard.reload,
    )


def read_events() -> list[EventResponse]:
    """Read only a bounded log tail so event queries cannot consume unbounded memory."""
    if not LOG_FILE.exists():
        return []
    try:
        with LOG_FILE.open("rb") as file:
            file.seek(0, 2)
            end = file.tell()
            start = max(0, end - settings.dashboard.event_tail_bytes)
            file.seek(start)
            raw = file.read(settings.dashboard.event_tail_bytes)
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Event log is unavailable") from exc
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if start:
        lines = lines[1:]
    events: deque[EventResponse] = deque(maxlen=settings.dashboard.event_tail_limit)
    for line in lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                details = parsed.get("details")
                if isinstance(details, dict):
                    normalized = {
                        **details,
                        "timestamp": parsed.get("timestamp", ""),
                        "correlation_id": details.get("correlation_id"),
                        "event_id": parsed.get("event_id"),
                        "event_type": parsed.get("event_type"),
                        "drone_id": parsed.get("drone_id"),
                        "state": parsed.get("state"),
                        "details": details,
                    }
                    if not isinstance(normalized.get("pattern"), str):
                        normalized["pattern"] = parsed.get("event_type", "UNKNOWN")
                    if isinstance(normalized.get("enforced"), str):
                        normalized["enforced"] = normalized["enforced"] not in {
                            "",
                            "NONE",
                            "FALSE",
                        }
                    normalized.setdefault("trust_score", parsed.get("trust"))
                    normalized.setdefault(
                        "pattern",
                        parsed.get("event_type", "UNKNOWN"),
                    )
                    normalized.setdefault("severity", parsed.get("severity", "LOW"))
                    normalized.setdefault("trust_state", parsed.get("state"))
                    events.append(EventResponse.model_validate(normalized))
                else:
                    events.append(EventResponse.model_validate(parsed))
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
    return list(events)


def _utc(value: datetime) -> datetime:
    """Normalize query timestamps before comparing log records."""
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _event_time(event: EventResponse) -> datetime | None:
    """Parse log timestamps defensively because old records may predate UTC ISO format."""
    try:
        parsed = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _utc(parsed)


def next_sequence() -> int:
    """Avoid reusing sequence identifiers when dashboard scenarios restart."""
    highest = 0

    for event in read_events():
        if event.drone_id != settings.dashboard.drone_id:
            continue
        try:
            highest = max(highest, int(event.seq or 0))
        except (TypeError, ValueError):
            continue

    return highest + 1


def next_control_sequence() -> int:
    """Keep control replay counters independent from telemetry sequence numbering."""
    global control_sequence
    with control_sequence_lock:
        control_sequence = max(control_sequence + 1, time.monotonic_ns())
        return control_sequence


def normal_packet(
    seq: int,
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Generate clean control traffic so scenario paths share the receiver pipeline."""
    dashboard = settings.dashboard
    sequence_modulus = dashboard.scenario_speed_sequence_modulus
    complete_cycles, remaining_steps = divmod(seq, sequence_modulus)
    remainder_speed = remaining_steps * (remaining_steps + 1) / 2
    cycle_speed = sequence_modulus * (sequence_modulus - 1) / 2
    distance_m = (
        dashboard.scenario_speed_base * seq
        + complete_cycles * cycle_speed
        + remainder_speed
    ) * settings.dashboard.packet_delay_seconds
    return {
        "drone_id": dashboard.drone_id,
        "sequence": seq,
        "timestamp": time.time() if timestamp is None else timestamp,
        "lat": dashboard.aircraft_center_latitude
        + math.degrees(distance_m / settings.validation.earth_radius_meters),
        "lon": dashboard.aircraft_center_longitude,
        "altitude": min(
            settings.validation.max_altitude,
            dashboard.scenario_altitude_base
            + (seq % dashboard.scenario_altitude_sequence_modulus),
        ),
        "speed": dashboard.scenario_speed_base
        + (seq % dashboard.scenario_speed_sequence_modulus),
        "battery": max(
            dashboard.scenario_battery_floor,
            dashboard.scenario_battery_base
            - seq * settings.validation.battery_drain_minimum,
        ),
    }


def attack_packet(
    seq: int,
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Generate explicit attack samples so dashboard scenarios are reproducible."""
    dashboard = settings.dashboard
    return {
        "drone_id": dashboard.drone_id,
        "sequence": seq,
        "timestamp": time.time() if timestamp is None else timestamp,
        "lat": dashboard.scenario_coordinate_latitude,
        "lon": dashboard.scenario_coordinate_longitude,
        "altitude": dashboard.scenario_attack_altitude,
        "speed": dashboard.scenario_attack_speed,
        "battery": dashboard.scenario_attack_battery,
    }


def build_scenario(scenario: str, start_seq: int) -> list[dict[str, Any]]:
    """Centralize scenario construction so API callers cannot drift in packet shape."""
    scenario_start_time = time.time()
    if scenario == "normal":
        return [
            normal_packet(start_seq + i, scenario_start_time + i * PACKET_DELAY)
            for i in range(settings.dashboard.normal_scenario_packet_count)
        ]

    if scenario == "gps_spoofing":
        trust_values = settings.dashboard.normal_scenario_trust

    elif scenario == "command_injection":
        trust_values = settings.dashboard.command_scenario_trust

    elif scenario == "critical":
        trust_values = settings.dashboard.critical_scenario_trust

    else:
        raise ValueError("Unsupported scenario")

    return [
        attack_packet(
            start_seq + i,
            scenario_start_time + i * PACKET_DELAY,
        )
        for i in range(len(trust_values))
    ]


def send_scenario(scenario: str, stop_event: threading.Event) -> None:
    """Send a cancellable scenario so a stop request ends work at packet boundaries."""
    authenticator: TelemetryAuthenticator | None = None
    try:
        start_sequence = next_sequence()
        packets = build_scenario(scenario, start_sequence)
        authenticator = TelemetryAuthenticator.from_settings()

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            control_message = {
                "_scoutx_control": "scenario_start",
                "scenario": scenario,
                "drone_id": settings.dashboard.drone_id,
                "sequence": next_control_sequence(),
                "timestamp": time.time(),
            }

            sock.sendto(
                authenticator.encode_packet(control_message),
                (RECEIVER_HOST, RECEIVER_PORT),
            )

            # Allow the receiver to process the reset first.
            if not stop_event.wait(settings.dashboard.reset_wait_seconds):
                for packet in packets:
                    if stop_event.is_set():
                        break
                    sock.sendto(
                        authenticator.encode_packet(packet),
                        (RECEIVER_HOST, RECEIVER_PORT),
                    )
                    if stop_event.wait(PACKET_DELAY):
                        break

            end_sequence = next_control_sequence()
            completion = {
                "_scoutx_control": "scenario_end",
                "drone_id": settings.dashboard.drone_id,
                "sequence": end_sequence,
                "timestamp": time.time(),
            }
            sock.sendto(
                authenticator.encode_packet(completion),
                (RECEIVER_HOST, RECEIVER_PORT),
            )
            sock.settimeout(settings.dashboard.scenario_ack_timeout_seconds)
            frame, _ = sock.recvfrom(settings.network.max_datagram_size_bytes)
            ack_sequence, ack_payload = authenticator.decode_frame(frame)
            acknowledgement = json.loads(ack_payload.decode("utf-8"))
            ack_timestamp = (
                float(acknowledgement["timestamp"])
                if isinstance(acknowledgement, dict)
                and isinstance(acknowledgement.get("timestamp"), (int, float))
                and not isinstance(acknowledgement.get("timestamp"), bool)
                else None
            )
            if (
                ack_sequence != end_sequence
                or not isinstance(acknowledgement, dict)
                or acknowledgement.get("_scoutx_control_ack") != "scenario_end"
                or type(acknowledgement.get("sequence")) is not int
                or acknowledgement.get("sequence") != end_sequence
                or acknowledgement.get("drone_id") != settings.network.drone_id
                or ack_timestamp is None
                or not math.isfinite(ack_timestamp)
                or abs(time.time() - ack_timestamp)
                > settings.validation.stale_timestamp_skew_seconds
            ):
                raise RuntimeError(
                    "Receiver returned an invalid scenario completion ACK"
                )

    except Exception as exc:
        with scenario_lock:
            scenario_state["last_error"] = str(exc)

    finally:
        if authenticator is not None:
            authenticator.close()
        with scenario_lock:
            scenario_state["running"] = False
            scenario_state["name"] = None


@app.get("/")
@app.get("/dashboard/index.html")
def dashboard() -> HTMLResponse:
    """Inject validated settings so the browser uses the same policy as the server."""
    dashboard_config: dict[str, Any] = dict(settings.dashboard.model_dump(mode="json"))
    dashboard_config.pop("api_key", None)
    dashboard_config.update(
        {
            "critical_trust_threshold": settings.trust.protect_threshold,
            "warning_trust_threshold": settings.trust.warning_threshold,
            "protect_threshold": settings.trust.protect_threshold,
            "evacuate_threshold": settings.trust.evacuate_threshold,
            "prepare_threshold": settings.trust.prepare_threshold,
            "standby_threshold": settings.trust.standby_threshold,
        }
    )
    config_json = html.escape(
        json.dumps(dashboard_config, separators=(",", ":")),
        quote=True,
    )
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    html = html.replace(
        '<meta id="scoutx-config" name="scoutx-config" content="{}">',
        f'<meta id="scoutx-config" name="scoutx-config" content="{config_json}">',
    )
    return HTMLResponse(
        content=html,
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://unpkg.com; "
                "style-src 'self' https://unpkg.com; "
                "img-src 'self' data: https://*.tile.openstreetmap.org; "
                "connect-src 'self'"
            )
        },
    )


@app.get(
    "/api/events",
    response_model=EventPageResponse,
    tags=["telemetry"],
)
def get_events(
    severity: str | None = Query(default=None, max_length=32),
    attack_type: str | None = Query(default=None, max_length=64),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=40, ge=1),
) -> EventPageResponse:
    """Return a paginated, filtered view of a bounded event-log tail."""
    if limit > settings.dashboard.event_page_limit:
        raise HTTPException(
            status_code=422,
            detail=f"limit must be at most {settings.dashboard.event_page_limit}",
        )
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=422, detail="start_time must not exceed end_time"
        )
    events = read_events()
    filtered: list[EventResponse] = []
    for event in events:
        timestamp = _event_time(event)
        if severity and event.severity.casefold() != severity.casefold():
            continue
        if attack_type and event.pattern.casefold() != attack_type.casefold():
            continue
        if start_time and (timestamp is None or timestamp < _utc(start_time)):
            continue
        if end_time and (timestamp is None or timestamp > _utc(end_time)):
            continue
        filtered.append(event)
    page = filtered[offset : offset + limit]
    return EventPageResponse(
        count=len(page),
        total=len(filtered),
        offset=offset,
        limit=limit,
        has_more=offset + len(page) < len(filtered),
        events=page,
    )


@app.get("/api/latest", response_model=LatestResponse, tags=["telemetry"])
def get_latest() -> LatestResponse:
    """Expose the newest event without returning unvalidated log dictionaries."""
    events = read_events()
    return LatestResponse(connected=bool(events), event=events[-1] if events else None)


@app.get("/health", response_model=HealthResponse, tags=["dashboard"])
@app.get("/api/health", response_model=HealthResponse, tags=["dashboard"])
def health() -> HealthResponse:
    """Provide a minimal health signal that does not reveal filesystem paths."""
    return HealthResponse(status="healthy", log_exists=LOG_FILE.exists())


@app.get("/api/version", response_model=VersionResponse, tags=["dashboard"])
def version() -> VersionResponse:
    """Expose the deployed dashboard build identity."""
    return VersionResponse(name="SCOUT-X Dashboard", version=app.version)


@app.post(
    "/api/session",
    response_model=SessionResponse,
    tags=["dashboard"],
)
def create_dashboard_session(
    request: Request,
    response: Response,
    _: None = Depends(require_api_key),
) -> SessionResponse:
    """Exchange the configured key for an HttpOnly cookie so EventSource can authenticate."""
    response.set_cookie(
        "scoutx_session",
        settings.dashboard.api_key.get_secret_value(),
        max_age=settings.dashboard.session_cookie_max_age_seconds,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return SessionResponse(authenticated=True)


@app.get("/api/aircraft", response_model=AircraftResponse, tags=["dashboard"])
def get_live_aircraft() -> AircraftResponse:
    """Fetch real aircraft visible in the public ADS-B feed."""
    request = urllib.request.Request(
        AIRCRAFT_API_URL,
        headers={"User-Agent": "SCOUT-X-Dashboard/1.0"},
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=settings.dashboard.aircraft_request_timeout_seconds,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))

    except (urllib.error.URLError, TimeoutError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Live aircraft feed unavailable: {exc}",
        ) from exc

    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Invalid response from the live aircraft feed.",
        ) from exc

    aircraft: list[AircraftItem] = []

    for item in payload.get("ac", []):
        lat = item.get("lat")
        lon = item.get("lon")

        if lat is None or lon is None:
            continue

        try:
            aircraft.append(
                AircraftItem(
                    hex=str(item.get("hex")) if item.get("hex") is not None else None,
                    flight=str(item.get("flight") or "").strip(),
                    lat=float(lat),
                    lon=float(lon),
                    altitude=item.get("alt_baro"),
                    speed=float(item["gs"]) if item.get("gs") is not None else None,
                    track=float(item["track"])
                    if item.get("track") is not None
                    else None,
                    category=str(item.get("category"))
                    if item.get("category") is not None
                    else None,
                )
            )
        except (TypeError, ValueError):
            continue

    return AircraftResponse(
        source="adsb.lol",
        count=len(aircraft),
        aircraft=aircraft,
        fetched_at=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/api/state", response_model=StateResponse, tags=["telemetry"])
def get_state() -> StateResponse:
    """Provide one consistent summary for the current receiver and scenario state."""
    latest = get_latest()
    return StateResponse(
        connected=latest.connected,
        latest=latest.event,
        scenario=get_scenario_status(),
    )


@app.get("/api/telemetry", response_model=TelemetryResponse, tags=["telemetry"])
def get_telemetry() -> TelemetryResponse:
    """Return the latest validated telemetry event."""
    return TelemetryResponse(event=get_latest().event)


@app.get("/api/hem", response_model=HemStatusResponse, tags=["telemetry"])
def get_hem_status() -> HemStatusResponse:
    """Return bounded HEM status fields from the latest enriched event."""
    event = get_latest().event
    return HemStatusResponse(
        phase=event.hem_phase if event else None,
        destination=event.hem_destination if event else None,
        moved=event.hem_moved if event else 0,
        zeroized=event.hem_zeroized if event else False,
        transfer_status=str(event.hem.get("transfer_status"))
        if event and event.hem.get("transfer_status") is not None
        else None,
    )


@app.get("/api/ml", response_model=MLStatusResponse, tags=["telemetry"])
def get_ml_status() -> MLStatusResponse:
    """Return the latest secondary ML signal without elevating it into policy."""
    event = get_latest().event
    return MLStatusResponse(
        status="ready" if event is not None else "model_not_ready",
        anomaly=event.ml_anomaly if event else False,
        score=event.ml_score if event else None,
    )


@app.get("/api/stream", tags=["telemetry"])
async def event_stream(request: Request) -> StreamingResponse:
    """Stream updates with heartbeat and a bounded queue per connected client."""
    queue = event_broker.subscribe()
    if queue is None:
        raise HTTPException(status_code=503, detail="Event stream capacity reached")

    async def stream():
        try:
            latest = read_events()
            if latest:
                queue.put_nowait(latest[-1])
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(
                        queue.get(),
                        timeout=settings.dashboard.event_stream_heartbeat_seconds,
                    )
                    payload = event.model_dump_json()
                    event_id = f"{event.timestamp}-{event.seq or 0}"
                    yield f"id: {event_id}\nevent: telemetry\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            event_broker.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get(
    "/api/scenario/status", response_model=ScenarioStateResponse, tags=["scenarios"]
)
def get_scenario_status() -> ScenarioStateResponse:
    """Expose synchronized scenario state so clients can avoid duplicate launches."""
    with scenario_lock:
        return ScenarioStateResponse.model_validate(scenario_state)


def _start_scenario(scenario: str) -> ScenarioResponse:
    global scenario_thread
    allowed_scenarios = {
        "normal",
        "gps_spoofing",
        "command_injection",
        "critical",
    }
    if scenario not in allowed_scenarios:
        raise HTTPException(status_code=400, detail="Unknown scenario")
    with scenario_lock:
        if scenario_state["running"]:
            raise HTTPException(status_code=409, detail="A scenario is already running")
        scenario_stop_event.clear()
        scenario_state["running"] = True
        scenario_state["name"] = scenario
        scenario_state["last_error"] = None
        scenario_thread = threading.Thread(
            target=send_scenario,
            args=(scenario, scenario_stop_event),
            name=f"scoutx-scenario-{scenario}",
            daemon=True,
        )
        scenario_thread.start()
    return ScenarioResponse(
        accepted=True,
        scenario=scenario,
        message="Simulated telemetry sent to the SCOUT-X receiver.",
    )


@app.post("/api/scenario", response_model=ScenarioResponse, tags=["scenarios"])
def launch_scenario(
    request: ScenarioRequest,
    _: None = Depends(require_api_key),
) -> ScenarioResponse:
    """Retain the original path while requiring operator authorization."""
    return _start_scenario(request.scenario)


@app.post(
    "/api/scenarios/{scenario_name}/start",
    response_model=ScenarioResponse,
    tags=["scenarios"],
)
def start_named_scenario(
    scenario_name: str,
    _: None = Depends(require_api_key),
) -> ScenarioResponse:
    """Start a named simulation scenario through the shared serialized runner."""
    return _start_scenario(scenario_name)


@app.post(
    "/api/scenarios/{scenario_name}/stop",
    response_model=ScenarioStateResponse,
    tags=["scenarios"],
)
def stop_named_scenario(
    scenario_name: str,
    _: None = Depends(require_api_key),
) -> ScenarioStateResponse:
    """Request cancellation without restarting or interleaving scenario packets."""
    with scenario_lock:
        if not scenario_state["running"] or scenario_state["name"] != scenario_name:
            raise HTTPException(status_code=409, detail="That scenario is not running")
        scenario_stop_event.set()
        return ScenarioStateResponse.model_validate(scenario_state)


@app.post(
    "/api/protect/reset",
    response_model=ScenarioResponse,
    tags=["scenarios"],
)
def reset_protect(_: None = Depends(require_api_key)) -> ScenarioResponse:
    """Send a signed reset command; the receiver independently validates its token."""
    reset_token = settings.trust.reset_token.get_secret_value()
    if not reset_token:
        raise HTTPException(
            status_code=503, detail="Trust reset token is not configured"
        )
    authenticator: TelemetryAuthenticator | None = None
    try:
        authenticator = TelemetryAuthenticator.from_settings()
        command = {
            "_scoutx_control": "protect_reset",
            "reset_token": reset_token,
            "drone_id": settings.dashboard.drone_id,
            "sequence": next_control_sequence(),
            "timestamp": time.time(),
        }
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(
                authenticator.encode_packet(command),
                (RECEIVER_HOST, RECEIVER_PORT),
            )
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=502, detail="Unable to send reset command"
        ) from exc
    finally:
        if authenticator is not None:
            authenticator.close()
    return ScenarioResponse(
        accepted=True,
        scenario="protect_reset",
        message="Authenticated PROTECT reset command submitted.",
    )


@app.get("/api/report", response_model=ReportResponse, tags=["reports"])
def export_report(
    format: str = Query(default="json", pattern="^(json|markdown)$"),
) -> ReportResponse:
    """Export a bounded event tail in JSON or Markdown without reading full logs."""
    events = read_events()
    if format == "json":
        content = json.dumps(
            [event.model_dump(mode="json") for event in events], indent=2
        )
    else:
        lines = [
            "# SCOUT-X Simulation Event Report",
            "",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
            "| Timestamp | Sequence | Pattern | Severity | Trust | Response |",
            "|---|---:|---|---|---:|---|",
        ]
        lines.extend(
            "| {timestamp} | {seq} | {pattern} | {severity} | {trust} | {response} |".format(
                timestamp=_markdown_cell(event.timestamp),
                seq=event.seq if event.seq is not None else "",
                pattern=_markdown_cell(event.pattern),
                severity=_markdown_cell(event.severity),
                trust=event.trust_score if event.trust_score is not None else "",
                response=_markdown_cell(event.response or ""),
            )
            for event in events
        )
        content = "\n".join(lines)
    return ReportResponse(format=format, content=content)


def _markdown_cell(value: str) -> str:
    """Prevent untrusted event strings from adding cells or rows to a report."""
    single_line = value.replace("\r", " ").replace("\n", " ")
    return html.escape(single_line, quote=False).replace("|", "&#124;")


app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_DIR),
    name="dashboard",
)
