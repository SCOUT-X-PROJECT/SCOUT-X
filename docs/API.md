# Dashboard and telemetry API

The default dashboard base URL is `http://127.0.0.1:8000`. FastAPI's generated
OpenAPI UI is available at `/docs`; the API is intended for local simulation.
Health and version endpoints are public. Sensitive reads, event streaming,
reports, and mutations require the configured dashboard API key. The browser
exchanges the key for a short-lived HttpOnly session cookie so native
EventSource can authenticate.

## HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` or `/dashboard/index.html` | Serve the dashboard page. |
| `GET` | `/health` or `/api/health` | Health response: `status` and whether the configured log file exists. |
| `GET` | `/api/version` | Dashboard name and version. |
| `POST` | `/api/session` | Exchange `X-API-Key` for a short-lived HttpOnly read-session cookie. |
| `GET` | `/api/state` | Connection/latest event and current dashboard scenario status. |
| `GET` | `/api/latest` | Whether a recent event exists and the latest event. |
| `GET` | `/api/telemetry` | Latest event telemetry. |
| `GET` | `/api/hem` | HEM phase, destination, moved count, zeroization, and transfer status. |
| `GET` | `/api/ml` | Latest ML status, anomaly boolean, and optional risk score. |
| `GET` | `/api/events` | Bounded event tail with filters and pagination. |
| `GET` | `/api/stream` | Server-Sent Events (`text/event-stream`) with heartbeat. |
| `GET` | `/api/scenario/status` | Current named scenario state. |
| `GET` | `/api/aircraft` | Optional external aircraft data from `adsb.lol`; requires internet. |
| `GET` | `/api/report?format=json\|markdown` | Export a bounded event tail as JSON or Markdown. |
| `POST` | `/api/scenario` | Start a named scenario using JSON `{"scenario":"normal"}`. Requires `X-API-Key`. |
| `POST` | `/api/scenarios/{scenario_name}/start` | Start one of `normal`, `gps_spoofing`, `command_injection`, `critical`. Requires `X-API-Key`; completion waits for a signed receiver acknowledgment after prior queued packets finish. |
| `POST` | `/api/scenarios/{scenario_name}/stop` | Request stop for the matching active dashboard scenario. Requires `X-API-Key`. |
| `POST` | `/api/protect/reset` | Send an authenticated reset control; requires API key and configured receiver reset token. |

The event route accepts:

| Query parameter | Type | Meaning |
|---|---|---|
| `severity` | string | Case-insensitive exact severity filter. |
| `attack_type` | string | Case-insensitive exact pattern filter. |
| `start_time` / `end_time` | ISO-8601 datetime | Inclusive time bounds; `start_time` cannot be later than `end_time`. |
| `offset` | integer, default `0` | Number of filtered events to skip. |
| `limit` | integer, default `40` | Page size; maximum is `SCOUTX_DASHBOARD__EVENT_PAGE_LIMIT` (default `100`). |

`/api/events` reads only a bounded byte/event tail from the configured log
files; `total` is the count in that bounded and filtered view, not necessarily
the lifetime event count.

### Event shape

Event responses expose a bounded set of fields; absent values may be `null` or
empty/default values:

```json
{
  "timestamp": "2026-01-01T12:00:00+00:00",
  "event_id": "optional-id",
  "event_type": "telemetry",
  "state": "STANDBY",
  "drone_id": "scout-x-01",
  "seq": 1,
  "gps": {"lat": 12.97, "lon": 77.59},
  "altitude": 10.0,
  "speed": 5.0,
  "battery": 99.9,
  "trust_score": 1.0,
  "pattern": "UNKNOWN",
  "severity": "LOW",
  "ml_anomaly": false,
  "ml_score": null,
  "response": "NORMAL_OPERATION",
  "hem_phase": "STANDBY",
  "hem": {}
}
```

The precise event can contain optional HEM and validation details; clients
should ignore unknown response fields. The server validates/filters event
records into Pydantic response models before returning them.

## Telemetry packet contract

After frame authentication, the payload is UTF-8 JSON with exactly these
required fields. Unknown fields are rejected. Numeric measurements must be
finite JSON numbers; `sequence` must be a non-negative integer.

| Field | Type | Constraints |
|---|---|---|
| `drone_id` | string | Required, non-empty, configured maximum length (default 64). |
| `sequence` | integer | Required; `0` through configured maximum (default signed 64-bit max). Strict integer; booleans are not accepted as integers. |
| `timestamp` | floating-point JSON number | Required finite Unix timestamp greater than zero; must be within configured skew of receiver wall clock (default 60 seconds). |
| `lat` | floating-point JSON number | Required finite latitude in `[-90, 90]`. |
| `lon` | floating-point JSON number | Required finite longitude in `[-180, 180]`. |
| `altitude` | floating-point JSON number | Required finite configured range; default `0` through `100`. |
| `speed` | floating-point JSON number | Required finite configured range; default `0` through `120`. |
| `battery` | floating-point JSON number | Required finite percentage; default `0` through `100`. |
| `heading` | floating-point JSON number or `null` | Optional; if present, finite and `0 <= heading < 360`. |

Payload size defaults to 2048 bytes. The UDP frame has a binary prefix
(`SXTP` magic, protocol version, unsigned 64-bit sequence), a 32-byte
HMAC-SHA256 tag, and the JSON payload. The sequence in the signed header must
match the sequence in JSON. The MAC is computed over a protocol domain label,
header, and payload. Senders should use
`TelemetryAuthenticator.encode_packet()` rather than sending raw JSON.

Example payload before framing:

Use the current Unix time for `timestamp` when sending; the number below is
illustrative and will become stale.

```json
{
  "drone_id": "scout-x-01",
  "sequence": 1,
  "timestamp": 1762000000.0,
  "lat": 12.9716,
  "lon": 77.5946,
  "altitude": 10.0,
  "speed": 5.0,
  "battery": 99.9,
  "heading": 90.0
}
```

The receiver returns structured validation events with reason codes such as
`invalid_schema`, `stale_timestamp`, `sequence_duplicate`, `gps_jump`,
`gps_speed_mismatch`, and `telemetry_flooding`. Rejected packets do not enter
the normal analysis/HEM path. Telemetry `drone_id` must match the configured
network or dashboard ID; signed control commands use the configured dashboard
ID.

## Security and operational notes

- The same private, random `SCOUTX_NETWORK__TELEMETRY_SHARED_SECRET` must be
  configured by sender and receiver. Keep it out of source control and logs.
- Use `X-API-Key: <configured-value>` for scenario start/stop and reset routes.
- Sensitive reads accept the same key as `X-API-Key` or the HttpOnly cookie
  returned by `POST /api/session`; mutations still require the header.
- `/health`, `/api/health`, and `/api/version` are public and intentionally
  reveal only basic service status/build identity.
- CORS, body size, per-source HTTP rate, event-tail, stream queue, and stream
  client bounds are configurable under `SCOUTX_DASHBOARD__...`.
- Dashboard scenario coordination and SSE subscriptions are process-local.
  Run one dashboard worker; scenario completion is not reported until the
  receiver returns its signed queue-drain acknowledgment.
- These routes run a local simulation. The API does not provide production
  user accounts, roles, or real flight-control capability.
