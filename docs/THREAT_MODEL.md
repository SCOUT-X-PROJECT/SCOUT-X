# SCOUT-X threat model

## Scope and purpose

SCOUT-X is a local cybersecurity simulation and research prototype. It models
telemetry intake, trust scoring, response selection, and mission-data handling.
It is not a real UAV communication system, flight controller, safety device,
or hardware security boundary.

## Assets

| Asset | Why it matters |
|---|---|
| Telemetry integrity and freshness | Incorrect packets can create false trust, false alerts, or misleading state transitions. |
| Trust score, state, and transition history | These drive simulated escalation and should not be silently manipulated. |
| In-memory simulated mission data | HEM tests confidentiality/integrity behavior for data chunks. |
| HMAC, HEM, TOTP, API, and reset secrets | Disclosure can allow frame forgery or unauthorized local simulation controls. |
| Event logs and integrity sidecars | They support local review of simulated decisions. |
| Dashboard event output | Untrusted logged strings must not become executable browser content. |
| Receiver availability and bounded resources | Floods should not cause unbounded queue/cache/log growth or kill the receive loop. |

## Attacker capabilities in the model

The tests and scenarios model an attacker who can supply malformed, stale,
duplicated, reordered, physically inconsistent, replayed, forged, or high-rate
telemetry datagrams to the local UDP receiver. Scenario inputs can introduce GPS
jumps/drift, battery anomalies, altitude/speed inconsistencies, replay,
flooding, intermittent attacks, and combinations of attacks. The simulated HEM
transport can inject packet loss and tampering.

The model assumes attackers do not already possess the configured telemetry
shared secret, dashboard API key, or PROTECT reset token. It does not model a
compromised host, compromised Python process, dependency, or operator account.

## Attacks and controls covered

| Threat | Implemented response |
|---|---|
| Forged telemetry frames | HMAC-SHA256 is checked over a versioned frame header, sequence number, and payload before JSON parsing. The MAC key is derived from a configured shared secret using HKDF. |
| Oversized or malformed telemetry | Datagram and payload limits; strict Pydantic schema; unknown fields, wrong types, NaN/infinity, and out-of-range values are rejected with structured results. |
| Replay, duplicate, stale, and reordered packets | Sequence and timestamp checks plus bounded per-drone history, a bounded persistent cache of accepted authenticated frame digests, and freshness checks on signed controls. Telemetry/control identities are limited to configured IDs. |
| Implausible consecutive movement/sensor changes | Haversine-based position checks, reported/implied speed comparison, altitude-rate checks, battery monotonicity tolerance, and timestamp ordering. |
| Source flood / slow processing | Per-source token buckets, datagram limits, bounded asyncio queue, worker separation, bounded event/cache structures, and structured flood reporting. |
| Trust oscillation or single low score recovery | Explicit trust state transitions, configured hysteresis, consecutive clean-packet recovery, bounded trust updates, and latched PROTECT state. |
| HEM ciphertext/context changes | AES-256-GCM with random 96-bit nonces and contextual AAD; HKDF-derived keys separated by purpose; authenticated manifest checks chunk identities/order/hashes. |
| Simulated packet loss and tampering | Seedable fault injection, retry/ACK tracking, priority order, transfer budget, and per-class terminal status. These are unit-level transport behaviors, not a radio protocol. |
| Dashboard injection in event values | API response models and DOM rendering that uses safe text/DOM APIs rather than interpolating event values as HTML. |
| Local log edits | JSONL hash chaining and verification detect some changes to retained logs if local integrity metadata is preserved. |

## Attacks not covered

- A hostile or compromised operating system, Python interpreter, process,
  dependency, filesystem administrator, or CI runner.
- Theft or misuse of shared secrets, API keys, reset tokens, or host environment.
- Key rotation, device-specific credentials, certificate validation, remote key
  exchange, secure enrollment, or non-repudiation.
- Cryptographic side channels, physical attacks, secure boot, or hardware
  security modules.
- Availability against distributed or network-scale denial-of-service attacks;
  configured per-source limits are not a complete network defense.
- A production-grade browser identity, role, or account model. Sensitive
  dashboard routes use one configured API key, exchanged for a short-lived
  HttpOnly, SameSite cookie to support EventSource; this is not multi-user
  authentication or a substitute for deployment-level access controls.
- Independent remote HEM peers or base stations. The handoff spool is in-memory
  simulation state shared by `SimTransport`.
- Real flight dynamics, collision avoidance, radio behavior, flight-control
  commands, or safety guarantees.
- Security of the older TCP examples. They are separate demonstrations and do
  not inherit the UDP receiver's framing/authentication behavior.

## Trust assumptions

1. The host and process are controlled by the local operator.
2. The receiver and telemetry sender share the same private
   `SCOUTX_NETWORK__TELEMETRY_SHARED_SECRET`; the secret is not available to the
   simulated attacker.
3. Dashboard operators protect `SCOUTX_DASHBOARD__API_KEY` and, for reset,
   `SCOUTX_TRUST__RESET_TOKEN`.
4. System wall-clock time is sufficiently correct for timestamp freshness and
   TOTP windows. A wrong clock can cause valid traffic to be rejected or alter
   event times.
5. Local log files and integrity metadata are kept together and are not
   rewritten by an attacker with filesystem access.
6. External map tiles and the optional `adsb.lol` feed are outside the
   application's trust boundary and are not needed for the local simulation.

## Cryptographic and memory limitations

### Shared-secret telemetry HMAC

The UDP framing key is derived with HKDF-SHA256 from one configured shared
secret and a fixed protocol purpose label. The frame MAC covers the versioned
header (including sequence) and the complete payload; verification precedes
JSON parsing. This demonstrates message authentication for a local simulation,
not per-device identity, secrecy, forward secrecy, rotation, or protection
after the shared secret is compromised. Every sender with the shared secret can
produce accepted frames for a configured drone identity. Accepted frame
digests are retained in a bounded SQLite cache so identical captured frames
remain rejected after receiver restart. Control commands also require a fresh
timestamp.

### Dashboard access

Sensitive read routes, reports, and the event stream require the configured
dashboard API key. The browser exchanges that key for a short-lived HttpOnly
cookie because native EventSource cannot attach arbitrary headers. Mutations
still require the API key header directly. Health and version remain public.
This single-key session model does not provide user accounts, roles, or
revocation tracking.

### Simulated destination proof

The HEM controller issues a random destination-bound challenge and verifies a
TOTP/HMAC proof returned by the `SimTransport` endpoint before deriving session
keys. Replayed proofs and proofs for a different challenge are rejected. The
simulated endpoint still runs in the same process and shares the configured
secret; this is not independent remote authentication or a real radio
handshake.

### HEM cryptography and transport

HEM uses AES-256-GCM, per-encryption random 96-bit nonces, contextual AAD, and
purpose-separated HKDF session keys. The transport, base, peer selection, and
handoff spool are simulated in process. There is no remote handshake, radio
protocol, independently authenticated peer endpoint, or durable key
provisioning. Random nonces make collisions very unlikely at the intended
simulation volume; they are probabilistic, not a formal never-repeat guarantee.

### TOTP and replay

The standalone TOTP helpers implement RFC 6238-style time-based codes, bounded
drift checking, constant-time comparison, and process-local same-window replay
tracking. Replay state is lost on restart. A demo secret is supplied via
configuration; this is not a production MFA enrollment or identity service.

### Zeroization

HEM removes the vault's direct plaintext reference after sealing and uses a
temporary mutable buffer for transfer, then overwrites that buffer. It also
overwrites selected owned `bytearray` buffers, drops references, and calls
garbage collection. Python cannot guarantee that copies, immutable byte strings,
cryptography-library internals, allocator pages, swap, or crash dumps are
erased. A reported wipe is best-effort cleanup, not forensic or
hardware-grade cryptographic erasure.

### Logs

Structured JSONL logs are size/time rotated and hash chained with local
integrity metadata. They are **tamper-evident, not tamper-proof**. An attacker
with write access to log segments and integrity metadata can rewrite the chain;
rotation also means old records outside retention cannot be checked. Logs and
reports summarize local inputs and are not an independent audit authority.

## Safe-use statement

Use synthetic data and local development secrets. Do not send real mission data,
provision real aircraft, or treat a simulated response as a flight command.
Environment variables and `.env` files are convenient local configuration, not
a production secret manager.
