# SCOUT-X Fake-Feature Inventory

## Scope and method

This is a read-only audit of the repository at the time of writing. “Fake” here
means a feature that looks like production behavior but is actually simulated,
display-only, unimplemented, stale, or silently replaced by a fallback. It does
not mean that a deliberate defensive simulation is defective.

Evidence was limited to source, call sites, tests, documentation, and checked-in
assets. No finding below claims that a feature is fake without a direct code
path or explicit documentation evidence. Items that could not be proven are
listed in [Needs a decision](#needs-a-decision).

## Summary

| ID | Classification | Area | Finding | Effort | Risk | Status | Proof |
|---|---|---|---|---:|---:|---|---|
| FF-001 | A | HEM | `SimTransport` is deliberately in-memory, not network delivery. | S | Low |
| FF-002 | A | Scenarios | Scenario packets, attacks, and metrics are deterministic synthetic inputs. | S | Low |
| FF-003 | A | Telemetry | `TelemetryEngine` generates random synthetic telemetry. | S | Low |
| FF-004 | A | HEM | Peer selection and transfer faults are simulated by seeded randomness/configuration. | M | Low |
| FF-005 | A | UI | Secondary map targets are explicitly generated simulated targets. | S | Medium |
| FF-006 | A | UI | ADS-B data is optional external display data, not SCOUT-X telemetry or threat state. | S | Low |
| FF-007 | B | Backend | HEM invalid GPS input is converted to `(0.0, 0.0)` and processing continues. | S | High |
| FF-008 | B | Backend | Event-bus sink exceptions are swallowed and represented only as a drop counter. | S | Medium |
| FF-009 | B | Backend | Dashboard scenario completion errors are stored in shared state and the caller is not failed. | S | Medium |
| FF-010 | C | UI | The dashboard’s “flight status” and threat status are display labels derived from event data, not flight-control state. | S | Medium |
| FF-011 | C | UI | The dashboard’s synthetic secondary target layer is not backend-driven. | S | Medium |
| FF-012 | C | UI | Dashboard freshness and aircraft polling timers can make the UI appear live without new security events. | S | Low |
| FF-013 | D | Docs | “Autonomous defense” and response language can look like real flight control despite simulated enforcement. | S | High | relabelled | `test_dashboard_uses_simulated_defense_label` |
| FF-014 | E | Repo | `simulation/validators/consistency_validator.py.save` is a stale source copy. | S | Medium | removed | bounded diff; active validator tests |
| FF-015 | E | Repo | `simulation/analysis/threat_dashboard.py` is a separate legacy log reader, not the FastAPI dashboard. | S | Medium | removed | no runtime references; pytest |
| FF-016 | A | Repo | Legacy TCP, Gazebo, Isaac, MuJoCo, and TOTP examples are explicitly separate demonstrations. | M | Low |
| FF-017 | D | Docs | ML evaluation documents only synthetic simulator performance, not real aircraft or unseen attacks. | S | Low |
| FF-018 | C | UI | Some dashboard labels are hardcoded presentation text and must not be interpreted as backend facts. | S | Low |
| FF-019 | B | Backend | The dashboard normalizes legacy event fields and can substitute `SECURITY_RESULT` for missing pattern data. | S | Medium |
| FF-020 | B | Backend | The report generator reads historical JSONL files rather than a live typed event source. | M | Medium |

## Detailed findings

### FF-001 — HEM transport is simulated

- **Location:** [`simulation/hem/transport.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/hem/transport.py:1),
  [`simulation/hem/controller.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/hem/controller.py:633)
- **Pretends to do:** Deliver protected mission data to a base or peer.
- **Evidence:** `SimTransport` keeps delivery state in memory and injects configured
  loss/tamper behavior. `HEMController._send_to_destination` calls transport
  methods rather than a real network client. The architecture documentation also
  states that `SimTransport` is not a network transport.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep, but retain “simulated transport” in every public description.
- **Effort/risk:** S / Low.

### FF-002 — Scenario results are synthetic

- **Location:** [`simulation/demo/run_scenarios.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/demo/run_scenarios.py:35),
  [`run_scenario`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/demo/run_scenarios.py:383)
- **Pretends to do:** Evaluate detection and protection behavior as if it were
  an operational telemetry benchmark.
- **Evidence:** `AttackInjection`, `ScenarioDefinition`, seeded `random.Random`,
  `_baseline_packet`, and `_apply_injections` construct all inputs locally.
  Metrics are computed from those generated labels and packets.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep; label results as synthetic regression metrics, not field performance.
- **Effort/risk:** S / Low.

### FF-003 — Telemetry is generated, not received from an aircraft

- **Location:** [`simulation/telemetry/telemetry_engine.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/telemetry/telemetry_engine.py:17)
- **Pretends to do:** Produce aircraft telemetry.
- **Evidence:** The engine initializes heading with `random.random()` and mutates
  position, speed, altitude, and battery with `random.uniform()`.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep; call it a telemetry generator in UI and docs.
- **Effort/risk:** S / Low.

### FF-004 — Peer choice and transfer faults are simulated

- **Location:** [`simulation/hem/transport.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/hem/transport.py:31),
  [`simulation/hem/peers.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/hem/peers.py:195)
- **Pretends to do:** Model reliable peer/base selection and delivery.
- **Evidence:** Transport owns a seeded `random.Random`; configured packet loss
  and tamper behavior determine outcomes. The peer module handles simulated
  authenticated messages and replay state, not a remote peer connection.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep; do not describe it as a tested radio or peer network.
- **Effort/risk:** M / Low.

### FF-005 — Secondary map targets are synthetic

- **Location:** [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:576)
- **Pretends to do:** Show additional tracked aircraft or threats.
- **Evidence:** `updateSecondaryTargets()` iterates `SECONDARY_TARGETS`, calls
  `getSecondaryPosition`, and labels markers `SIMULATED`. Popups say
  `SCOUT-X SIMULATION` and `Simulated target only`.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep for demonstrations; visually separate these markers from
  authenticated telemetry and live ADS-B.
- **Effort/risk:** S / Low.

### FF-006 — ADS-B is external display data, not security telemetry

- **Location:** [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:860),
  [`dashboard/server.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/server.py:850)
- **Pretends to do:** Provide live aircraft context for the SCOUT-X security
  pipeline.
- **Evidence:** The browser calls `/api/aircraft`; the server fetches an optional
  `adsb.lol` URL. The UI labels rows `LIVE ADS-B`, while no result is passed into
  `SecurityPipeline`.
- **Classification:** **A. LEGITIMATE SIMULATION/CONTEXT**
- **Action:** Keep, but preserve the current “not a threat assessment” warning.
- **Effort/risk:** S / Low.

### FF-007 — Invalid HEM GPS silently becomes zero coordinates

- **Location:** [`simulation/hem/controller.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/hem/controller.py:308)
- **Pretends to do:** Safely process packet coordinates for HEM destination
  selection.
- **Evidence:** `_gps_coordinates()` catches `TypeError`/`ValueError`, executes
  `pass`, and returns `(0.0, 0.0)`. This can turn malformed input into a valid
  geographic point and continue processing instead of rejecting or escalating.
- **Classification:** **B. FAKE IN A REAL PATH**
- **Action:** Return a structured invalid-coordinate result or raise a typed
  stage error so the pipeline fails closed; add a regression test.
- **Effort/risk:** S / High.

### FF-008 — Event sink failures are swallowed

- **Location:** [`simulation/pipeline.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/pipeline.py:192)
- **Pretends to do:** Persist and publish every security event.
- **Evidence:** The sink worker catches broad `Exception`, increments
  `dropped_events`, and continues. The producer receives no error and there is no
  structured `StageError` event for a logger failure.
- **Classification:** **B. FAKE IN A REAL PATH**
- **Action:** Keep the pipeline non-blocking, but emit an explicit observable
  sink-failure event/health signal and expose the drop reason.
- **Effort/risk:** S / Medium.

### FF-009 — Dashboard scenario failure is not propagated to the caller

- **Location:** [`dashboard/server.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/server.py:626)
- **Pretends to do:** Run a scenario and report whether it completed.
- **Evidence:** `send_scenario()` catches `Exception`, writes `str(exc)` to
  `scenario_state["last_error"]`, and does not raise to the initiating request.
  The caller must poll state to discover failure; a failed ACK can appear as an
  accepted start request.
- **Classification:** **B. FAKE IN A REAL PATH**
- **Action:** Return an operation ID and explicit status/failure contract; preserve
  asynchronous execution but make failure observable through the API.
- **Effort/risk:** S / Medium.

### FF-010 — “Flight status” is a display status, not flight control

- **Location:** [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:1073),
  [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:1195)
- **Pretends to do:** Show current aircraft flight state.
- **Evidence:** `updateTrustPhase()` sets DOM text/classes from the event’s
  `state`, and `updateThreatPanel()` writes `CRITICAL THREAT`, `THREAT DETECTED`,
  or `NORMAL FLIGHT`. These are browser labels; no flight-control command is
  issued. Repository docs correctly state the system is not a flight controller.
- **Classification:** **C. DISPLAY-ONLY FAKE**
- **Action:** Rename labels to “simulated security state” where ambiguity matters.
- **Effort/risk:** S / Medium.

### FF-011 — Synthetic targets are not pipeline state

- **Location:** [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:576),
  [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:1792)
- **Pretends to do:** Maintain a live multi-target radar view.
- **Evidence:** A timer invokes `updateSecondaryTargets()` every
  `CONFIG.simulated_target_refresh_interval_ms`; those positions are generated
  locally and never arrive through `/api/events` or the pipeline.
- **Classification:** **C. DISPLAY-ONLY FAKE**
- **Action:** Keep only in a clearly marked simulation layer, or wire it to a
  typed target feed if multi-target telemetry is required.
- **Effort/risk:** S/M / Medium.

### FF-012 — Timers can create a “live” appearance without security updates

- **Location:** [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:1789)
- **Pretends to do:** Keep the dashboard current.
- **Evidence:** `setInterval(updateFreshness, 1000)` updates freshness independently
  of new telemetry; another interval polls external aircraft data and another
  refreshes synthetic targets. These timers do not prove that the pipeline has
  processed a packet.
- **Classification:** **C. DISPLAY-ONLY FAKE**
- **Action:** Base “live” indicators on event timestamps and show separate
  labels for external aircraft polling and synthetic targets.
- **Effort/risk:** S / Low.

### FF-013 — Defense language can overstate simulated enforcement

- **Location:** [`README.md`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/README.md:88),
  [`dashboard/index.html`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/index.html:65),
  [`simulation/security/enforcer.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/security/enforcer.py:1)
- **Pretends to do:** Provide autonomous real-world aircraft defense.
- **Evidence:** The UI contains “Autonomous Defense” and the pipeline emits
  enforcement labels, but the repository’s own README says no real aircraft or
  flight-control capability exists. The enforcer produces simulated action
  labels only.
- **Classification:** **D. UNIMPLEMENTED CLAIM**
- **Status:** **RELABELLED** in [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:50),
  [`dashboard/index.html`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/index.html:44),
  and the README’s Planned / not implemented section.
- **Proof:** `test_dashboard_uses_simulated_defense_label`.
- **Action:** Keep the simulated label; do not add real flight-control claims.
- **Effort/risk:** S / High.

### FF-014 — Stale validator source copy

- **Location:** [`simulation/validators/consistency_validator.py.save`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/validators/consistency_validator.py.save:1)
- **Pretends to do:** Be an active validator module.
- **Evidence:** The `.save` suffix is not an importable Python module and is not
  part of the maintained package path. The active implementation is
  `consistency_validator.py`.
- **Classification:** **E. DEAD CODE**
- **Status:** **REMOVED** after review. The bounded diff showed an older,
  syntactically invalid implementation with broad exception handling, while the
  active module contains the typed `ValidationResult` contract and is covered
  by maintained validation tests.
- **Proof:** Active validator tests and repository import search.
- **Action:** None.
- **Effort/risk:** S / Low.

### FF-015 — Legacy threat dashboard is not the dashboard

- **Location:** [`simulation/analysis/threat_dashboard.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/analysis/threat_dashboard.py:1)
- **Pretends to do:** Provide the project dashboard.
- **Evidence:** It executes at module scope, reads the JSONL file directly, counts
  `flagged` and `enforced == "ISOLATED"`, and prints totals. It is not imported
  by `dashboard.server`, has no API, and does not consume `SystemState`.
- **Classification:** **E. DEAD CODE**
- **Status:** **REMOVED** after usage search found no runtime or test caller.
- **Proof:** Repository reference search; maintained dashboard tests.
- **Action:** None.
- **Effort/risk:** S / Medium.

### FF-016 — Experimental/legacy examples are not production paths

- **Location:** [`simulation/legacy_tcp/`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/legacy_tcp),
  [`simulation_tests/`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation_tests),
  [`totp_test/`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/totp_test)
- **Pretends to do:** Be part of the authenticated UDP production pipeline.
- **Evidence:** `docs/ARCHITECTURE.md:128-131` explicitly identifies these as
  older TCP, experimental Gazebo/Isaac/MuJoCo, and standalone TOTP
  demonstrations. Their scripts use local simulation loops and are not called
  by `receiver.py` or `dashboard.server`.
- **Classification:** **A. LEGITIMATE SIMULATION**
- **Action:** Keep if educational examples are desired; otherwise archive them
  outside the runtime package and preserve clear warnings.
- **Effort/risk:** M / Low.

### FF-017 — ML evaluation is not real-world validation

- **Location:** [`docs/ml_evaluation.md`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/docs/ml_evaluation.md:1),
  [`scripts/evaluate_ml.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/scripts/evaluate_ml.py:1)
- **Pretends to do:** Demonstrate operational ML detection performance.
- **Evidence:** The evaluation uses synthetic `TelemetryEngine` samples and
  documents that it does not measure real aircraft or unseen attack classes.
- **Classification:** **D. UNIMPLEMENTED CLAIM** if presented as production
  performance; otherwise **A. LEGITIMATE SIMULATION**.
- **Action:** Keep the limitation prominent and label all metrics “synthetic
  regression/evaluation only.”
- **Effort/risk:** S / Low.

### FF-018 — Hardcoded UI labels are presentation, not system facts

- **Location:** [`dashboard/index.html`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/index.html:145),
  [`dashboard/app.js`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/app.js:1195)
- **Pretends to do:** Display current configured thresholds and current threat
  status.
- **Evidence:** HTML includes threshold labels and the browser writes
  `CRITICAL THREAT`, `THREAT DETECTED`, and `NORMAL FLIGHT` strings. The
  authoritative phase is separately read from event state; these labels are
  presentation decisions.
- **Classification:** **C. DISPLAY-ONLY FAKE**
- **Action:** Load all threshold display values from the server configuration
  and label derived descriptions as explanatory text.
- **Effort/risk:** S / Low.

### FF-019 — Dashboard parser repairs malformed/legacy events

- **Location:** [`dashboard/server.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/dashboard/server.py:482)
- **Pretends to do:** Return the exact pipeline event model.
- **Evidence:** `read_events()` merges `details` into a dashboard model,
  substitutes an event type when `pattern` is absent, and converts string
  enforcement values into booleans. This is a compatibility projection, not a
  typed event pass-through.
- **Classification:** **B. FAKE IN A REAL PATH**
- **Action:** Version the log/dashboard contract and reject or explicitly mark
  compatibility projections instead of silently repairing them.
- **Effort/risk:** M / Medium.

### FF-020 — Historical reporting still uses file hand-off

- **Location:** [`simulation/reporting/report_generator.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/reporting/report_generator.py:39),
  [`simulation/reporting/report_generator.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/simulation/reporting/report_generator.py:293)
- **Pretends to do:** Generate reports from the pipeline’s event stream.
- **Evidence:** The live subscriber exists, but report generation also opens
  configured JSONL files and parses their contents. This makes the file format
  a second integration contract and can produce a report from stale or
  incomplete files.
- **Classification:** **B. FAKE IN A REAL PATH**
- **Action:** Define whether reports are live snapshots or historical file
  reports; for live reports, consume a bounded typed event store and expose
  file verification failures.
- **Effort/risk:** M / Medium.

## Tests and dependencies

### Tests that may give a false sense of coverage

No test was classified as definitively meaningless from static inspection alone.
The maintained tests contain concrete assertions, and the Phase 6 proof tests
exercise stage failures, contracts, scenario outcomes, event-bus boundedness,
and dashboard normalization. The following items are candidates for review, not
confirmed fake tests:

- [`tests/test_pipeline.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/tests/test_pipeline.py:54)
  uses a collecting callback and timing assertions for the event bus; it proves
  non-blocking behavior but not durable delivery.
- [`tests/test_phase6_proof.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/tests/test_phase6_proof.py:106)
  uses `time.sleep()` in a deliberately slow subscriber; this is a concurrency
  test fixture, not production fake work.
- [`tests/simulation/test_scenario_runner.py`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/tests/simulation/test_scenario_runner.py:40)
  validates deterministic synthetic scenarios, not real-world detection.

### Dependencies

The runtime manifest contains packages used by the inspected runtime paths:
`fastapi`, `uvicorn`, `pydantic`, `cryptography`, `joblib`, `matplotlib`,
`numpy`, `pydantic-settings`, `python-dotenv`, and `scikit-learn`
([`requirements.txt`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/requirements.txt:1)).
This audit did not prove an unused dependency by text search alone; import
resolution and optional runtime paths need a separate dependency audit.

## Needs a decision

These are plausible concerns, but the repository evidence is insufficient to
classify them as fake without an explicit product decision:

1. **Screenshots:** [`screenshots/dashboard-overview.png`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/screenshots/dashboard-overview.png)
   and [`screenshots/dashboard-threats.png`](C:/Users/OLUDEMI%20JOSHUA/Projects/SCOUT-X/screenshots/dashboard-threats.png)
   are checked-in binaries. Static source inspection cannot prove whether they
   match the current HTML/CSS. Recommendation: recapture them from the current
   server and compare manually.
2. **External ADS-B availability:** the endpoint is implemented, but whether
   `adsb.lol` is acceptable for the intended deployment cannot be established
   from this repository. Recommendation: decide whether this optional feature
   belongs in the supported product.
3. **Legacy examples:** `simulation/legacy_tcp`, `simulation_tests`, and
   `totp_test` may be intentionally educational. Recommendation: decide whether
   to keep them in the main repository or archive them.
4. **Config keys:** this audit did not prove every settings field is unused.
   Some are consumed only by optional dashboard or demo paths. Recommendation:
   generate a settings-field reference report from the runtime import graph
   before deleting any key.
5. **Log/report authority:** the code intentionally retains JSONL as a historical
   report source. Recommendation: decide whether this is an accepted durable
   audit boundary or an integration smell that must be removed.

## Recommended priority order

1. **P0:** Fix FF-007 so malformed coordinates cannot become `(0.0, 0.0)` in a
   real processing path.
2. **P1:** Make FF-008 and FF-009 observable through structured health/status
   reporting rather than silent/asynchronous failure.
3. **P1:** Resolve FF-019 and FF-020 by versioning the event contract and choosing
   one authoritative reporting source.
4. **P1:** Relabel FF-013, FF-017, and all UI defense language to preserve the
   project’s honest simulation limitations.
5. **P2:** Remove or archive FF-014 and FF-015 after confirming no external users
   depend on them.
6. **P2:** Clarify FF-011, FF-012, and FF-018 in the dashboard UX.
