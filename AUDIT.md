# SCOUT-X Repository Audit

**Scope:** repository source, dashboard, simulation/test examples, README, and dependency manifests.  
**Date:** 2026-11-02  
**Worktree constraint:** only this report is being added; no existing source or data files are changed.

## Executive summary

SCOUT-X has two materially different telemetry paths. The README's runnable path starts the UDP receiver, FastAPI dashboard, and a canned scenario sender. A second simulator/validator path lives in `simulation/runner/simulation_runner.py`; it is not started by the README and sends a different validation shape. The receiver's `AttackAnalyzer` and ML-training gate expect a flat validation shape, so they do not consume the nested validation results produced by that runner. Dashboard scenarios bypass the middleware and validators altogether and send pre-populated trust/validation claims.

The HEM includes AES-GCM, HKDF, random nonces, and AAD; no nonce reuse or missing AAD was identified in the inspected encryption calls. However, the vault retains plaintext after sealing, and its transfer path reads that plaintext rather than the sealed ciphertext. The at-rest encryption claim is therefore not true of the in-memory vault. HEM's TOTP check also generates and verifies its own code locally, so it is not proof of a remote peer's identity.

No P0 was assigned for the documented simulation-only deployment: the receiver listens on loopback and the README explicitly excludes real radio and flight-control integration. P1 issues nevertheless make the prototype unsafe to treat as a security boundary or to expose as a protected service.

## Architecture map

The "callers" below are code-level callers or entry points, not assumed external consumers. Many utility modules are manually runnable rather than part of the README-started pipeline.

### Primary application and pipeline

| Module | Responsibility; inputs -> outputs | Callers / flow |
|---|---|---|
| [`simulation/legacy_tcp/drone_sim.py`](./simulation/legacy_tcp/drone_sim.py) | Legacy TCP telemetry generator; synthesizes GPS/altitude/battery dictionaries -> newline-delimited JSON over TCP. | Starts [`simulation/legacy_tcp/ground_control.py`](./simulation/legacy_tcp/ground_control.py) as a subprocess. Not used by README instructions. |
| [`simulation/legacy_tcp/ground_control.py`](./simulation/legacy_tcp/ground_control.py) | Legacy TCP listener; reads bytes -> console output. | Spawned by `simulation.legacy_tcp.drone_sim`; separate from the UDP receiver. |
| [`simulation/security/telemetry_middleware.py`](./simulation/security/telemetry_middleware.py) | Sanitizes selected values, performs basic anomaly checks, and adjusts an in-memory trust score. Dict -> mutated dict with `flagged` and `trust_score`. | Used only by `simulation/runner/simulation_runner.py`; not installed as FastAPI middleware and not used by dashboard scenarios. |
| [`simulation/security/defense_logic.py`](./simulation/security/defense_logic.py) | Legacy trust/altitude clamp. Dict -> mutated dict with an action/altitude. | Used only by `simulation/runner/simulation_runner.py`. |
| [`simulation/telemetry/telemetry_engine.py`](./simulation/telemetry/telemetry_engine.py) | Generates random-walk telemetry with a wall-clock timestamp and sequence. No input -> packet dict. | Instantiated by `simulation/runner/simulation_runner.py`; package initializer is empty. |
| [`simulation/validators/consistency_validator.py`](./simulation/validators/consistency_validator.py) | Compares consecutive GPS, time, speed, and altitude values -> score/flags/anomaly dict. | Called by `simulation/runner/simulation_runner.py`. |
| [`simulation/validators/motion_validator.py`](./simulation/validators/motion_validator.py) | Compares GPS coordinate delta with a crude speed-derived limit -> score/flags/anomaly dict. | Called by `simulation/runner/simulation_runner.py`. |
| [`simulation/analysis/attack_classifier.py`](./simulation/analysis/attack_classifier.py) | Maps validation flags to a single attack label. Validation dict -> label string. | Called by `simulation/runner/simulation_runner.py`; not used by the receiver. |
| [`simulation/runner/simulation_runner.py`](./simulation/runner/simulation_runner.py) | Top-level infinite simulation loop: generates, spoofs, validates, classifies, sends UDP, logs, prints. | Manual entry point; sends to `simulation/ground_control/receiver.py`. Not included in README's run steps. |
| [`simulation/ground_control/receiver.py`](./simulation/ground_control/receiver.py) | Main UDP receiver and orchestrator: parses packets, tracks scenarios, analyzes, trains/predicts ML, chooses/enforces a response, calls HEM, updates stats, and logs. Datagram -> enriched packet and side effects. | Started by README; receives from `dashboard/server.py`, `simulation/demo/run_scenarios.py`, and the separately run simulation runner. |
| [`simulation/analysis/attack_analyzer.py`](./simulation/analysis/attack_analyzer.py) | Maintains a bounded recent history and labels it persistent/intermittent/normal. Packet with a **flat** `validation.is_anomalous` -> pattern/severity. | Called by `simulation/ground_control/receiver.py`. |
| [`simulation/security/response_engine.py`](./simulation/security/response_engine.py) | Tracks attack streak and selects response string from packet pattern/severity/trust. | Called by `simulation/ground_control/receiver.py`. |
| [`simulation/security/enforcer.py`](./simulation/security/enforcer.py) | Converts a response string to an `enforced` label and prints a message. | Called by receiver; it does not issue hardware or flight-control commands. |
| [`simulation/ml/anomaly_detector.py`](./simulation/ml/anomaly_detector.py) | Scales five telemetry features, trains Isolation Forest, returns anomaly/risk values. | Called by receiver; tests are in [`tests/simulation/ml/test_anomaly_detector.py`](./tests/simulation/ml/test_anomaly_detector.py). |
| [`simulation/logging/attack_logger.py`](./simulation/logging/attack_logger.py) | Appends UTC-stamped packet/detection/response/HEM JSON Lines records under `logs/attack_log.json`. | Used by receiver and simulation runner; read by dashboard and report utilities. |
| [`simulation/analysis/threat_stats.py`](./simulation/analysis/threat_stats.py) | In-memory packet/attack/response counters -> console display. | Updated/displayed by receiver. |

### HEM and reporting modules

| Module | Responsibility; inputs -> outputs | Callers / flow |
|---|---|---|
| [`simulation/hem/__init__.py`](./simulation/hem/__init__.py) | Re-exports HEM public classes. | Imported by receiver and [`tests/simulation/hem/test_hem.py`](./tests/simulation/hem/test_hem.py). |
| [`simulation/hem/controller.py`](./simulation/hem/controller.py) | Trust/response phase machine, destination choice, transfers, audit events, terminal PROTECT result. Packet -> HEM result and vault/log side effects. | Receiver calls `on_packet`; controller calls `exfil`, peer/TOTP helpers, vault, transport. |
| [`simulation/hem/vault.py`](./simulation/hem/vault.py) | Stores prioritized mission data, creates AES-GCM sealed copies, marks/purges transfers, and clears references on zeroize. | Created by receiver's `create_hem_session`; used by controller and HEM tests. |
| [`simulation/hem/exfil.py`](./simulation/hem/exfil.py) | HKDF session key derivation; AES-GCM chunking, retry send, and chunk reassembly/decryption. | Called by HEM controller; receive helper is exercised by HEM tests. |
| [`simulation/hem/peers.py`](./simulation/hem/peers.py) | TOTP helper, Haversine distance, peer record/eligibility sorting. Peer metadata and location/time -> eligible peers. | Called by HEM controller; test fixtures create peers. |
| [`simulation/hem/transport.py`](./simulation/hem/transport.py) | In-memory simulated base/peer transport, loss, and tampering. Chunks -> simulated ACK/inbox. | Created by receiver and HEM tests; no actual radio implementation. |
| [`tests/simulation/hem/test_hem.py`](./tests/simulation/hem/test_hem.py) | Pytest assertions for phase, transfer, peer, loss/tampering, and zeroization behavior. | Pytest; also has a manual test runner. |
| [`simulation/analysis/report_generator.py`](./simulation/analysis/report_generator.py) | Reads JSONL and prints counts of patterns/responses. | Instantiated and called by receiver on Ctrl-C. |
| [`simulation/reporting/report_generator.py`](./simulation/reporting/report_generator.py) | Separately reads JSONL and prints attack/trust/isolation summary. | Standalone CLI only; no application caller found. |
| [`simulation/analysis/threat_dashboard.py`](./simulation/analysis/threat_dashboard.py) | Standalone JSONL counter for flagged and isolated events. | Manual execution only; not the FastAPI dashboard. |
| [`simulation/demo/run_scenarios.py`](./simulation/demo/run_scenarios.py) | Sends canned flat-schema normal and attack UDP packets. | Manual demo entry point; destination is the receiver. |
| [`tests/simulation/ml/test_anomaly_detector.py`](./tests/simulation/ml/test_anomaly_detector.py) | Pytest assertions for untrained output, training-data bounds, and an obvious outlier; retains a standalone demo entry point. | Pytest or direct script execution. |
| [`simulation/runner/__init__.py`](./simulation/runner/__init__.py) | Empty package initializer. | Python package loading only. |
| [`simulation/telemetry/__init__.py`](./simulation/telemetry/__init__.py) | Empty package initializer. | Python package loading only. |

### Dashboard modules

| Module | Responsibility; inputs -> outputs | Callers / flow |
|---|---|---|
| [`dashboard/server.py`](./dashboard/server.py) | FastAPI static/API server; reads event log, sends canned scenario/control UDP messages, fetches an external ADS-B feed. HTTP -> HTML/JSON or UDP datagrams. | Started by README; called by browser and external HTTP clients; sends to receiver. |
| [`dashboard/index.html`](./dashboard/index.html) | Dashboard structure and element IDs; links stylesheet and application script. | Served by `dashboard.server`. |
| [`dashboard/app.js`](./dashboard/app.js) | Normalizes API event fields, polls events/aircraft, renders DOM/Leaflet panels, and posts scenario requests. API/ADS-B JSON -> browser UI. | Loaded by `index.html`; calls `dashboard/server.py`. |
| [`dashboard/style.css`](./dashboard/style.css) | Dashboard presentation/layout only. | Loaded by `index.html`. |

### Separate examples and simulator test modules

These are not wired into the main README pipeline; several execute work at import time.

| Module(s) | Responsibility; inputs -> outputs | Callers / flow |
|---|---|---|
| [`totp_test/totp_sender.py`](./totp_test/totp_sender.py) | Toy TCP sender with a fixed TOTP seed. Command/time/code -> TCP message. | Manual standalone counterpart to `totp_receiver.py`. |
| [`totp_test/totp_receiver.py`](./totp_test/totp_receiver.py) | Toy TCP listener with IP check, time check, and timestamp replay set. TCP message -> console accept/reject. | Manual standalone; conflicts for port 5000 with `simulation/legacy_tcp/ground_control.py` if both are started. |
| [`simulation_tests/mujoco_tests/camera_tracking.py`](./simulation_tests/mujoco_tests/camera_tracking.py) | Import-time proportional-yaw tracking toy loop. | Imported by `simulation_runner.py` and `test_mujoco_suite.py`; neither calls a named test. |
| [`simulation_tests/mujoco_tests/control_test.py`](./simulation_tests/mujoco_tests/control_test.py) | Placeholder print-only control test. | Manual only. |
| [`simulation_tests/mujoco_tests/drone_controller.py`](./simulation_tests/mujoco_tests/drone_controller.py) | Toy `MissionState`-based action selector. | Manual script only; imports `mission_state.py`. |
| [`simulation_tests/mujoco_tests/event_logger.py`](./simulation_tests/mujoco_tests/event_logger.py) | Appends timestamped text events to `events.log`. | Called by `scenario_manager.py`; manual sample calls at module entry. |
| [`simulation_tests/mujoco_tests/intrusion_detection.py`](./simulation_tests/mujoco_tests/intrusion_detection.py) | Import-time randomized restricted-zone detector loop. | Imported by both simulator runners and `test_mujoco_suite.py`. |
| [`simulation_tests/mujoco_tests/mission_state.py`](./simulation_tests/mujoco_tests/mission_state.py) | Mutable toy mission mode/threat/intrusion state. | Used by `drone_controller.py` and `scenario_manager.py`; also has a manual demo. |
| [`simulation_tests/mujoco_tests/navigation_manager.py`](./simulation_tests/mujoco_tests/navigation_manager.py) | Toy waypoint storage and Euclidean distance. | No caller found. |
| [`simulation_tests/mujoco_tests/scenario_manager.py`](./simulation_tests/mujoco_tests/scenario_manager.py) | Sets toy threat levels and logs scenario labels. | Manual entry point; calls `mission_state.py` and `event_logger.py`. |
| [`simulation_tests/mujoco_tests/sensor_manager.py`](./simulation_tests/mujoco_tests/sensor_manager.py) | Returns fixed example sensor values. | Manual entry point only. |
| [`simulation_tests/mujoco_tests/simulation_runner.py`](./simulation_tests/mujoco_tests/simulation_runner.py) | Prints four headings; intended actions are commented out. | Manual only; wildcard-imports side-effect scripts. |
| [`simulation_tests/mujoco_tests/target_generator.py`](./simulation_tests/mujoco_tests/target_generator.py) | Linear/circular/random/zigzag point generator. | Manual demo only; no core pipeline caller. |
| [`simulation_tests/mujoco_tests/telemetry_logger.py`](./simulation_tests/mujoco_tests/telemetry_logger.py) | Import-time writes 50 simulated rows to `telemetry.csv`. | No core caller found. |
| [`simulation_tests/mujoco_tests/test_mujoco_suite.py`](./simulation_tests/mujoco_tests/test_mujoco_suite.py) | Wildcard-imports four modules and prints status; has no pytest test functions/assertions. | Pytest collects the module, triggering imported scripts' top-level loops. |
| [`simulation_tests/mujoco_tests/threat_assessment.py`](./simulation_tests/mujoco_tests/threat_assessment.py) | Toy points-based threat score and import-time random demo. | Imported by both simulator runners; no integration with core response engine. |
| [`simulation_tests/mujoco_tests/waypoint_patrol.py`](./simulation_tests/mujoco_tests/waypoint_patrol.py) | Import-time waypoint convergence demo. | Imported by both simulator runners and `test_mujoco_suite.py`. |
| [`simulation_tests/gazebo_tests/scripts/surveillance_patrol.py`](./simulation_tests/gazebo_tests/scripts/surveillance_patrol.py) | Print/sleep waypoint placeholder. | Standalone only. |
| [`simulation_tests/gazebo_tests/scripts/telemetry_monitor.py`](./simulation_tests/gazebo_tests/scripts/telemetry_monitor.py) | Prints fixed sensor statuses. | Standalone only. |

`camera_feed_check.sh`, `gps_topic_check.sh`, and `sensor_topic_check.sh` run ROS 2 CLI inspection commands; they do not feed SCOUT-X's receiver. The remaining `simulation_tests` files are simulator documentation, sample world/model/scene files, images, and saved outputs—not imported application modules.

## README architecture alignment

The README diagram at [`README.md:32-84`](./README.md#L32) describes a single validation -> classification -> trust/ML -> response -> enforcement -> HEM/logger -> dashboard pipeline. The implementation diverges in these concrete ways:

1. **The documented runnable flow does not run the telemetry engine or validators.** README starts `simulation.ground_control.receiver`, then `dashboard.server`, then `simulation.demo.run_scenarios` ([`README.md:330-360`](./README.md#L330)). `simulation/runner/simulation_runner.py` is a separate infinite loop and is not in those instructions.
2. **Dashboard scenarios bypass telemetry validation.** `dashboard/server.py` manufactures already-labeled trust/validation fields and sends them straight to UDP; the receiver does not invoke `SecurityMiddleware` or either validator. The middleware and validators are only in the separate simulation runner.
3. **Attack analysis is split and has incompatible schemas.** The runner nests validator results under `validation.consistency` and `validation.motion`; `AttackAnalyzer` reads only `validation.is_anomalous` and top-level `validation.flags`. The receiver therefore interprets runner validation as clean. The separate `classify_attack` understands nested flags but is not called by the receiver.
4. **There is no standalone trust-score engine in the package.** Trust is adjusted by root `SecurityMiddleware` only on the separate runner path; canned dashboard/demo packets supply trust themselves. HEM consumes the supplied field.
5. **The "response enforcer" is a simulation labeler, not a control adapter.** It writes strings and prints messages; no flight-control/communications adapter is present. README's limitations correctly exclude real integration.
6. **HEM/logger/dashboard are connected only through receiver/log files.** HEM emits in-memory/file events, AttackLogger appends JSONL, and dashboard rereads that JSONL. These are not a transactional event pipeline and no shared synchronization/retention policy exists.
7. **Additional modules do not appear in the diagram:** ADS-B proxy/presentation code in `dashboard/server.py`/`app.js`, legacy TCP scripts, stand-alone TOTP demo, and Gazebo/MuJoCo/Isaac prototype assets.

## Findings

### Correctness and reliability

| ID | Priority | Finding |
|---|---|---|
| C1 | P1 | **Validation is discarded by the receiver for runner packets.** The runner sends nested validation results, while `AttackAnalyzer.analyze()` reads only a flat boolean; it therefore records those packets as clean. The receiver's ML-training gate also checks only `validation.is_anomalous`, so nested anomalies can be added to the supposedly clean training set. This defeats the analysis/training signal on that path. Evidence: [`simulation/runner/simulation_runner.py:39-45`](./simulation/runner/simulation_runner.py#L39-L45), [`simulation/analysis/attack_analyzer.py:6-15`](./simulation/analysis/attack_analyzer.py#L6-L15), [`simulation/ground_control/receiver.py:131-151`](./simulation/ground_control/receiver.py#L131-L151). |
| C2 | P1 | **AttackAnalyzer classifies clean startup packets as attacks.** With one history item, `int(0.7 * 1)` is zero, so `anomaly_count >= 0` is true even with zero anomalies; the persistent branch wins. This can spuriously raise severity/streak at startup. Use a minimum nonzero threshold or ratio comparison and test window lengths 1/2 plus exact boundaries. Evidence: [`simulation/analysis/attack_analyzer.py:23-42`](./simulation/analysis/attack_analyzer.py#L23-L42). |
| C3 | P1 | **The response failsafe disagrees with the documented PROTECT boundary.** HEM enters PROTECT at `trust <= 0.2`, but ResponseEngine isolates only at `trust < 0.2`; at exactly 0.20 the response path does not take its trust failsafe. Dashboard `threatClass` also uses `< 0.2`. HEM does still protect, so this is a cross-surface state/action mismatch, not a missed HEM transition. Evidence: [`README.md:95-103`](./README.md#L95), [`simulation/hem/controller.py:59-72`](./simulation/hem/controller.py#L59-L72), [`simulation/security/response_engine.py:16-18`](./simulation/security/response_engine.py#L16-L18), [`dashboard/app.js:268-284`](./dashboard/app.js#L268-L284). |
| C4 | P1 | **Dashboard scenarios are test fixtures presented as pipeline output.** They include their own trust values and anomaly booleans/flags; the receiver trusts these fields rather than validating a raw telemetry message. This is a material architecture/correctness gap and compounds unauthenticated UDP input (S1). Evidence: [`dashboard/server.py:89-162`](./dashboard/server.py#L89-L162), [`simulation/ground_control/receiver.py:128-172`](./simulation/ground_control/receiver.py#L128-L172). |
| C5 | P1 | **Motion validator mixes units and has no elapsed-time input.** It compares Euclidean latitude/longitude degrees directly with `speed * 0.001`, with no conversion to metres and no timestamp delta; a threshold cannot consistently mean “GPS movement matches speed.” The consistency validator does convert degree distance with a fixed 111,000 factor, which also treats longitude scale as latitude scale. Evidence: [`simulation/validators/motion_validator.py:4-12,27-41`](./simulation/validators/motion_validator.py#L4-L12), [`simulation/validators/consistency_validator.py:26-49`](./simulation/validators/consistency_validator.py#L26-L49). |
| C6 | P2 | **Invalid time deltas are hidden, not reported.** `dt <= 0` and `dt > 2` are silently replaced with 1.0 seconds; duplicate, reversed, or delayed timestamps can therefore yield plausible-looking derived speeds instead of a time anomaly. Evidence: [`simulation/validators/consistency_validator.py:26-35`](./simulation/validators/consistency_validator.py#L26-L35). |
| C7 | P2 | **Boundary logic is inconsistent outside HEM.** `DefenseLogic` does not update `last_safe_altitude` at exactly 0.8 (`<` then `>`), despite README defining 0.80 as STANDBY. Dashboard labels trust >=0.7 as normal, not the documented >=0.8. The legacy class is now in the security package, but these surfaces can disagree at the stated threshold. Evidence: [`simulation/security/defense_logic.py:7-20`](./simulation/security/defense_logic.py#L7-L20), [`dashboard/app.js:948-979`](./dashboard/app.js#L948-L979). |
| C8 | P2 | **Input shape/type exceptions can drop a packet.** `validate_motion` indexes GPS/speed without validation; the telemetry middleware assumes GPS is a mapping and numeric fields are comparable. The receiver catches a broad exception around the whole packet and continues, so malformed-but-valid JSON can skip every downstream action with only a console error. The consistency validator's bare `except` conversely converts all failures into the same `STATE_ERROR`. Evidence: [`simulation/validators/motion_validator.py:27-31`](./simulation/validators/motion_validator.py#L27-L31), [`simulation/security/telemetry_middleware.py:29-76`](./simulation/security/telemetry_middleware.py#L29-L76), [`simulation/validators/consistency_validator.py:7-24`](./simulation/validators/consistency_validator.py#L7-L24), [`simulation/ground_control/receiver.py:217-220`](./simulation/ground_control/receiver.py#L217-L220). |
| C9 | P2 | **Timestamp formats are mixed.** Telemetry uses epoch seconds, the attack logger writes timezone-aware UTC ISO text, while dashboard-generated packets use naive local `datetime.now().isoformat()`. Consumers may interpret naive values in their own local timezone. TOTP/peer freshness also relies on wall-clock time; a future peer `last_seen` passes the stale-age upper-bound test. Evidence: [`simulation/telemetry/telemetry_engine.py:11-17`](./simulation/telemetry/telemetry_engine.py#L11-L17), [`simulation/logging/attack_logger.py:20-22`](./simulation/logging/attack_logger.py#L20-L22), [`dashboard/server.py:89-110`](./dashboard/server.py#L89-L110), [`simulation/hem/peers.py:100-123`](./simulation/hem/peers.py#L100-L123). |
| C10 | P2 | **Legacy TCP framing is not robust.** The sender transmits JSON plus newline, but the server parses each arbitrary `recv(1024)` result as one whole JSON document. TCP may split or coalesce writes; malformed fragments are printed/dropped. The pair is retained in `simulation/legacy_tcp/`. Evidence: [`simulation/legacy_tcp/drone_sim.py:23-38`](./simulation/legacy_tcp/drone_sim.py#L23-L38), [`simulation/legacy_tcp/ground_control.py:14-24`](./simulation/legacy_tcp/ground_control.py#L14-L24). |

### Security and data handling

| ID | Priority | Finding |
|---|---|---|
| S1 | P1 | **UDP telemetry and scenario-control datagrams are unauthenticated and replayable.** The receiver binds loopback, which limits network exposure by default, but accepts any local sender, does not verify sender `addr`, authenticate packets, deduplicate sequence numbers, or reject replays. The `_scoutx_control=scenario_start` reset message has no authentication either. Evidence: [`simulation/ground_control/receiver.py:22-23,83-103`](./simulation/ground_control/receiver.py#L22-L23), [`simulation/demo/run_scenarios.py:10-13`](./simulation/demo/run_scenarios.py#L10-L13), [`dashboard/server.py:165-185`](./dashboard/server.py#L165-L185). |
| S2 | P1 | **Vault sealing does not remove plaintext or protect the transfer source.** `seal()` encrypts into `_sealed` but leaves `DataItem.plaintext` intact; `pending()` retains sealed items, and `send_item()` is called with the item whose payload is plaintext. The ciphertext is never used for transfer or read-back. Thus in-memory mission data remains plaintext while status says SEALED, contrary to the “encrypted at rest” description. This is not a claim about hardware storage or erasure. Evidence: [`simulation/hem/vault.py:58-87`](./simulation/hem/vault.py#L58-L87), [`simulation/hem/controller.py:232-233,301-307`](./simulation/hem/controller.py#L232-L233), [`simulation/hem/exfil.py:31-45,59-60`](./simulation/hem/exfil.py#L31-L45). |
| S3 | P1 | **HEM authentication is a local self-check, not remote TOTP authentication.** Destination selection computes `totp(secret, now)` locally and immediately verifies that same generated value with the same secret and time. There is no received peer/base proof or challenge-response exchange. In addition, the receiver's base secret is the literal `b"CHANGE-ME"`. Do not treat this as authenticated peer selection. Evidence: [`simulation/hem/controller.py:120-140`](./simulation/hem/controller.py#L120-L140), [`simulation/ground_control/receiver.py:22-26`](./simulation/ground_control/receiver.py#L22-L26). |
| S4 | P1 | **Dashboard API has no authentication and permissive CORS.** All event/latest/health/aircraft/status endpoints and the scenario POST are unauthenticated; CORS allows every origin and credentials. `render-start.sh` binds the dashboard to `0.0.0.0`, making exposure broader than the README's localhost command. The scenario endpoint is constrained to fixed scenarios, but remains remotely triggerable and its events/logs are readable. Evidence: [`dashboard/server.py:31-38,200-321`](./dashboard/server.py#L31-L38), [`render-start.sh:9`](./render-start.sh#L9), [`README.md:345`](./README.md#L345). |
| S5 | P1 | **Unbounded logs and full-file dashboard reads create growth/availability risk.** AttackLogger and HEM append without rotation/retention; HEM also retains every event in `self.events`. Every dashboard poll reparses the entire event log, and `next_sequence()` scans it again. A long-running process accumulates disk/memory and increasingly expensive requests. Evidence: [`simulation/logging/attack_logger.py:16-58`](./simulation/logging/attack_logger.py#L16-L58), [`simulation/hem/controller.py:32-55,357-370`](./simulation/hem/controller.py#L32-L55), [`dashboard/server.py:53-85,205-220`](./dashboard/server.py#L53-L85). |
| S6 | P1 | **Scenario state and JSONL access are not coordinated with receiver completion or multiple workers.** The lock protects only process-local dashboard state. `send_scenario` marks it stopped after sending the last datagram, not after receiver processing; a second scenario can then be accepted while queued datagrams are still being consumed. Multiple Uvicorn workers would each have independent lock/state. AttackLogger has no shared-process/file lock while dashboard reads the same append-only file, so a partially written final line can be skipped. Evidence: [`dashboard/server.py:165-198,286-321`](./dashboard/server.py#L165-L198), [`simulation/logging/attack_logger.py:57-58`](./simulation/logging/attack_logger.py#L57-L58), [`dashboard/server.py:59-73`](./dashboard/server.py#L59-L73). |
| S7 | P2 | **Live aircraft tooltip interpolates an external feed value as HTML.** The popup escapes flight/hex/telemetry values, and ordinary timeline fields use `textContent`, but `bindTooltip()` receives `aircraftDisplayName(aircraft)` unescaped. Leaflet interprets string tooltip content as HTML; a compromised or unexpected ADS-B response can reach a DOM HTML sink. Escape this value or provide a DOM node/text-only renderer. Evidence: [`dashboard/app.js:137-147,582-588,629-637`](./dashboard/app.js#L137-L147). |
| S8 | P2 | **The standalone TOTP receiver has a replay weakness and unbounded replay state.** It records used timestamps rather than used OTPs/authenticated messages; the same valid TOTP can be replayed with a different timestamp still inside the ±10-second check and 30-second TOTP window. `used_timestamps` grows for the lifetime of the process. This is a test-only TCP demo, not the HEM transport. Evidence: [`totp_test/totp_receiver.py:6-9,33-50`](./totp_test/totp_receiver.py#L6-L9). |
| S9 | P2 | **Operational errors are hidden or weakly surfaced.** Dashboard `read_events()` silently returns an empty list for I/O errors and skips malformed lines; HEM `_log()` silently suppresses write errors. A dashboard can look merely empty and HEM can continue without durable audit records. Evidence: [`dashboard/server.py:53-73`](./dashboard/server.py#L53-L73), [`simulation/hem/controller.py:357-370`](./simulation/hem/controller.py#L357-L370). |
| S10 | Informational | **No AES-GCM nonce reuse or missing AAD found in the inspected paths.** Vault sealing uses 12 random bytes and item ID as AAD; chunk encryption uses 12 random bytes and binds item ID/index/count as AAD. Retries resend the same ciphertext/nonce rather than encrypting different plaintext under that nonce. No repeated-nonce test was found, but the code path inspected does not demonstrate reuse. Evidence: [`simulation/hem/vault.py:71-87`](./simulation/hem/vault.py#L71-L87), [`simulation/hem/exfil.py:27-49,83-96`](./simulation/hem/exfil.py#L27-L49). |
| S11 | Informational | **No user-controlled filesystem path was found in the dashboard/report path.** Static files are mounted from a fixed repository directory and `FileResponse` serves a fixed `index.html`; no endpoint concatenates a request path into a file path. Evidence: [`dashboard/server.py:18-20,200-202,330-333`](./dashboard/server.py#L18-L20). |

**Zeroization limitation:** The vault reassigns plaintext references, clears sealed entries, and drops its key/AES object; this is best-effort Python-level cleanup, not guaranteed cryptographic erasure of memory copies. README explicitly lists forensic-grade destruction as unavailable ([`simulation/hem/vault.py:111-121`](./simulation/hem/vault.py#L111-L121), [`README.md:406-420`](./README.md#L406)).

### Duplicate, dead, and misleading code

| Area | Finding |
|---|---|
| Root vs package | The legacy TCP pair was relocated to `simulation/legacy_tcp/`; it remains a separate port-5000 demo from the UDP port-9999 pipeline. The trust middleware and defense logic were relocated to `simulation/security/` and the runner imports them there. These features were retained rather than deleted. |
| HTML backup | The unused `dashboard/index.backup.html` was deleted; `dashboard.server.dashboard()` continues to serve `index.html` directly. |
| Validator backup | `simulation/validators/consistency_validator.py.save` is not imported (non-`.py` extension) and contains a malformed indented `def` at its start. Treat as a stale backup, not runnable source. |
| Repeated reporting | `simulation/analysis/report_generator.py`, `simulation/reporting/report_generator.py`, and `simulation/analysis/threat_dashboard.py` independently read/count the same log in overlapping ways. Only the analysis `ReportGenerator` is called by receiver; the other two are standalone. |
| Repeated analysis | `simulation/analysis/attack_classifier.py` classifies validation flags; `AttackAnalyzer` tracks temporal patterns. They are distinct but both are called “attack analysis/classification” across different paths and have incompatible validation inputs. |
| Unused symbols | The unused `math` import was removed from `simulation/telemetry/telemetry_engine.py`; `simulation/security/telemetry_middleware.py` still stores `anomaly_threshold` without reading it; `simulation/legacy_tcp/ground_control.py` records `start_time` without using it; receiver binds `addr` without checking it. |
| Import-time demos | `test_mujoco_suite.py` and `simulation_tests/mujoco_tests/simulation_runner.py` wildcard-import files that run loops at import time. `test_mujoco_suite.py` has no assertions, but slows pytest and emits misleading “suite completed” output. `telemetry_logger.py` also writes a CSV at import. |
| Other unused/dead behavior | `ResponseEnforcer` only annotates a packet/prints; the README diagrams it as enforcement. `simulation_tests/mujoco_tests/control_test.py` is a print-only placeholder; `navigation_manager.py` has no caller; `simulation_tests/mujoco_tests/simulation_runner.py` has all actual actions commented out. |
| Undeclared demo dependency | `totp_test/totp_sender.py` and `totp_test/totp_receiver.py` import `pyotp`, but it is absent from the pinned runtime and development manifests; these standalone scripts do not run in an environment installed from the declared dependencies. |
| Mutable defaults / unreachable code | No mutable list/dict function defaults or definite unreachable branch were identified in the application modules. No evidence that the high-level `PROTECT` branch is unreachable: HEM correctly checks `trust <= 0.2` and terminalizes the vault. |

### Testing gaps

**Validation performed before the layout cleanup:** `pytest -q` from an isolated temporary working directory completed with **13 passed in 81.97s**. The temporary working directory kept HEM's relative test log out of the repository. After this cleanup, Pytest is configured to collect only the actual tests under `tests/`; see the latest validation result in the task summary.

The prior 13 passing tests were all in `simulation/hem/test_hem.py`; HEM and ML tests now live under [`tests/simulation/`](./tests/simulation/). Pytest is configured to collect from `tests/`, so the import-time MuJoCo demo wrapper is no longer collected as an automated test.

| Coverage gap | Modules/branches with no meaningful pytest assertion |
|---|---|
| UDP orchestration and trust schema | `simulation/ground_control/receiver.py`, scenario start/reset messages, malformed/oversize packets, duplicate/replayed sequence, and receiver exception paths. |
| Validation and threshold boundaries | `simulation/security/telemetry_middleware.py`, `simulation/security/defense_logic.py`, both validators, attack classifier/analyzer, response engine/enforcer; including 0.80, 0.50, 0.20, analyzer window startup, invalid timestamps, and schema errors. |
| ML | [`tests/simulation/ml/test_anomaly_detector.py`](./tests/simulation/ml/test_anomaly_detector.py) checks untrained prediction, minimum training data, and an obvious outlier; malformed features and training contamination remain uncovered. |
| Dashboard | No FastAPI endpoint tests, CORS/auth checks, scenario concurrency/status tests, log tail/error tests, or JS DOM/XSS tests. |
| Logging/reporting | No concurrent append/read tests, retention/rotation behavior, malformed/truncated JSONL contract, or reporter failure tests. |
| HEM security/reliability | HEM tests cover normal transfer mechanics but not that sealing removes plaintext (it currently does not), remote TOTP proof, future peer timestamps, log-write failure, malformed peer secrets, repeated nonces, resource limits, or multiple concurrent callers. |
| Prototype suites | MuJoCo/Gazebo/Isaac and standalone TOTP modules have no meaningful automated behavior tests. `test_mujoco_suite.py` is discovered by pytest but contains no assertions. |

No coverage tool was run; branch coverage percentages are therefore unknown.

### Config sprawl / numeric constants

At the time of the initial audit there was no central configuration module or shared config schema. The values below are the operational/security/ML/simulation thresholds and timing/buffer limits found in source. Presentation-only CSS sizes/colors and sample SVG coordinates are excluded; they are not runtime security policy.

**Implementation follow-up (2026-11-02):** These audited settings are now centralized in `simulation/config.py`, loaded from `SCOUTX_*` environment variables or the repository `.env` file, and validated at startup. Standalone `simulation_tests/` examples use `DemoConfig` so demonstration constants remain separate from runtime policy.

| File | Hard-coded values / meaning |
|---|---|
| [`simulation/hem/controller.py:29,41,59-95,200-206`](./simulation/hem/controller.py#L29) | Trust transitions `<=0.2`, `<0.5`, `<0.8`; hysteresis margin `0.1`; budget `20,000` bytes; trust fallback/clamp `1.0` and `[0,1]`; output rounding to 2 decimals. |
| [`simulation/security/response_engine.py:6-25`](./simulation/security/response_engine.py#L6) | Failsafe `<0.2`; streak `>5` with HIGH severity; movement limit `>3`; default trust `1.0`. |
| [`simulation/analysis/attack_analyzer.py:2-4,23-38`](./simulation/analysis/attack_analyzer.py#L2) | History length `10`; persistent ratio `0.7`; intermittent ratio `0.4`; both truncated with `int()`. |
| [`simulation/ground_control/receiver.py:22-26,83,91,134-151`](./simulation/ground_control/receiver.py#L22) | Host `127.0.0.1`, port `9999`, receive buffer `4096`, ML clean-training sample count `8`, placeholder base secret `CHANGE-ME`; fallback trust `1.0`; canned scenario set. |
| [`simulation/hem/exfil.py:14-15,18,27-45,63,83-89`](./simulation/hem/exfil.py#L14) | Chunk `1024` bytes; retries `3`; nonce `12` bytes; HKDF output `32` bytes; receive total inferred from blob count. |
| [`simulation/hem/peers.py:16,38-70,80-91,100-120`](./simulation/hem/peers.py#L16) | Earth radius `6,371,000`; TOTP step `30` sec, `6` digits, verification window `1`; peer minimum trust `0.7`, link `0.4`, range `2,000m`, stale limit `10s`, capacity `5,000,000` bytes. |
| [`simulation/hem/vault.py:16-20,44,71-87,119-120`](./simulation/hem/vault.py#L16) | AES key size `256` bits; nonce `12` bytes; priority values `0/1/2`; zero-key byte length `32`. |
| [`simulation/ml/anomaly_detector.py:16-21,45-46,82-92`](./simulation/ml/anomaly_detector.py#L16) | `200` trees; contamination `0.10`; fixed random seed `42`; minimum training count `5`; risk transform midpoint `0.5`; feature count `5`. |
| [`simulation/validators/consistency_validator.py:26-53`](./simulation/validators/consistency_validator.py#L26) | Invalid/>`2s` delta reset to `1s`; degree-to-meter factor `111000`; speed mismatch `>4`; GPS jump `>20m`; altitude delta `>5`; score penalties `0.4/0.4/0.3`; clamp `[0,1]`. |
| [`simulation/validators/motion_validator.py:36-44`](./simulation/validators/motion_validator.py#L36) | Raw-coordinate movement limit `speed * 0.001`; score penalty `0.4`; score floor `0`. |
| [`simulation/security/telemetry_middleware.py:3-4,34-44,51-76,84-90`](./simulation/security/telemetry_middleware.py#L3) | Initial trust `1.0`; unused threshold `0.6`; battery `[0,100]`; GPS bounds `90/180`; noise `>0.8`; altitude `>100`; altitude delta `>50`; trust adjustment `-0.1/+0.02`; trust clamp `[0,1]`. |
| [`simulation/security/defense_logic.py:7-28`](./simulation/security/defense_logic.py#L7) | Trust threshold `0.8`; altitude clamp `100`. |
| [`simulation/telemetry/telemetry_engine.py:6-30`](./simulation/telemetry/telemetry_engine.py#L6) | Bengaluru seed coordinates `12.9716/77.5946`; altitude/speed initial `10/5`; battery `100`; GPS jitter `0.0001`; altitude jitter `0.5`; speed jitter `0.2`; battery drain `0.05-0.2`; loop delay `1s` in runner. |
| [`simulation/runner/simulation_runner.py:18-19,24-32,68`](./simulation/runner/simulation_runner.py#L18) | UDP `127.0.0.1:9999`; attack sequence `5 < seq < 15`; injected altitude `+500`, latitude `+1.5`; delay `1s`. |
| [`dashboard/server.py:22-28,89-110,140-188,242`](./dashboard/server.py#L22) | Receiver `127.0.0.1:9999`; scenario send spacing `0.7s`, reset wait `0.2s`; external ADS-B center `12.9716/77.5946`, range `100`; HTTP timeout `8s`; normal scenario `8` packets; hard-coded scenario trust arrays; naive local timestamps. |
| [`dashboard/app.js:35-39,113,125-134,275-282,307,355-399,450,1094,1221-1279`](./dashboard/app.js#L35) | Trust presentation `0.7/0.2`; default map/center and zoom `8`; trail cap `250`; event timeline last `40`; polling `1s`, aircraft `30s`, simulated target refresh `1.5s`; scenario/UI timeouts `0.25/1.2s`; number conversion timestamp cutoff `1e12`; fixed secondary target locations/speeds/phases. |
| [`simulation/legacy_tcp/drone_sim.py:7-38`](./simulation/legacy_tcp/drone_sim.py#L7), [`simulation/legacy_tcp/ground_control.py:6-19`](./simulation/legacy_tcp/ground_control.py#L6) | Legacy TCP default port `5000` (environment override), receiver buffer `1024`, connect wait `1s`, initial coordinates, per-tick GPS `0.0001`, altitude `+1`, battery `-0.1`. |
| [`totp_test/totp_sender.py:4-6`](./totp_test/totp_sender.py#L4), [`totp_test/totp_receiver.py:4-9,39-45`](./totp_test/totp_receiver.py#L4) | Port `5000`; fixed TOTP seed; timestamp freshness `10s`; TOTP verification window `1`; IP allowlist literal. |
| [`simulation/demo/run_scenarios.py:6-79`](./simulation/demo/run_scenarios.py#L6) | UDP `127.0.0.1:9999`, `1s` send delay, normal packet range `1..8`, GPS/speed/battery scenario values and trust sequence down to `0.10`. |
| [`simulation_tests/mujoco_tests/camera_tracking.py:6-41`](./simulation_tests/mujoco_tests/camera_tracking.py#L6), [`simulation_tests/mujoco_tests/waypoint_patrol.py:5-36`](./simulation_tests/mujoco_tests/waypoint_patrol.py#L5) | Demo target/waypoint coordinates (`10,5` and points at `0/10`), duration/step values `20`, `0.1s`, target increment `0.5`, controller gain `0.2`, waypoint tolerance `0.5`, interpolation `0.2`, delay `0.2s`. |
| [`simulation_tests/mujoco_tests/intrusion_detection.py:4-33`](./simulation_tests/mujoco_tests/intrusion_detection.py#L4), [`simulation_tests/mujoco_tests/threat_assessment.py:3-28`](./simulation_tests/mujoco_tests/threat_assessment.py#L3) | Zone bounds `5..15`; random domain `0..20`; distance threshold `5`; speed `8`; score weights `50/30/20`, levels `70/40`; `20` or `10` demo iterations and `1s` sleep. |
| [`simulation_tests/mujoco_tests/target_generator.py:7-47`](./simulation_tests/mujoco_tests/target_generator.py#L7), [`simulation_tests/mujoco_tests/telemetry_logger.py:20-39`](./simulation_tests/mujoco_tests/telemetry_logger.py#L20) | Demo defaults: `0.5`, `5`, radius `10`, angle step `0.1`, walk step `1`, zigzag period/cutoff `20/10`; logger `50` samples, movement `0.1..1`, speed `5..15`, sleep `0.1s`. |
| [`simulation_tests/mujoco_tests/sensor_manager.py:4-13`](./simulation_tests/mujoco_tests/sensor_manager.py#L4) | Fixed demo GPS `(10.2, 5.1)`, altitude `25.4`, and battery `87`. |
| [`simulation_tests/gazebo_tests/scripts/surveillance_patrol.py:5-13`](./simulation_tests/gazebo_tests/scripts/surveillance_patrol.py#L5), [`simulation_tests/gazebo_tests/scripts/telemetry_monitor.py:5-14`](./simulation_tests/gazebo_tests/scripts/telemetry_monitor.py#L5) | Standalone demo delays `2s` and `1s`. |
| [`render-start.sh:9`](./render-start.sh#L9), [`README.md:352`](./README.md#L352), [`simulation/legacy_tcp/ground_control.py:7`](./simulation/legacy_tcp/ground_control.py#L7), [`simulation/ground_control/receiver.py:23`](./simulation/ground_control/receiver.py#L23) | Dashboard port default `8000`; README separately documents port `8000`, while the legacy TCP stack uses `5000` and UDP pipeline uses `9999`. |

## Prioritized fix list

Effort estimates: **S** = small, **M** = medium, **L** = large.

### P0 — urgent

**None identified for the explicitly documented local simulation-only scope.** The top issues below are P1 because the UDP receiver is loopback-bound by default and the repository disclaims real flight-control/radio integration. Reassess severity before any network-exposed or real-system integration.

### P1 — important

| Fix | Effort | Evidence |
|---|---:|---|
| Normalize/validate one telemetry schema at the receiver boundary; compute trust/detection server-side; make analyzer and ML training consume the same validated result. | M | C1, C4; `simulation/runner/simulation_runner.py`, `simulation/ground_control/receiver.py`, `simulation/analysis/attack_analyzer.py`. |
| Authenticate telemetry/control messages, enforce sequence/replay policy, reject malformed/non-finite values, and keep receiver network exposure explicit. | L | S1, C8. |
| Make the vault's storage and transfer model actually use ciphertext (or accurately label the feature as a sealed-copy simulation); verify no plaintext access while sealed. | L | S2. |
| Replace the placeholder base secret and local TOTP self-check with configured secrets and a real simulated remote proof protocol; keep test seeds isolated. | M | S3, S8. |
| Protect dashboard endpoints and restrict CORS; choose an explicit trusted-origin policy before binding on all interfaces. | M | S4. |
| Fix analyzer startup ratio behavior and add tests for zero, first packet, window boundaries, and exact trust thresholds. | S | C2, C3. |
| Reconcile `<0.2`/`<=0.2` and `0.7`/`0.8` policy across response, HEM, and dashboard using one config source. | S | C3, C7. |
| Add log retention/rotation and a safe tailing strategy; coordinate scenario completion with receiver processing and serialize writes if multiple processes are supported. | M | S5, S6, S9. |

### P2 — quality and resilience

| Fix | Effort | Evidence |
|---|---:|---|
| Correct validator units/geodesic handling; use measured elapsed time and report invalid clocks rather than replacing them with `1.0`. | M | C5, C6. |
| Normalize timestamps to timezone-aware UTC; validate peer timestamps against both past and future bounds. | S | C9. |
| Split testable code from import-time demos; replace wildcard imports and add meaningful assertions for endpoint, receiver, response, and ML paths. | M | Testing gaps. |
| Decide whether legacy TCP and simulator prototypes are supported; otherwise clearly quarantine/remove stale backups and duplicated reporters. | M | Duplicate/dead code section. |
| Add a central typed configuration object for ports, trust thresholds, timing, budgets, buffer sizes, and ML settings; document environment overrides. | M | Config sprawl section. |
| Remove the unused `math` import and unused `anomaly_threshold`, and add consistent annotations/schema types for public pipeline APIs. | S | Static-check and code inspection findings. |
| Escape aircraft tooltip strings and add a DOM-sink regression test. | S | S7. |
| Replace the toy TOTP replay set with bounded one-time-use semantics if the standalone demo remains supported. | S | S8. |
