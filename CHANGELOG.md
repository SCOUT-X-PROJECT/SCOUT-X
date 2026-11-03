# Changelog

## Security re-audit — 2026-11-02

### Resolved P1 findings

- **C1 / C4:** Receiver-side validation is the source of truth for anomaly
  classification and ML-clean training. Dashboard scenarios now send raw,
  authenticated telemetry rather than trust or anomaly claims.
  Evidence: `is_clean_training_sample()` in
  `simulation/ground_control/receiver.py`, plus
  `test_accepted_sequence_gap_is_not_clean_ml_training_data` and
  `test_only_fully_clean_accepted_telemetry_trains_ml`.
- **C2:** Small attack-analysis windows use ceiling-based non-zero thresholds;
  clean startup packets remain `NORMAL`. Evidence:
  `tests/simulation/test_attack_analyzer.py`.
- **C3 / C7:** PROTECT uses the inclusive configured boundary across response
  handling and the dashboard display. Evidence:
  `tests/simulation/hem/test_hem.py::test_hem_phase_boundaries_match_readme`
  and `dashboard/app.js`.
- **S1:** UDP frames and controls require HMAC authentication, strict identity
  checks, sequence checks, timestamp freshness for controls, bounded intake,
  and a persistent bounded digest cache. Evidence:
  `test_exact_authenticated_frame_is_rejected_after_receiver_restart`,
  `test_shared_key_cannot_switch_to_an_unconfigured_drone_identity`, and
  `test_udp_receiver_accepts_signed_protect_reset_control`.
- **S2:** Sealing removes the vault's direct plaintext reference; transfer
  decrypts into a temporary mutable buffer and wipes it after use. Evidence:
  `test_vault_rejects_duplicate_ids_and_does_not_expose_sealed_plaintext`,
  `test_prepare_seals_but_doesnt_send`, and
  `test_zeroize_overwrites_owned_mutable_secrets_and_reports_limits`.
- **S3:** HEM destination selection now verifies a fresh destination-bound
  TOTP/HMAC challenge before deriving session keys. Evidence:
  `test_hem_session_requires_destination_bound_transport_proof`.
- **S4:** Sensitive dashboard reads, reports, and SSE require the configured
  API key or short-lived HttpOnly session cookie; health/version remain public.
  Evidence: `test_sensitive_read_routes_require_api_key_session`.
- **S5 / S9:** Structured JSONL logging is bounded, rotated, hash-chained,
  redacted, and read through bounded tails. Existing logging/reporting tests
  cover rotation, schema, redaction, and tamper detection.
- **S6:** Scenario completion waits for a signed receiver acknowledgment after
  the receiver drains queued telemetry. Evidence:
  `test_scenario_end_ack_waits_until_queued_telemetry_is_processed`.

### Adversarial coverage

Added regression coverage for malformed bytes, recursive/invalid JSON,
non-finite values, boolean-as-integer confusion, unknown fields, coordinate
overflow, stale timestamps, duplicate and reordered sequences, cross-identity
frames, restart replay, stale controls, sealed-vault access, duplicate vault
IDs, replayed HEM proofs, dashboard read authorization, and queue-drain
ordering. The focused security set passes **57 tests**.

### Validation

- `pytest -q`: **233 passed**
- `ruff check .`: **passed**
- `ruff format --check .`: **passed**
- `mypy --follow-imports=silent`: **passed (49 source files)**
- `python -m simulation.demo.run_scenarios --headless`: **passed; 11 scenarios**
- `python -m dashboard.server`: **passed; `/health` returned healthy**
- `python -m simulation.ground_control.receiver`: **passed; UDP
  `127.0.0.1:9999` bound**
- `node --check dashboard/app.js`: **passed**

## Remaining known issues

1. This is still a local simulation, not a production radio, aircraft,
   identity, or flight-control security boundary.
2. The HEM destination proof runs inside the same process and shares the
   configured secret; it is a deterministic simulated remote-proof boundary,
   not independent peer authentication.
3. Dashboard authentication is a single shared API key and cookie, without
   users, roles, CSRF tokens, key rotation, or revocation. Deploy behind a
   trusted access layer.
4. Replay-cache state is bounded and persistent, so entries older than the
   retention window can eventually be forgotten. SQLite file protection and
   filesystem compromise are outside scope.
5. Scenario state, event brokers, replay coordination, and worker lifecycle
   are process-local. Run one dashboard worker; multi-worker deployment needs
   shared coordination.
6. Python and cryptography-library memory handling cannot guarantee forensic
   erasure. Zeroization is best-effort cleanup of owned mutable buffers.
7. The legacy TCP and standalone demo scripts intentionally do not inherit the
   authenticated UDP pipeline and should not be used as secure transports.
8. External ADS-B feeds and map tiles are outside the trust boundary and may
   be unavailable or untrusted.
9. Remaining `print()` calls are deliberate CLI/demo/test output, not silent
   debugging paths. No TODO/FIXME markers or bare `except:` clauses remain.
