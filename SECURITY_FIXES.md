# Security remediation

This pass was test-first: each listed change has a regression test and the
focused security/ML suite passed (`23 passed`).

| ID | Severity | Location | Exploit | Fix | Test |
|---|---|---|---|---|---|
| SEC-01 | High | `simulation/config.py` | Empty deployment credentials could make authentication fail open or use predictable defaults. | Development mode generates fresh credentials; non-development mode fails startup when required secrets are absent. | `test_development_secrets_are_ephemeral`, `test_non_development_requires_secrets` |
| SEC-02 | High | `simulation/ml/anomaly_detector.py` | A replaced joblib artifact could execute code during load. | Model artifacts are constrained to the trusted model directory in deployment mode and must match a SHA-256 sidecar hash before deserialization. | `test_model_hash_is_required_and_tampering_is_rejected` |
| SEC-03 | Medium | `simulation/logging/jsonl.py` | Newline/control-character injection could forge records or affect terminals. | Log strings are scrubbed before serialization while configured secrets remain redacted. | `test_log_strings_cannot_inject_records` |
| SEC-04 | High | `dashboard/server.py`, `dashboard/index.html`, `dashboard/app.js` | Inline configuration weakened a strict CSP and could become an injection sink. | Configuration is delivered as escaped metadata; browser code parses it, with no inline script or nonce exception. | `tests/dashboard/test_server.py` |
| SEC-05 | High | `dashboard/server.py`, `render-start.sh` | Accidental public binding could expose the dashboard. | Public binding requires an explicit configuration flag; Render sets that flag intentionally. | Dashboard lifespan startup checks |

## Remaining issues and decisions

- `joblib` is code-equivalent deserialization. Keep the model directory
  administrative-only and treat its hash metadata as integrity evidence, not
  a substitute for trusted deployment.
- `detect-secrets` is configured in pre-commit and pinned in
  `requirements-dev.txt`, but the executable was unavailable in this
  environment, so a fresh baseline/history scan still needs to run in CI.
- A `pip-audit` report still needs to be run in the provisioned development
  environment. Upgrade any vulnerable transitive dependency before deployment.
- Historical credentials, if found by the pending history scan, must be
  rotated outside the repository; deletion from Git history does not rotate
  them.
- Python memory zeroization and same-process simulated HEM transport remain
  best-effort limitations documented in `docs/THREAT_MODEL.md`.
