# SCOUT-X Scenario Evaluation

Generated: 2026-11-03T06:35:22.428181+00:00

Runs use deterministic per-scenario seeds. `Detect` is the share of ground-truth attack packets rejected by validation; `FPR` is the share of clean packets rejected. TTD and TTP are measured from the first ground-truth attack packet. `Protected before compromise` reports bytes sealed or transferred before the first labeled attack packet, grouped Critical/Sensitive/Routine. HEM receives trust-state signals but only validated telemetry coordinates, so rejected coordinates are not trusted.

| Scenario | Seed | Detect | FPR | TTD | TTP | Protected before compromise (C/S/R bytes) | Flaps | End state |
|---|---:|---:|---:|---:|---:|---|---:|---|
| normal | 4201 | 0.0% | 0.0% | n/a | n/a | 0/0/0 | 0 | STANDBY |
| gps_spoofing | 4202 | 100.0% | 0.0% | 0.0s | 3.0s | 0/0/0 | 1 | PROTECT |
| command_injection | 4203 | 100.0% | 0.0% | 0.0s | 4.0s | 0/0/0 | 0 | PROTECT |
| critical | 4204 | 100.0% | 0.0% | 0.0s | 2.0s | 0/0/0 | 1 | PROTECT |
| slow_gps_drift | 4205 | 0.0% | 0.0% | n/a | n/a | 0/0/0 | 0 | STANDBY |
| replay_attack | 4206 | 100.0% | 0.0% | 0.0s | 3.0s | 0/0/0 | 0 | PROTECT |
| telemetry_flooding | 4207 | 100.0% | 0.0% | 0.0s | 2.0s | 0/0/0 | 0 | PROTECT |
| battery_spoofing | 4208 | 100.0% | 0.0% | 0.0s | 8.0s | 0/0/0 | 0 | PROTECT |
| multi_vector | 4209 | 100.0% | 0.0% | 0.0s | 2.0s | 0/0/0 | 1 | PROTECT |
| intermittent_attack | 4210 | 100.0% | 0.0% | 0.0s | 24.0s | 0/0/0 | 0 | PROTECT |
| false_alarm | 4211 | 0.0% | 0.0% | n/a | n/a | 0/0/0 | 0 | STANDBY |

This is a deterministic software simulation, not a real flight-control or cryptographic-erasure performance claim.
