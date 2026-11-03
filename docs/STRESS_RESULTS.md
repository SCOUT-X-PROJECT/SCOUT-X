# Stress verification results

This report contains measurements from the opt-in harness in
[`tests/stress/stress_harness.py`](../tests/stress/stress_harness.py). Stress
tests are excluded from the normal `pytest` command and run with:

```powershell
pytest tests\stress -m stress -o addopts="" --timeout=30
python tests\stress\stress_harness.py
```

## Measurement policy

The load test uses the real authenticated UDP receiver and `SecurityPipeline`.
The soak test advances 1,800 packet steps to represent 30 minutes of simulated
time; it does not claim 30 minutes of wall-clock operation. Memory is measured
with `tracemalloc` and RSS with `psutil`. A result is recorded only after the
harness has run on this checkout.

## Results

The following measurements were recorded on 2026-11-03 from the commands
above. The stress harness uses the real pipeline and Isolation Forest with
`n_estimators=10` for all pressure measurements so the runs complete within
the watchdog; production configuration uses the configured 200 estimators.

### Machine

| Item | Value |
|---|---|
| Platform | Windows 11 build 26300 |
| CPU | Intel64 Family 6 Model 142 Stepping 12 |
| CPUs | 8 |
| Python | 3.14.5 |
| psutil | 7.2.2 |

### Load

The default receiver rate limit is 20 packets/second with a burst capacity of
40. The short loopback runs admitted all offered packets; this is not a
production-model or network-capacity certification.

| Offered rate | Sent | Processed | Shed | Rejected | Lost | p50 ms | p95 ms | p99 ms | Peak Python bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10x | 20 | 20 | 0 | 0 | 0 | 45.707 | 995.780 | 995.780 | 170,557 |
| 50x | 28 | 28 | 0 | 0 | 0 | 30.087 | 949.018 | 980.342 | 133,406 |
| 100x | 34 | 34 | 0 | 0 | 0 | 43.851 | 816.442 | 846.976 | 219,110 |

The high tail latency is a measured limitation: the ML stage and bounded
receiver queue create backpressure before the short sender duration can offer
the nominal multiplier continuously.

### Malicious traffic

| Malformed | Oversized | Replayed | Forged HMAC | Valid processed |
|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 1 |

### Soak and concurrency

| Metric | Measured |
|---|---:|
| Simulated seconds | 1,800 |
| Packets | 1,800 |
| RSS delta | 528,384 bytes |
| Python peak allocation | 819,233 bytes |
| Threads before / after | 3 / 3 |
| Event queue capacity | 256 |
| Event subscribers | 0 |
| Current allocations | 413,358 bytes |
| Concurrent state reads | 500 |
| Final state version | 500 |

These results show bounded queue/state behavior for this run. They do not
prove flat RSS over a 30-minute wall-clock service run, file-handle stability,
or disk-full recovery; those remain unmeasured.

## Known limits

- The harness measures one local host and loopback UDP; it is not a radio or
  multi-host network certification.
- `pytest-timeout` provides the test watchdog; individual tests also use
  bounded joins and asyncio timeouts.
- File-handle and log-size observations require the full receiver/service
  command and are reported separately if those resources are exercised.
- The current load run does not yet include a sustained multi-minute sender,
  dashboard-client churn, base-link failure, corrupt state-file recovery, or
  receiver process restart measurement.
