"""Phase 6 proof tests for contracts, scenario wiring, and import layering."""

import ast
from pathlib import Path
import time

from simulation.analysis.attack_classifier import AttackClassifier
from simulation.contract_adapters import (
    AnomalyDetectorAdapter,
    AttackClassifierAdapter,
    EnforcerAdapter,
    HemControllerAdapter,
    JsonlEventSinkAdapter,
    MiddlewareValidatorAdapter,
    ResponseEngineAdapter,
    TrustEngineAdapter,
)
from simulation.contracts import (
    AnomalyDetector,
    Classifier,
    DataProtector,
    Enforcer,
    EventSink,
    ResponseEngine,
    TrustEngine,
    Validator,
)
from simulation.demo.run_scenarios import SCENARIOS, run_scenario
from simulation.hem import DataVault, HEMController, PeerRegistry, SimTransport
from simulation.hem.vault import CRITICAL
from simulation.ml.anomaly_detector import TelemetryAnomalyDetector
from simulation.security.enforcer import ResponseEnforcer
from simulation.security.response_engine import ResponseEngine as LegacyResponseEngine
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.security.trust_engine import TrustScoreEngine
from simulation.logging.jsonl import JsonlEventWriter
from simulation.ground_control.receiver import create_receiver


def test_all_legacy_adapters_satisfy_contract_protocols(tmp_path: Path) -> None:
    vault = DataVault()
    vault.add("proof", CRITICAL, b"proof")
    hem = HEMController(
        vault,
        PeerRegistry(),
        SimTransport(seed=1),
        base_secret=b"p" * 32,
        log_path=tmp_path / "hem.jsonl",
    )
    assert isinstance(MiddlewareValidatorAdapter(SecurityMiddleware()), Validator)
    assert isinstance(AttackClassifierAdapter(AttackClassifier()), Classifier)
    assert isinstance(TrustEngineAdapter(TrustScoreEngine()), TrustEngine)
    assert isinstance(
        AnomalyDetectorAdapter(TelemetryAnomalyDetector()),
        AnomalyDetector,
    )
    assert isinstance(ResponseEngineAdapter(LegacyResponseEngine()), ResponseEngine)
    assert isinstance(EnforcerAdapter(ResponseEnforcer()), Enforcer)
    assert isinstance(HemControllerAdapter(hem), DataProtector)
    assert isinstance(
        JsonlEventSinkAdapter(JsonlEventWriter(tmp_path / "events.jsonl")),
        EventSink,
    )


def test_four_readme_scenarios_use_pipeline_and_reach_expected_states() -> None:
    names = ("normal", "gps_spoofing", "command_injection", "critical")
    results = [run_scenario(SCENARIOS[name], headless=True) for name in names]

    assert [result.final_state for result in results] == [
        "STANDBY",
        "PROTECT",
        "PROTECT",
        "PROTECT",
    ]


def test_import_graph_has_no_cycle_and_contracts_are_bottom_layer() -> None:
    root = Path(__file__).parents[1]
    package_files = list((root / "simulation").rglob("*.py"))
    graph: dict[str, set[str]] = {}
    for path in package_files:
        module = ".".join(path.relative_to(root).with_suffix("").parts)
        graph[module] = set()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported = node.module
                if imported.startswith("simulation."):
                    graph[module].add(imported)

    def visit(module: str, stack: tuple[str, ...]) -> None:
        assert module not in stack, f"import cycle: {stack + (module,)}"
        for dependency in graph.get(module, set()):
            visit(dependency, stack + (module,))

    for module in graph:
        visit(module, ())

    assert not any(
        dependency.startswith("simulation.analysis")
        for dependency in graph["simulation.contracts"]
    )


def test_slow_subscriber_does_not_block_pipeline_event_publish() -> None:
    from simulation.pipeline import EventBus
    from simulation.contracts import SecurityEvent
    from datetime import datetime, timezone

    bus = EventBus(queue_capacity=2)
    bus.subscribe_sink(lambda _event: time.sleep(0.5))
    event = SecurityEvent(
        correlation_id="slow:1",
        timestamp=datetime.now(timezone.utc),
        event_type="TEST",
        severity="INFO",
    )
    started = time.monotonic()
    for _ in range(20):
        bus.publish(event)
    elapsed = time.monotonic() - started
    bus.close()

    assert elapsed < 0.2


def test_receiver_initializes_development_secrets_before_binding() -> None:
    receiver, report = create_receiver()
    assert receiver.authenticator is not None
    assert report is not None
