from simulation.security.defense_logic import DefenseLogic
from simulation.security.telemetry_middleware import SecurityMiddleware
from simulation.telemetry.telemetry_engine import TelemetryEngine
from simulation.logging.attack_logger import AttackLogger

import socket
import time

from simulation.config import settings
from simulation.security.telemetry_auth import TelemetryAuthenticator

engine = TelemetryEngine()
defense = DefenseLogic()
logger = AttackLogger()
security = SecurityMiddleware(event_callback=logger.log_trust_transition)
authenticator = TelemetryAuthenticator.from_settings()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
simulation_tick = 0

while True:
    # Step 1: generate telemetry
    data = engine.update()
    simulation_tick += 1

    # Step 2: inject spoof attack
    if (
        settings.network.attack_start_sequence
        < simulation_tick
        < settings.network.attack_end_sequence
    ):
        data["altitude"] += settings.validation.altitude_attack_offset
        data["lat"] += settings.validation.latitude_attack_offset

    # Step 3: security validation
    validation_result = security.validate_telemetry(data)
    if not validation_result.accepted:
        print(
            "[REJECTED]",
            validation_result.reason_code.value,
            f"({validation_result.classification})",
            validation_result.offending_field,
        )
        engine.sequence -= 1
        time.sleep(settings.network.telemetry_interval_seconds)
        continue

    wire_packet = validation_result.packet
    if wire_packet is None:
        raise RuntimeError("Accepted telemetry validation returned no packet.")

    data = wire_packet.model_dump()
    data["seq"] = data["sequence"]
    data["gps"] = {"lat": data["lat"], "lon": data["lon"]}
    data["trust_score"] = security.trust_score
    data["trust_state"] = security.trust_state.value
    data["flagged"] = False
    data["validation"] = {
        "is_anomalous": False,
        "flags": [],
        "consistency": validation_result.to_dict(),
    }
    data = defense.apply_defense(data)

    # Step 4: classify the accepted packet using structured validation context.
    data["classified_attack"] = validation_result.classification

    # Only the strict schema crosses the UDP boundary.
    sock.sendto(
        authenticator.encode_packet(wire_packet.model_dump()),
        (settings.network.host, settings.network.udp_port),
    )

    # Step 5: logging
    pattern = {
        "pattern": data["classified_attack"],
        "severity": "HIGH" if data.get("flagged") else "LOW",
    }

    decision = data.get("enforced", "NONE")
    logger.log(data, pattern, decision)

    # Step 6: print output
    print("[SIMULATION]", data)

    time.sleep(settings.network.telemetry_interval_seconds)
