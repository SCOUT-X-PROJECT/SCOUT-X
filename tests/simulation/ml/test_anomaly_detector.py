from simulation.ml.anomaly_detector import TelemetryAnomalyDetector


def packet(gps, altitude, speed, battery):
    return {
        "gps": gps,
        "altitude": altitude,
        "speed": speed,
        "battery": battery
    }


normal_packets = [
    packet([12.9716, 77.5946], 100, 12, 95),
    packet([12.9720, 77.5950], 102, 13, 94),
    packet([12.9725, 77.5955], 98, 11, 93),
    packet([12.9730, 77.5960], 101, 12, 92),
    packet([12.9735, 77.5965], 99, 13, 91),
    packet([12.9740, 77.5970], 103, 12, 90),
    packet([12.9745, 77.5975], 100, 11, 89),
    packet([12.9750, 77.5980], 102, 12, 88),
]


attack_packet = packet(
    [13.8000, 78.9000],
    500,
    80,
    88
)


detector = TelemetryAnomalyDetector()

detector.train(normal_packets)

result = detector.predict(attack_packet)

print("ML RESULT")
print(f"Anomaly: {result['ml_anomaly']}")
print(f"Risk score: {result['ml_score']:.4f}")

if result["ml_anomaly"]:
    print("PASS: attack telemetry detected")
else:
    print("WARNING: attack telemetry not detected")