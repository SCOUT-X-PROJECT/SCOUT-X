import time

from simulation.config import settings

demo = settings.demo

print("Starting telemetry monitor...\n")

telemetry_data = {
    "GPS": "ACTIVE",
    "IMU": "ACTIVE",
    "LiDAR": "ACTIVE",
    "Camera": "ACTIVE"
}

for sensor, status in telemetry_data.items():
    print(f"{sensor} Status: {status}")
    time.sleep(demo.telemetry_monitor_interval_seconds)

print("\nTelemetry validation completed.")
