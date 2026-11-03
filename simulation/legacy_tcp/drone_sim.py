import socket
import json
import time
import subprocess
import sys

from simulation.config import settings


HOST = settings.network.host
PORT = settings.network.tcp_port

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

subprocess.Popen(
    [
        sys.executable,
        "-m",
        "simulation.legacy_tcp.ground_control",
    ]
)

time.sleep(settings.network.tcp_connect_wait_seconds)

sock.connect((HOST, PORT))

lat: float = settings.dashboard.aircraft_center_latitude
lon: float = settings.dashboard.aircraft_center_longitude
altitude: float = 0.0
battery: float = 100.0

while True:
    data = {"gps": {"lat": lat, "lon": lon}, "altitude": altitude, "battery": battery}

    sock.sendall((json.dumps(data) + "\n").encode())

    # Simulate changes
    lat += settings.validation.gps_jitter
    lon += settings.validation.gps_jitter
    altitude += settings.validation.legacy_altitude_step
    battery -= settings.validation.legacy_battery_drain

    time.sleep(settings.network.telemetry_interval_seconds)

    print("Telemetry:", data)
