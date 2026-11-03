import socket
import json
import time
import subprocess
import os

HOST = "127.0.0.1"
PORT = int(os.getenv("SCOUTX_PORT", "5000"))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

subprocess.Popen(["python", "ground_control.py"])

time.sleep(1)

sock.connect((HOST, PORT))

lat = 12.9716
lon = 77.5946
altitude = 0
battery = 100

while True:
    data = {
        "gps": {"lat": lat, "lon": lon},
        "altitude": altitude,
        "battery": battery
    }

    sock.sendall((json.dumps(data) + "\n").encode())

    # Simulate changes
    lat += 0.0001
    lon += 0.0001
    altitude += 1
    battery -= 0.1

    time.sleep(1)

    print("Telemetry:", data)