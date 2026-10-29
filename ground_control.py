import socket
import json
import os
from time import time

HOST = "127.0.0.1"
PORT = int(os.getenv("SCOUTX_PORT", "5000"))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Ground control listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print("Drone connected from", addr)
        start_time = time()
        while True:
            data = conn.recv(1024)
            if not data:
                break
            try:
                telemetry = json.loads(data.decode().strip())
                print("Telemetry received:", telemetry)
            except json.JSONDecodeError:
                print("Received non-JSON data:", data.decode().strip())