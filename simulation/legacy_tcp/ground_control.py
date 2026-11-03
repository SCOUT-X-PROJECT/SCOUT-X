import socket
import json
from time import time

from simulation.config import settings


HOST = settings.network.host
PORT = settings.network.tcp_port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Ground control listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print("Drone connected from", addr)
        start_time = time()
        while True:
            data = conn.recv(settings.network.tcp_buffer_size)
            if not data:
                break
            try:
                telemetry = json.loads(data.decode().strip())
                print("Telemetry received:", telemetry)
            except json.JSONDecodeError:
                print("Received non-JSON data:", data.decode().strip())
