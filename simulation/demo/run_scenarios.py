import json
import socket
import time


HOST = "127.0.0.1"
PORT = 9999


def send_packet(sock, packet):
    data = json.dumps(packet).encode("utf-8")
    sock.sendto(data, (HOST, PORT))
    time.sleep(1)


def normal_packet(seq):
    return {
        "seq": seq,
        "gps": [12.9716, 77.5946],
        "altitude": 100,
        "speed": 12,
        "battery": 95,
        "trust_score": 1.0,
        "validation": {
            "is_anomalous": False,
            "flags": []
        }
    }


def attack_packet(seq, trust):
    return {
        "seq": seq,
        "gps": [13.5000, 77.9000],
        "altitude": 250,
        "speed": 45,
        "battery": 88,
        "trust_score": trust,
        "validation": {
            "is_anomalous": True,
            "flags": [
                "GPS_POSITION_JUMP",
                "ALTITUDE_ANOMALY"
            ]
        }
    }


def run_demo():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("\n========================================")
    print("        SCOUT-X SECURITY DEMO")
    print("========================================")

    print("\n[SCENARIO 1] NORMAL FLIGHT")
    for seq in range(1, 4):
        send_packet(sock, normal_packet(seq))

    print("\n[SCENARIO 2] TELEMETRY ATTACK")
    send_packet(sock, attack_packet(4, 0.70))
    send_packet(sock, attack_packet(5, 0.60))
    send_packet(sock, attack_packet(6, 0.50))

    print("\n[SCENARIO 3] CONTINUED COMPROMISE")
    send_packet(sock, attack_packet(7, 0.40))
    send_packet(sock, attack_packet(8, 0.30))
    send_packet(sock, attack_packet(9, 0.20))

    print("\n[SCENARIO 4] CRITICAL COMPROMISE")
    send_packet(sock, attack_packet(10, 0.15))
    send_packet(sock, attack_packet(11, 0.10))

    print("\n========================================")
    print("Demo packets sent.")
    print("========================================\n")

    sock.close()


if __name__ == "__main__":
    run_demo()