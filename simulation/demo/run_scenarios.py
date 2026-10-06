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
        "gps": [
            12.9716 + (seq * 0.0004),
            77.5946 + (seq * 0.0004)
        ],
        "altitude": 100 + (seq % 3),
        "speed": 11 + (seq % 3),
        "battery": 95 - seq,
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

    for seq in range(1, 9):
        send_packet(sock, normal_packet(seq))

    print("\n[SCENARIO 2] TELEMETRY ATTACK")

    send_packet(sock, attack_packet(9, 0.70))
    send_packet(sock, attack_packet(10, 0.60))
    send_packet(sock, attack_packet(11, 0.50))

    print("\n[SCENARIO 3] CONTINUED COMPROMISE")

    send_packet(sock, attack_packet(12, 0.40))
    send_packet(sock, attack_packet(13, 0.30))
    send_packet(sock, attack_packet(14, 0.20))

    print("\n[SCENARIO 4] CRITICAL COMPROMISE")

    send_packet(sock, attack_packet(15, 0.15))
    send_packet(sock, attack_packet(16, 0.10))

    print("\n========================================")
    print("Demo packets sent.")
    print("========================================\n")

    sock.close()


if __name__ == "__main__":
    run_demo()