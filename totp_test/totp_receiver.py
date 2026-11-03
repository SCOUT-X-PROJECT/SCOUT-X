"""Receive commands authenticated by a TOTP proof and a command-bound MAC."""

import socket
import time

from simulation.config import settings
from simulation.hem.peers import TOTPReplayGuard, verify_authenticated_command


def main() -> None:
    """Run the bounded local command receiver with per-process replay tracking."""
    secret_value = settings.hem.totp_demo_secret.get_secret_value()
    if not secret_value:
        raise RuntimeError(
            "Set SCOUTX_HEM__TOTP_DEMO_SECRET before running the TOTP demo"
        )
    secret = secret_value.encode("utf-8")
    allowed_ips = settings.network.allowed_client_ips
    replay_guard = TOTPReplayGuard()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((settings.network.host, settings.network.tcp_port))
    server.listen(1)
    print("Ground control listening...")

    while True:
        conn, address = server.accept()
        with conn:
            if address[0] not in allowed_ips:
                print("Rejected: unauthorized IP")
                continue
            conn.settimeout(settings.hem.totp_timestamp_freshness_seconds)
            received = bytearray()
            try:
                while len(received) <= settings.network.tcp_buffer_size:
                    fragment = conn.recv(
                        min(
                            settings.network.tcp_buffer_size,
                            settings.network.tcp_buffer_size + 1 - len(received),
                        )
                    )
                    if not fragment:
                        break
                    received.extend(fragment)
            except TimeoutError:
                received.clear()
            payload = (
                bytes(received)
                if len(received) <= settings.network.tcp_buffer_size
                else b""
            )
        command = verify_authenticated_command(
            payload,
            secret,
            time.time(),
            replay_guard,
        )
        if command is None:
            print("Rejected: invalid, expired, or replayed command")
        else:
            print("Accepted authenticated command:", command)


if __name__ == "__main__":
    main()
