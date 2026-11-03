"""Send a sample command with RFC 6238 proof and command-bound authentication."""

import socket
import time

from simulation.config import settings
from simulation.hem.peers import build_authenticated_command


def main() -> None:
    """Send one authenticated sample without printing its OTP or MAC."""
    secret_value = settings.hem.totp_demo_secret.get_secret_value()
    if not secret_value:
        raise RuntimeError(
            "Set SCOUTX_HEM__TOTP_DEMO_SECRET before running the TOTP demo"
        )
    payload = build_authenticated_command(
        "MOVE_FORWARD",
        secret_value.encode("utf-8"),
        int(time.time()),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((settings.network.host, settings.network.tcp_port))
        sock.sendall(payload)
    print("Sent authenticated sample command.")


if __name__ == "__main__":
    main()
