"""Authenticate telemetry framing before decoding untrusted JSON payloads."""

import hashlib
import hmac
import json
import struct
from typing import Any

from simulation.config import settings
from simulation.hem.crypto import hkdf_derive


_FRAME_PREFIX = struct.Struct("!4sBQ")
_FRAME_MAGIC = b"SXTP"
_FRAME_VERSION = 1
_MAC_SIZE = hashlib.sha256().digest_size
FRAME_HEADER_SIZE = _FRAME_PREFIX.size + _MAC_SIZE
_HKDF_SALT = b"SCOUT-X/telemetry/HKDF/v1"
_HKDF_INFO = b"SCOUT-X/telemetry/HMAC/v1"
_MAC_DOMAIN = b"SCOUT-X/telemetry/frame/v1\x00"


class TelemetryAuthenticationError(ValueError):
    """Raised when a datagram is not a valid authenticated telemetry frame."""


class TelemetryAuthenticator:
    """Create and verify bounded UDP frames using a purpose-derived HMAC key."""

    def __init__(self, shared_secret: str | bytes | bytearray) -> None:
        """Derive a dedicated frame key so the configured shared secret is never used directly."""
        secret = (
            shared_secret.encode("utf-8")
            if isinstance(shared_secret, str)
            else shared_secret
        )
        if not secret:
            raise ValueError(
                "Telemetry shared secret is required; set "
                "SCOUTX_NETWORK__TELEMETRY_SHARED_SECRET."
            )
        if len(secret) < 32:
            raise ValueError("Telemetry shared secret must contain at least 32 bytes.")
        self._key = hkdf_derive(secret, _HKDF_SALT, _HKDF_INFO)

    @classmethod
    def from_settings(cls) -> "TelemetryAuthenticator":
        """Load the sender/receiver secret from the shared validated settings."""
        return cls(settings.network.telemetry_shared_secret.get_secret_value())

    def encode_packet(self, packet: dict[str, Any]) -> bytes:
        """Serialize and authenticate a JSON packet with its sequence in the MAC."""
        sequence = packet.get("sequence")
        if (
            type(sequence) is not int
            or not 0 <= sequence <= settings.validation.max_sequence_number
        ):
            raise ValueError("telemetry sequence must be a configured-range integer")
        payload = json.dumps(
            packet,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > settings.validation.max_telemetry_payload_bytes:
            raise ValueError("telemetry payload exceeds the configured maximum")
        if len(payload) + FRAME_HEADER_SIZE > settings.network.max_datagram_size_bytes:
            raise ValueError(
                "authenticated frame exceeds the configured datagram maximum"
            )
        return self.encode_payload(sequence, payload)

    def encode_payload(self, sequence: int, payload: bytes) -> bytes:
        """Authenticate raw payload bytes for malformed-frame tests and protocol tools."""
        if (
            type(sequence) is not int
            or not 0 <= sequence <= settings.validation.max_sequence_number
        ):
            raise ValueError("telemetry sequence must be a configured-range integer")
        prefix = _FRAME_PREFIX.pack(_FRAME_MAGIC, _FRAME_VERSION, sequence)
        tag = hmac.new(
            self._key,
            _MAC_DOMAIN + prefix + payload,
            hashlib.sha256,
        ).digest()
        return prefix + tag + payload

    def decode_frame(self, frame: bytes) -> tuple[int, bytes]:
        """Verify the frame MAC before returning payload bytes for JSON parsing."""
        if len(frame) < FRAME_HEADER_SIZE:
            raise TelemetryAuthenticationError("truncated telemetry frame")

        prefix = frame[: _FRAME_PREFIX.size]
        magic, version, sequence = _FRAME_PREFIX.unpack(prefix)
        if magic != _FRAME_MAGIC or version != _FRAME_VERSION:
            raise TelemetryAuthenticationError("unsupported telemetry frame")

        supplied_tag = frame[_FRAME_PREFIX.size : FRAME_HEADER_SIZE]
        payload = frame[FRAME_HEADER_SIZE:]
        expected_tag = hmac.new(
            self._key,
            _MAC_DOMAIN + prefix + payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise TelemetryAuthenticationError("telemetry HMAC verification failed")
        return sequence, payload

    def close(self) -> None:
        """Overwrite the owned derived key when the receiver shuts down."""
        self._key[:] = b"\x00" * len(self._key)
        self._key.clear()
