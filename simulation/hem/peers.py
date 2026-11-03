"""Peer eligibility and replay-resistant RFC 6238 authentication helpers."""

import hmac
import json
import math
import os
import re
import struct
import time
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock

from simulation.config import settings
from simulation.hem.crypto import hkdf_derive


def haversine_m(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """Use surface distance so peer-range checks reflect geographic separation."""
    p1, p2 = math.radians(lat1), math.radians(lat2)

    dlat = p2 - p1
    dlon = math.radians(lon2 - lon1)

    a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2

    return (
        2
        * settings.hem.earth_radius_meters
        * math.atan2(
            math.sqrt(a),
            math.sqrt(1 - a),
        )
    )


def totp(
    secret: bytes,
    now: float | None = None,
    step: int | None = None,
    digits: int | None = None,
) -> str:
    """Generate an RFC 6238 HMAC-SHA1 code with the configured period and width."""
    step = settings.hem.totp_step_seconds if step is None else step
    digits = settings.hem.totp_digits if digits is None else digits
    if not secret or step <= 0 or not 1 <= digits <= 10:
        raise ValueError("TOTP secret, period, and digit count must be valid")
    counter = int((now if now is not None else time.time()) // step)

    mac = hmac.new(
        secret,
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()

    offset = mac[-1] & 0x0F

    code = (
        struct.unpack(
            ">I",
            mac[offset : offset + 4],
        )[0]
        & 0x7FFFFFFF
    ) % (10**digits)

    return str(code).zfill(digits)


class TOTPReplayGuard:
    """Accept each matching RFC 6238 timestep at most once within its drift window."""

    def __init__(self) -> None:
        self._used_codes: dict[tuple[bytes, str], int] = {}
        self._lock = Lock()

    def clear(self) -> int:
        """Drop process-local replay fingerprints during session teardown."""
        with self._lock:
            count = len(self._used_codes)
            self._used_codes.clear()
            return count

    def verify(
        self,
        secret: bytes,
        code: str,
        now: float,
        step: int,
        window: int,
        digits: int,
    ) -> bool:
        """Check all allowed counters in constant-time, then atomically consume one."""
        if (
            not secret
            or step <= 0
            or window < 0
            or not re.fullmatch(rf"\d{{{digits}}}", code)
        ):
            return False

        current_counter = int(now // step)
        candidates = range(
            max(0, current_counter - window),
            current_counter + window + 1,
        )
        matches: list[int] = []
        for counter in candidates:
            expected = totp(secret, counter * step, step, digits)
            if hmac.compare_digest(expected, code):
                matches.append(counter)
        if not matches:
            return False

        secret_fingerprint = hashlib.sha256(secret).digest()
        token = (secret_fingerprint, code)
        with self._lock:
            self._used_codes = {
                used_token: accepted_counter
                for used_token, accepted_counter in self._used_codes.items()
                if accepted_counter >= current_counter - window
            }
            if token in self._used_codes:
                return False
            self._used_codes[token] = current_counter
            return True


def verify_totp(
    secret: bytes,
    code: str,
    now: float | None = None,
    step: int | None = None,
    window: int | None = None,
    *,
    replay_guard: TOTPReplayGuard,
) -> bool:
    """Verify a TOTP proof and reject reuse of the matching timestep."""
    step = settings.hem.totp_step_seconds if step is None else step
    window = settings.hem.totp_window if window is None else window
    digits = settings.hem.totp_digits
    now = now if now is not None else time.time()
    return replay_guard.verify(secret, code, now, step, window, digits)


def build_authenticated_command(
    command: str,
    secret: bytes,
    timestamp: int,
    *,
    salt: bytes | None = None,
) -> bytes:
    """Create an RFC 6238 proof plus a purpose-derived MAC over command metadata."""
    if not command or not secret:
        raise ValueError("command and TOTP secret must not be empty")
    salt = os.urandom(settings.hem.hkdf_salt_size_bytes) if salt is None else salt
    otp = totp(secret, float(timestamp))
    fields: dict[str, object] = {
        "version": settings.hem.protocol_version,
        "command": command,
        "timestamp": timestamp,
        "otp": otp,
        "salt": salt.hex(),
    }
    key = hkdf_derive(
        secret,
        salt,
        b"SCOUT-X/TOTP/v1/command-mac",
    )
    canonical = json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fields["signature"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_authenticated_command(
    payload: bytes,
    secret: bytes,
    now: float,
    replay_guard: TOTPReplayGuard,
) -> str | None:
    """Authenticate command, timestamp, and OTP without exposing parsing details."""
    if not secret:
        return None
    try:
        fields = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(fields, dict):
        return None
    command = fields.get("command")
    timestamp = fields.get("timestamp")
    otp = fields.get("otp")
    salt_hex = fields.get("salt")
    signature = fields.get("signature")
    if (
        not secret
        or fields.get("version") != settings.hem.protocol_version
        or not isinstance(command, str)
        or not command
        or isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or not isinstance(otp, str)
        or not isinstance(salt_hex, str)
        or not isinstance(signature, str)
        or set(fields)
        != {"version", "command", "timestamp", "otp", "salt", "signature"}
    ):
        return None
    if abs(now - timestamp) > settings.hem.totp_timestamp_freshness_seconds:
        return None
    try:
        salt = bytes.fromhex(salt_hex)
        supplied_mac = bytes.fromhex(signature)
    except ValueError:
        return None
    if (
        len(salt) != settings.hem.hkdf_salt_size_bytes
        or len(supplied_mac) != hashlib.sha256().digest_size
    ):
        return None

    authenticated_fields = {
        "version": fields["version"],
        "command": command,
        "timestamp": timestamp,
        "otp": otp,
        "salt": salt_hex,
    }
    canonical = json.dumps(
        authenticated_fields,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    key = hkdf_derive(secret, salt, b"SCOUT-X/TOTP/v1/command-mac")
    expected_mac = hmac.new(key, canonical, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, supplied_mac):
        return None
    if not verify_totp(
        secret,
        otp,
        now,
        replay_guard=replay_guard,
    ):
        return None
    return command


@dataclass
class Peer:
    peer_id: str
    lat: float
    lon: float
    trust: float
    link_quality: float
    secret: bytes | bytearray | None
    last_seen: float = 0.0
    capacity_bytes: int = settings.hem.peer_capacity_bytes
    accepted_bytes: int = 0

    def __post_init__(self) -> None:
        if self.secret is not None and not isinstance(self.secret, bytearray):
            self.secret = bytearray(self.secret)


@dataclass(frozen=True)
class RejectedPeer:
    """Explain why a candidate was excluded from destination selection."""

    peer_id: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ScoredPeer:
    """Expose normalized score factors for one eligible destination."""

    peer: Peer
    score: float
    factors: dict[str, float]


@dataclass(frozen=True)
class PeerDecision:
    """Deterministic peer choice and auditable candidate rejection reasons."""

    chosen_peer: Peer | None
    chosen_score: float | None
    rejected_peers: tuple[RejectedPeer, ...]
    scored_peers: tuple[ScoredPeer, ...]

    def to_dict(self) -> dict[str, object]:
        """Return safe JSON-ready reasoning without exposing peer secrets."""
        return {
            "chosen_peer": (
                None if self.chosen_peer is None else self.chosen_peer.peer_id
            ),
            "chosen_score": self.chosen_score,
            "rejected_peers": [
                {"peer_id": peer.peer_id, "reasons": list(peer.reasons)}
                for peer in self.rejected_peers
            ],
            "scored_peers": [
                {
                    "peer_id": candidate.peer.peer_id,
                    "score": candidate.score,
                    "factors": candidate.factors,
                }
                for candidate in self.scored_peers
            ],
        }


class PeerRegistry:
    def __init__(self) -> None:
        self.peers: dict[str, Peer] = {}

    def update(self, peer: Peer) -> None:
        peer.last_seen = peer.last_seen or time.time()
        self.peers[peer.peer_id] = peer

    def eligible(
        self,
        my_lat: float,
        my_lon: float,
        now: float | None = None,
    ) -> list[tuple[Peer, float]]:
        """Filter peers before transfer so protected data only uses eligible links."""

        now = now if now is not None else time.time()

        eligible_peers = []

        for peer in self.peers.values():
            distance = haversine_m(
                my_lat,
                my_lon,
                peer.lat,
                peer.lon,
            )

            if (
                peer.trust >= settings.hem.peer_minimum_trust
                and peer.link_quality >= settings.hem.peer_minimum_link
                and distance <= settings.hem.peer_distance_limit
                and now - peer.last_seen <= settings.hem.peer_stale_limit_seconds
                and peer.accepted_bytes < peer.capacity_bytes
            ):
                eligible_peers.append((peer, distance))

        # Trust matters most, then link quality, then distance.
        eligible_peers.sort(
            key=lambda item: (
                -item[0].trust,
                -item[0].link_quality,
                item[1],
            )
        )

        return eligible_peers

    def select(
        self,
        my_lat: float,
        my_lon: float,
        now: float,
        totp_validator: Callable[[Peer], bool],
    ) -> PeerDecision:
        """Score all peers deterministically and retain explicit exclusion reasons."""
        scored: list[ScoredPeer] = []
        rejected: list[RejectedPeer] = []
        stale_limit = settings.hem.peer_stale_limit_seconds
        distance_limit = settings.hem.peer_distance_limit

        for peer in sorted(self.peers.values(), key=lambda item: item.peer_id):
            distance = haversine_m(my_lat, my_lon, peer.lat, peer.lon)
            age = max(0.0, now - peer.last_seen)
            reasons: list[str] = []
            if peer.trust < settings.hem.peer_minimum_trust:
                reasons.append("below_trust_floor")
            if peer.link_quality < settings.hem.peer_minimum_link:
                reasons.append("below_link_quality_floor")
            if distance > distance_limit:
                reasons.append("above_max_distance")
            if age > stale_limit:
                reasons.append("stale_peer")
            if peer.accepted_bytes >= peer.capacity_bytes:
                reasons.append("capacity_exhausted")
            if not reasons and not totp_validator(peer):
                reasons.append("totp_not_validated")
            if reasons:
                rejected.append(RejectedPeer(peer.peer_id, tuple(reasons)))
                continue

            factors = {
                "trust": min(1.0, max(0.0, peer.trust)),
                "link_quality": min(1.0, max(0.0, peer.link_quality)),
                "distance": min(1.0, max(0.0, 1.0 - distance / distance_limit)),
                "recency": (
                    1.0
                    if stale_limit == 0
                    else min(1.0, max(0.0, 1.0 - age / stale_limit))
                ),
                "totp_validated": 1.0,
            }
            weights = {
                "trust": settings.hem.peer_weight_trust,
                "link_quality": settings.hem.peer_weight_link,
                "distance": settings.hem.peer_weight_distance,
                "recency": settings.hem.peer_weight_recency,
                "totp_validated": settings.hem.peer_weight_totp,
            }
            score = sum(factors[name] * weights[name] for name in factors)
            scored.append(ScoredPeer(peer, score, factors))

        scored.sort(key=lambda candidate: (-candidate.score, candidate.peer.peer_id))
        chosen = scored[0] if scored else None
        return PeerDecision(
            chosen_peer=None if chosen is None else chosen.peer,
            chosen_score=None if chosen is None else chosen.score,
            rejected_peers=tuple(rejected),
            scored_peers=tuple(scored),
        )
