"""
peers.py - who is nearby, how far, and whether we trust them enough to hand data over.

Peer auth uses a time-based one-time code (RFC 6238 style, HMAC-SHA1, 30s step)
built on the standard library, so the swarm doesn't need extra packages.
"""

import hmac
import math
import struct
import time
import hashlib
from dataclasses import dataclass


EARTH_R = 6_371_000.0


def haversine_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)

    dlat = p2 - p1
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(p1)
        * math.cos(p2)
        * math.sin(dlon / 2) ** 2
    )

    return 2 * EARTH_R * math.atan2(
        math.sqrt(a),
        math.sqrt(1 - a),
    )


def totp(secret: bytes, now=None, step=30, digits=6):
    counter = int(
        (now if now is not None else time.time()) // step
    )

    mac = hmac.new(
        secret,
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()

    offset = mac[-1] & 0x0F

    code = (
        struct.unpack(
            ">I",
            mac[offset:offset + 4],
        )[0]
        & 0x7FFFFFFF
    ) % (10 ** digits)

    return str(code).zfill(digits)


def verify_totp(secret, code, now=None, step=30, window=1):
    now = now if now is not None else time.time()

    return any(
        hmac.compare_digest(
            totp(secret, now + delta * step, step),
            code,
        )
        for delta in range(-window, window + 1)
    )


@dataclass
class Peer:
    peer_id: str
    lat: float
    lon: float
    trust: float
    link_quality: float
    secret: bytes
    last_seen: float = 0.0
    capacity_bytes: int = 5_000_000
    accepted_bytes: int = 0


class PeerRegistry:
    MIN_TRUST = 0.7
    MIN_LINK = 0.4
    MAX_RANGE_M = 2000.0
    MAX_STALE_S = 10.0

    def __init__(self):
        self.peers = {}

    def update(self, peer: Peer):
        peer.last_seen = peer.last_seen or time.time()
        self.peers[peer.peer_id] = peer

    def eligible(self, my_lat, my_lon, now=None):
        """Peers we'd actually hand data to, best first."""

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
                peer.trust >= self.MIN_TRUST
                and peer.link_quality >= self.MIN_LINK
                and distance <= self.MAX_RANGE_M
                and now - peer.last_seen <= self.MAX_STALE_S
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