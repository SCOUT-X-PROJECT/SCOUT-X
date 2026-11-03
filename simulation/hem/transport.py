"""
transport.py - pretend radio. Drops chunks at a configurable rate so we can
test retransmission without real hardware. Swap for a UDP/MAVLink transport later
(same send() contract: returns the receiver's ack or None).
"""

import random
import time
from collections.abc import Callable

from simulation.config import settings
from simulation.hem.exfil import ChunkManifest
from simulation.hem.peers import build_authenticated_command


class SimTransport:
    def __init__(
        self,
        loss_rate: float | None = None,
        seed: int | None = None,
        base_up: bool = True,
        tamper_rate: float | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.loss_rate = (
            settings.hem.packet_loss_rate if loss_rate is None else loss_rate
        )
        self.tamper_rate = (
            settings.hem.tamper_rate if tamper_rate is None else tamper_rate
        )
        self.rng = random.Random(
            settings.hem.transport_random_seed if seed is None else seed
        )
        self.base_up = base_up
        self.sleep_fn = sleep_fn
        self.base_inbox: dict[str, list[tuple[int, bytearray]]] = {}
        self.base_manifests: dict[str, ChunkManifest] = {}
        self.peer_inboxes: dict[str, dict[str, list[tuple[int, bytearray]]]] = {}
        self.peer_manifests: dict[str, dict[str, ChunkManifest]] = {}
        self.acknowledged_chunks: dict[str, dict[int, bytearray]] = {}
        self.acknowledgements: list[tuple[str, str, int]] = []
        self.tampering = False
        self.dropped_chunks = 0

    def request_authentication_proof(
        self,
        principal_id: str,
        challenge: str,
        secret: bytes,
        timestamp: int,
    ) -> bytes | None:
        """Model a destination signing a fresh, identity-bound session challenge."""
        if principal_id == "base" and not self.base_up:
            return None
        command = f"HEM_SESSION:{principal_id}:{challenge}"
        return build_authenticated_command(command, secret, timestamp)

    def retry_delay(self, attempt: int) -> float:
        """Return capped exponential backoff with reproducible symmetric jitter."""
        base = min(
            settings.hem.retry_backoff_base_seconds * (2**attempt),
            settings.hem.retry_backoff_max_seconds,
        )
        spread = base * settings.hem.retry_jitter_fraction
        return max(0.0, self.rng.uniform(base - spread, base + spread))

    def _drop(self) -> bool:
        return self.rng.random() < self.loss_rate

    def _maybe_tamper(self, blob: bytes) -> bytes:
        if (
            self.tampering
            or (self.tamper_rate > 0 and self.rng.random() < self.tamper_rate)
        ) and blob:
            b = bytearray(blob)
            b[0] ^= 0x01
            return bytes(b)
        return blob

    def send_to_base(
        self,
        item_id: str,
        idx: int,
        blob: bytes,
    ) -> tuple[str, str, int] | None:
        if not self.base_up:
            return None
        if self._drop():
            self.dropped_chunks += 1
            return None
        if idx == 0:
            self.base_inbox[item_id] = []
            self.base_manifests.pop(item_id, None)
        self.base_inbox.setdefault(item_id, []).append(
            (idx, bytearray(self._maybe_tamper(blob)))
        )
        self.acknowledged_chunks.setdefault(item_id, {})[idx] = self.base_inbox[
            item_id
        ][-1][1]
        self.acknowledgements.append(("BASE", item_id, idx))
        return ("ACK", item_id, idx)

    def resume_to_peer(
        self,
        peer_id: str,
        item_id: str,
        acknowledged: set[int],
    ) -> int:
        """Model a shared handoff spool forwarding existing ACKed chunks."""
        peer_chunks = self.peer_inboxes.setdefault(peer_id, {}).setdefault(
            item_id,
            [],
        )
        present = {index for index, _blob in peer_chunks}
        copied = 0
        for index in sorted(acknowledged - present):
            blob = self.acknowledged_chunks.get(item_id, {}).get(index)
            if blob is not None:
                peer_chunks.append((index, blob))
                copied += 1
        return copied

    def send_manifest_to_base(
        self,
        item_id: str,
        manifest: ChunkManifest,
    ) -> tuple[str, str] | None:
        if not self.base_up or self._drop():
            return None
        self.base_manifests[item_id] = manifest
        return ("ACK_MANIFEST", item_id)

    def send_to_peer(
        self,
        peer_id: str,
        item_id: str,
        idx: int,
        blob: bytes,
    ) -> tuple[str, str, int] | None:
        if self._drop():
            self.dropped_chunks += 1
            return None
        inbox = self.peer_inboxes.setdefault(peer_id, {})
        if idx == 0:
            inbox[item_id] = []
            self.peer_manifests.setdefault(peer_id, {}).pop(item_id, None)
        inbox.setdefault(item_id, []).append((idx, bytearray(self._maybe_tamper(blob))))
        self.acknowledged_chunks.setdefault(item_id, {})[idx] = inbox[item_id][-1][1]
        self.acknowledgements.append((peer_id, item_id, idx))
        return ("ACK", item_id, idx)

    def send_manifest_to_peer(
        self,
        peer_id: str,
        item_id: str,
        manifest: ChunkManifest,
    ) -> tuple[str, str] | None:
        if self._drop():
            return None
        self.peer_manifests.setdefault(peer_id, {})[item_id] = manifest
        return ("ACK_MANIFEST", item_id)

    def zeroize(self) -> dict[str, int]:
        """Overwrite retained mutable ciphertext copies and drop simulated inboxes."""
        buffers: dict[int, bytearray] = {}
        buffers.update(
            (id(blob), blob)
            for chunks in self.base_inbox.values()
            for _index, blob in chunks
        )
        buffers.update(
            (id(blob), blob)
            for peer_items in self.peer_inboxes.values()
            for chunks in peer_items.values()
            for _index, blob in chunks
        )
        buffers.update(
            (id(blob), blob)
            for chunks in self.acknowledged_chunks.values()
            for blob in chunks.values()
        )
        for buffer in buffers.values():
            buffer[:] = b"\x00" * len(buffer)
            buffer.clear()
        count = len(buffers)
        self.base_inbox.clear()
        self.base_manifests.clear()
        self.peer_inboxes.clear()
        self.peer_manifests.clear()
        self.acknowledged_chunks.clear()
        self.acknowledgements.clear()
        return {"ciphertext_buffers": count}
