"""
transport.py - pretend radio. Drops chunks at a configurable rate so we can
test retransmission without real hardware. Swap for a UDP/MAVLink transport later
(same send() contract: returns the receiver's ack or None).
"""
import random


class SimTransport:
    def __init__(self, loss_rate=0.0, seed=7, base_up=True):
        self.loss_rate = loss_rate
        self.rng = random.Random(seed)
        self.base_up = base_up
        self.base_inbox = {}          # item_id -> {chunk_idx: bytes}
        self.peer_inboxes = {}        # peer_id -> {(item_id, idx): bytes}
        self.tampering = False        # flip a bit in flight when True

    def _drop(self):
        return self.rng.random() < self.loss_rate

    def _maybe_tamper(self, blob):
        if self.tampering and blob:
            b = bytearray(blob)
            b[0] ^= 0x01
            return bytes(b)
        return blob

    def send_to_base(self, item_id, idx, blob):
        if not self.base_up or self._drop():
            return None
        self.base_inbox.setdefault(item_id, {})[idx] = self._maybe_tamper(blob)
        return ("ACK", item_id, idx)

    def send_to_peer(self, peer_id, item_id, idx, blob):
        if self._drop():
            return None
        self.peer_inboxes.setdefault(peer_id, {})[(item_id, idx)] = self._maybe_tamper(blob)
        return ("ACK", item_id, idx)