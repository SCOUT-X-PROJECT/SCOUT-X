"""
vault.py - holds the mission data the drone is carrying and keeps it encrypted at rest.

Every item gets a priority class so that when time is short we move the stuff
that matters most first. Keys live only in memory; zeroize() is the "burn it" button.
"""

import os
import time
import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CRITICAL, SENSITIVE, ROUTINE = 0, 1, 2
PRIORITY_NAMES = {
    0: "CRITICAL",
    1: "SENSITIVE",
    2: "ROUTINE",
}


@dataclass
class DataItem:
    item_id: str
    priority: int
    plaintext: bytes
    captured_at: float = field(default_factory=time.time)
    status: str = "STORED"

    @property
    def size(self):
        return len(self.plaintext)

    def digest(self):
        return hashlib.sha256(self.plaintext).hexdigest()


class DataVault:
    def __init__(self):
        self._items = {}
        self._sealed = {}
        self._key = AESGCM.generate_key(bit_length=256)
        self._aes = AESGCM(self._key)
        self.zeroized = False

    def add(self, item_id, priority, payload: bytes):
        if self.zeroized:
            raise RuntimeError("vault already zeroized")

        self._items[item_id] = DataItem(
            item_id,
            priority,
            payload,
        )

    def pending(self):
        """Items not yet transferred, most important first, then oldest first."""
        live = [
            i
            for i in self._items.values()
            if i.status in ("STORED", "SEALED")
        ]

        return sorted(
            live,
            key=lambda i: (i.priority, i.captured_at),
        )

    def seal(self, item_id):
        """Encrypt one item at rest. Item id is bound in as associated data."""
        item = self._items[item_id]

        if item.status != "STORED":
            return

        nonce = os.urandom(12)

        ct = self._aes.encrypt(
            nonce,
            item.plaintext,
            item_id.encode(),
        )

        self._sealed[item_id] = (nonce, ct)
        item.status = "SEALED"

    def seal_all(self):
        for item in self.pending():
            self.seal(item.item_id)

    def get(self, item_id):
        return self._items[item_id]

    def mark_transferred(self, item_id):
        self._items[item_id].status = "TRANSFERRED"

    def purge_transferred(self):
        count = 0

        for item in self._items.values():
            if item.status == "TRANSFERRED":
                item.plaintext = b""
                self._sealed.pop(item.item_id, None)
                item.status = "PURGED"
                count += 1

        return count

    def zeroize(self):
        """Last resort: drop every plaintext copy and the key. Not reversible."""
        for item in self._items.values():
            if item.status != "PURGED":
                item.plaintext = b""
                item.status = "PURGED"

        self._sealed.clear()
        self._key = b"\x00" * 32
        self._aes = None
        self.zeroized = True

    def summary(self):
        output = {}

        for item in self._items.values():
            output[item.status] = output.get(item.status, 0) + 1

        return output