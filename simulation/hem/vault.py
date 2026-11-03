"""Hold prioritized mission data and encrypt stored items with AES-256-GCM."""

import os
import time
import hashlib
import gc
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from simulation.config import settings
from simulation.hem.crypto import TransferContext, chunk_aad

CRITICAL = settings.hem.critical_priority
SENSITIVE = settings.hem.sensitive_priority
ROUTINE = settings.hem.routine_priority
PRIORITY_NAMES = {
    CRITICAL: "CRITICAL",
    SENSITIVE: "SENSITIVE",
    ROUTINE: "ROUTINE",
}


@dataclass
class DataItem:
    item_id: str
    priority: int
    plaintext: bytearray | None
    captured_at: float = field(default_factory=time.time)
    status: str = "STORED"
    stored_size: int = 0
    stored_sha256: str = ""

    def __post_init__(self) -> None:
        if self.plaintext is not None and not isinstance(self.plaintext, bytearray):
            self.plaintext = bytearray(self.plaintext)
        if self.plaintext is not None:
            self.stored_size = len(self.plaintext)
            self.stored_sha256 = hashlib.sha256(self.plaintext).hexdigest()

    @property
    def size(self) -> int:
        return len(self.plaintext) if self.plaintext is not None else self.stored_size

    def digest(self) -> str:
        if self.plaintext is not None:
            return hashlib.sha256(self.plaintext).hexdigest()
        return self.stored_sha256


class DataVault:
    def __init__(self) -> None:
        self._items: dict[str, DataItem] = {}
        self._sealed: dict[str, tuple[bytearray, bytearray]] = {}
        self._key: bytearray | None = bytearray(
            AESGCM.generate_key(bit_length=settings.hem.aes_key_bits)
        )
        self._aes: AESGCM | None = AESGCM(bytes(self._key))
        self.zeroized = False

    def add(self, item_id: str, priority: int, payload: bytes | bytearray) -> None:
        if self.zeroized:
            raise RuntimeError("vault already zeroized")
        if item_id in self._items:
            raise ValueError(f"duplicate vault item id: {item_id}")

        self._items[item_id] = DataItem(
            item_id,
            priority,
            bytearray(payload),
        )

    @property
    def items(self) -> tuple[DataItem, ...]:
        """Provide stable metadata iteration without exposing the internal mapping."""
        return tuple(self._items.values())

    def pending(self) -> list[DataItem]:
        """Items not yet transferred, most important first, then oldest first."""
        live = [i for i in self._items.values() if i.status in ("STORED", "SEALED")]

        return sorted(
            live,
            key=lambda i: (i.priority, i.captured_at),
        )

    def seal(self, item_id: str) -> None:
        """Encrypt one item at rest. Item id is bound in as associated data."""
        item = self._items[item_id]

        if item.status != "STORED":
            return
        if self._aes is None:
            raise RuntimeError("vault encryption key is unavailable")
        if item.plaintext is None:
            raise RuntimeError("stored plaintext is unavailable for sealing")

        nonce = os.urandom(settings.hem.nonce_size_bytes)

        ct = self._aes.encrypt(
            nonce,
            item.plaintext,
            chunk_aad(
                item_id,
                0,
                1,
                TransferContext(
                    drone_id=settings.network.drone_id,
                    mission_id=settings.hem.mission_id,
                    priority_class=PRIORITY_NAMES.get(
                        item.priority,
                        str(item.priority),
                    ),
                    protocol_version=settings.hem.protocol_version,
                ),
            ),
        )

        self._sealed[item_id] = (bytearray(nonce), bytearray(ct))
        item.stored_size = len(item.plaintext)
        item.stored_sha256 = hashlib.sha256(item.plaintext).hexdigest()
        item.plaintext[:] = b"\x00" * len(item.plaintext)
        item.plaintext.clear()
        item.plaintext = None
        item.status = "SEALED"

    def seal_all(self) -> None:
        for item in self.pending():
            self.seal(item.item_id)

    def get(self, item_id: str) -> DataItem:
        return self._items[item_id]

    def open_for_transfer(self, item_id: str) -> bytearray:
        """Decrypt a temporary transfer buffer without retaining plaintext in the vault."""
        item = self._items[item_id]
        if item.status not in ("STORED", "SEALED"):
            raise RuntimeError("item is not available for transfer")
        if item.status == "STORED" and item.plaintext is not None:
            return bytearray(item.plaintext)
        sealed = self._sealed.get(item_id)
        if sealed is None or self._aes is None:
            raise RuntimeError("sealed item or vault key is unavailable")
        nonce, ciphertext = sealed
        plaintext = self._aes.decrypt(
            bytes(nonce),
            bytes(ciphertext),
            chunk_aad(
                item_id,
                0,
                1,
                TransferContext(
                    drone_id=settings.network.drone_id,
                    mission_id=settings.hem.mission_id,
                    priority_class=PRIORITY_NAMES.get(
                        item.priority,
                        str(item.priority),
                    ),
                    protocol_version=settings.hem.protocol_version,
                ),
            ),
        )
        return bytearray(plaintext)

    def mark_transferred(self, item_id: str) -> None:
        self._items[item_id].status = "TRANSFERRED"

    def purge_transferred(self) -> dict[str, int]:
        wiped_plaintext = 0
        wiped_sealed = 0
        transferred_items = 0

        for item in self._items.values():
            if item.status == "TRANSFERRED":
                transferred_items += 1
                if item.plaintext is not None:
                    item.plaintext[:] = b"\x00" * len(item.plaintext)
                    item.plaintext.clear()
                    item.plaintext = None
                    wiped_plaintext += 1
                sealed = self._sealed.pop(item.item_id, None)
                if sealed is not None:
                    nonce, ciphertext = sealed
                    nonce[:] = b"\x00" * len(nonce)
                    ciphertext[:] = b"\x00" * len(ciphertext)
                    wiped_sealed += 1
                item.status = "PURGED"

        return {
            "plaintext_buffers": wiped_plaintext,
            "sealed_buffers": wiped_sealed,
            "transferred_items": transferred_items,
        }

    def zeroize(self) -> dict[str, list[str]]:
        """Overwrite owned mutable buffers and report cleanup that cannot be verified."""
        wiped: list[str] = []
        wiped_plaintext = 0
        for item in self._items.values():
            if item.status != "PURGED":
                if item.plaintext is not None:
                    item.plaintext[:] = b"\x00" * len(item.plaintext)
                    item.plaintext.clear()
                    item.plaintext = None
                    wiped_plaintext += 1
                item.status = "PURGED"

        wiped.append(f"plaintext_buffers:{wiped_plaintext}")
        sealed_count = len(self._sealed)
        for nonce, ciphertext in self._sealed.values():
            nonce[:] = b"\x00" * len(nonce)
            ciphertext[:] = b"\x00" * len(ciphertext)
        wiped.append(f"sealed_buffers:{sealed_count}")
        self._sealed.clear()
        if self._key is not None:
            self._key[:] = b"\x00" * len(self._key)
            self._key.clear()
            wiped.append("vault_key_buffer")
        else:
            wiped.append("vault_key_buffer:already_cleared")
        self._key = None
        self._aes = None
        self.zeroized = True
        gc.collect()
        return {
            "wiped": wiped,
            "could_not_verify": [
                "immutable copies held by callers or Python internals",
                "cryptography backend key material",
                "physical or forensic erasure",
            ],
        }

    def summary(self) -> dict[str, int]:
        output: dict[str, int] = {}

        for item in self._items.values():
            output[item.status] = output.get(item.status, 0) + 1

        return output
