"""Authenticated, session-keyed chunk transfers for the HEM simulation."""

import hashlib
import hmac
import os
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from simulation.config import settings
from simulation.hem.crypto import (
    SessionKeys,
    TransferContext,
    chunk_aad,
    canonical_json,
)
from simulation.hem.vault import DataItem, PRIORITY_NAMES


@dataclass(frozen=True)
class ChunkManifest:
    """Authenticated inventory of an item's ordered, encrypted chunks."""

    item_id: str
    drone_id: str
    mission_id: str
    priority_class: str
    protocol_version: int
    chunk_size: int
    total_chunks: int
    plaintext_size: int
    plaintext_sha256: str
    chunk_sha256: tuple[str, ...]
    mac: str = field(repr=False)

    def authenticated_fields(self) -> dict[str, object]:
        """Return the canonical manifest body without its authenticator."""
        return {
            "item_id": self.item_id,
            "drone_id": self.drone_id,
            "mission_id": self.mission_id,
            "priority_class": self.priority_class,
            "protocol_version": self.protocol_version,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "plaintext_size": self.plaintext_size,
            "plaintext_sha256": self.plaintext_sha256,
            "chunk_sha256": list(self.chunk_sha256),
        }


class TransferState(StrEnum):
    """Terminal progress categories returned for each priority class."""

    DELIVERED = "DELIVERED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


@dataclass
class TransferProgress:
    """Retain encrypted chunks and destination ACKs so fallback resumes in place."""

    chunks: list[bytes]
    manifest: ChunkManifest
    plaintext_chunk_sizes: tuple[int, ...]
    acknowledged: set[int] = field(default_factory=set)
    attempts: dict[int, int] = field(default_factory=dict)
    manifest_acknowledged_destinations: set[str] = field(default_factory=set)


def encrypt_chunk(
    plaintext: bytes,
    key: bytes,
    item_id: str,
    chunk_index: int,
    total_chunks: int,
    context: TransferContext,
) -> bytes:
    """Encrypt one chunk under AES-256-GCM with a fresh random 96-bit nonce."""
    if len(key) != settings.hem.hkdf_key_size_bytes:
        raise ValueError("AES-256-GCM requires a 32-byte session key")
    nonce = os.urandom(settings.hem.nonce_size_bytes)
    ciphertext = AESGCM(bytes(key)).encrypt(
        nonce,
        plaintext,
        chunk_aad(item_id, chunk_index, total_chunks, context),
    )
    return nonce + ciphertext


def decrypt_chunk(
    blob: bytes,
    key: bytes,
    item_id: str,
    chunk_index: int,
    total_chunks: int,
    context: TransferContext,
) -> bytes:
    """Authenticate chunk bytes and all contextual metadata before returning data."""
    nonce_size = settings.hem.nonce_size_bytes
    if len(blob) < nonce_size + 16:
        raise ValueError("encrypted chunk is truncated")
    if len(key) != settings.hem.hkdf_key_size_bytes:
        raise ValueError("AES-256-GCM requires a 32-byte session key")
    return AESGCM(bytes(key)).decrypt(
        blob[:nonce_size],
        blob[nonce_size:],
        chunk_aad(item_id, chunk_index, total_chunks, context),
    )


def _manifest_mac(fields: dict[str, object], key: bytes) -> str:
    return hmac.new(key, canonical_json(fields), hashlib.sha256).hexdigest()


def _create_manifest(
    item: DataItem,
    context: TransferContext,
    chunks: list[bytes],
    keys: SessionKeys,
    plaintext: bytes | bytearray,
) -> ChunkManifest:
    chunk_digests = tuple(hashlib.sha256(chunk).hexdigest() for chunk in chunks)
    priority_class = PRIORITY_NAMES.get(item.priority, str(item.priority))
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    fields: dict[str, object] = {
        "item_id": item.item_id,
        "drone_id": context.drone_id,
        "mission_id": context.mission_id,
        "priority_class": priority_class,
        "protocol_version": context.protocol_version,
        "chunk_size": settings.hem.chunk_size,
        "total_chunks": len(chunks),
        "plaintext_size": len(plaintext),
        "plaintext_sha256": plaintext_sha256,
        "chunk_sha256": list(chunk_digests),
    }
    manifest = ChunkManifest(
        item_id=item.item_id,
        drone_id=context.drone_id,
        mission_id=context.mission_id,
        priority_class=priority_class,
        protocol_version=context.protocol_version,
        chunk_size=settings.hem.chunk_size,
        total_chunks=len(chunks),
        plaintext_size=len(plaintext),
        plaintext_sha256=plaintext_sha256,
        chunk_sha256=chunk_digests,
        mac=_manifest_mac(fields, keys.manifest_mac),
    )
    return manifest


def _manifest_is_valid(manifest: ChunkManifest, key: bytes) -> bool:
    if not isinstance(manifest, ChunkManifest):
        return False
    if (
        type(manifest.protocol_version) is not int
        or type(manifest.chunk_size) is not int
        or type(manifest.total_chunks) is not int
        or type(manifest.plaintext_size) is not int
        or not isinstance(manifest.chunk_sha256, (tuple, list))
    ):
        return False
    fields = manifest.authenticated_fields()
    if (
        not isinstance(manifest.item_id, str)
        or not isinstance(manifest.drone_id, str)
        or not isinstance(manifest.mission_id, str)
        or not isinstance(manifest.priority_class, str)
        or not isinstance(manifest.mac, str)
        or len(manifest.mac) != 64
        or any(character not in "0123456789abcdef" for character in manifest.mac)
        or manifest.total_chunks <= 0
        or manifest.chunk_size <= 0
        or manifest.plaintext_size < 0
        or manifest.total_chunks
        != max(
            1,
            (manifest.plaintext_size + manifest.chunk_size - 1) // manifest.chunk_size,
        )
        or len(manifest.chunk_sha256) != manifest.total_chunks
        or any(
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in manifest.chunk_sha256
        )
        or not isinstance(manifest.plaintext_sha256, str)
        or len(manifest.plaintext_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in manifest.plaintext_sha256
        )
    ):
        return False
    expected = _manifest_mac(fields, key)
    return hmac.compare_digest(expected, manifest.mac)


def make_chunks(
    item: DataItem,
    keys: SessionKeys,
    context: TransferContext,
    plaintext: bytes | bytearray | None = None,
) -> tuple[list[bytes], ChunkManifest]:
    """Encrypt and inventory chunks before any transfer attempt begins."""
    if context.priority_class != PRIORITY_NAMES.get(
        item.priority,
        str(item.priority),
    ):
        raise ValueError("transfer priority does not match the data item")
    data = item.plaintext if plaintext is None else plaintext
    if data is None:
        raise ValueError("sealed item requires a temporary plaintext transfer buffer")
    parts: list[bytes] = [
        bytes(data[index : index + settings.hem.chunk_size])
        for index in range(0, len(data), settings.hem.chunk_size)
    ] or [b""]
    total_chunks = len(parts)
    chunks = [
        encrypt_chunk(
            part,
            keys.encryption,
            item.item_id,
            index,
            total_chunks,
            context,
        )
        for index, part in enumerate(parts)
    ]
    return chunks, _create_manifest(item, context, chunks, keys, data)


def send_item(
    item: DataItem,
    keys: SessionKeys,
    send_fn: Callable[[str, int, bytes], object | None],
    manifest_fn: Callable[[str, ChunkManifest], object | None],
    context: TransferContext,
    *,
    progress: TransferProgress | None = None,
    byte_budget: int | None = None,
    destination_id: str = "destination",
    retry_delay: Callable[[int], float] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    plaintext: bytes | bytearray | None = None,
) -> tuple[bool, TransferProgress, dict[str, int | str]]:
    """Send missing chunks only, honoring a strict payload-byte budget and ACKs."""
    if progress is None:
        data = item.plaintext if plaintext is None else plaintext
        if data is None:
            raise ValueError(
                "sealed item requires a temporary plaintext transfer buffer"
            )
        chunks, manifest = make_chunks(item, keys, context, data)
        sizes = tuple(
            min(
                settings.hem.chunk_size,
                max(0, len(data) - index * settings.hem.chunk_size),
            )
            for index in range(len(chunks))
        )
        progress = TransferProgress(chunks, manifest, sizes)

    sent = 0
    retries = 0
    bytes_sent = 0
    failed = False
    delay_fn = retry_delay or (
        lambda attempt: min(
            settings.hem.retry_backoff_base_seconds * (2**attempt),
            settings.hem.retry_backoff_max_seconds,
        )
    )
    remaining = byte_budget
    failure_reason = ""
    budget_blocked = False

    for index, blob in enumerate(progress.chunks):
        if index in progress.acknowledged:
            continue
        chunk_size = progress.plaintext_chunk_sizes[index]
        if remaining is not None and chunk_size > remaining:
            failure_reason = "budget_exhausted"
            break

        acknowledged = False
        for attempt in range(settings.hem.retry_limit + 1):
            if remaining is not None and chunk_size > remaining:
                failure_reason = "budget_exhausted"
                budget_blocked = True
                break
            if remaining is not None:
                remaining -= chunk_size
            bytes_sent += chunk_size
            progress.attempts[index] = progress.attempts.get(index, 0) + 1
            ack = send_fn(item.item_id, index, blob)
            if (
                isinstance(ack, tuple)
                and len(ack) >= 3
                and ack[0] == "ACK"
                and ack[1] == item.item_id
                and ack[2] == index
            ):
                progress.acknowledged.add(index)
                sent += 1
                acknowledged = True
                break
            if attempt < settings.hem.retry_limit:
                retries += 1
                sleep(max(0.0, delay_fn(attempt)))

        if not acknowledged:
            if budget_blocked:
                break
            failed = True
            failure_reason = "chunk_ack_timeout"
            break

    all_chunks_acknowledged = len(progress.acknowledged) == len(progress.chunks)
    if (
        all_chunks_acknowledged
        and destination_id not in progress.manifest_acknowledged_destinations
    ):
        for attempt in range(settings.hem.retry_limit + 1):
            ack = manifest_fn(item.item_id, progress.manifest)
            if (
                isinstance(ack, tuple)
                and len(ack) >= 2
                and ack[0] == "ACK_MANIFEST"
                and ack[1] == item.item_id
            ):
                progress.manifest_acknowledged_destinations.add(destination_id)
                break
            if attempt < settings.hem.retry_limit:
                retries += 1
                sleep(max(0.0, delay_fn(attempt)))
        else:
            failed = True
            failure_reason = "manifest_ack_timeout"

    delivered = (
        all_chunks_acknowledged
        and destination_id in progress.manifest_acknowledged_destinations
    )
    state = (
        TransferState.DELIVERED
        if delivered
        else (
            TransferState.FAILED
            if failed and not progress.acknowledged
            else TransferState.PARTIAL
        )
    )
    stats: dict[str, int | str] = {
        "chunks": len(progress.chunks),
        "sent": sent,
        "bytes_sent": bytes_sent,
        "bytes_acknowledged": sum(
            progress.plaintext_chunk_sizes[index] for index in progress.acknowledged
        ),
        "retries": retries,
        "acknowledged_chunks": len(progress.acknowledged),
        "transfer_state": state.value,
        "failure_reason": failure_reason,
    }
    if delivered:
        stats["sha256"] = progress.manifest.plaintext_sha256
    return delivered, progress, stats


def receive_item(
    item_id: str,
    blobs: Mapping[int, bytes | bytearray] | Iterable[tuple[int, bytes | bytearray]],
    keys: SessionKeys,
    manifest: ChunkManifest,
    expected_context: TransferContext | None = None,
) -> bytes:
    """Verify manifest, exact chunk set, ordering, and plaintext digest before use."""
    if not _manifest_is_valid(manifest, keys.manifest_mac):
        raise ValueError("chunk manifest authentication failed")
    if manifest.item_id != item_id:
        raise ValueError("chunk manifest item does not match transfer")

    context = TransferContext(
        drone_id=manifest.drone_id,
        mission_id=manifest.mission_id,
        priority_class=manifest.priority_class,
        protocol_version=manifest.protocol_version,
    )
    if expected_context is not None and expected_context != context:
        raise ValueError("chunk manifest context does not match expected transfer")

    entries = blobs.items() if isinstance(blobs, Mapping) else blobs
    indexed_chunks: dict[int, bytes] = {}
    next_index = 0
    for index, blob in entries:
        if type(index) is not int or not isinstance(blob, (bytes, bytearray)):
            raise ValueError("chunk entry has an invalid index or payload")
        if index in indexed_chunks:
            raise ValueError("duplicate chunk index")
        if index != next_index:
            raise ValueError("chunks arrived out of manifest order")
        indexed_chunks[index] = blob
        next_index += 1

    expected_indices = set(range(manifest.total_chunks))
    if set(indexed_chunks) != expected_indices:
        raise ValueError("chunk set is incomplete or contains unexpected indices")

    plaintext_parts: list[bytes] = []
    for index in range(manifest.total_chunks):
        blob = indexed_chunks[index]
        expected_plaintext_length = (
            manifest.chunk_size
            if index < manifest.total_chunks - 1
            else manifest.plaintext_size
            - manifest.chunk_size * (manifest.total_chunks - 1)
        )
        expected_blob_length = (
            settings.hem.nonce_size_bytes + expected_plaintext_length + 16
        )
        if len(blob) != expected_blob_length:
            raise ValueError("encrypted chunk length does not match manifest")
        digest = hashlib.sha256(blob).hexdigest()
        if not hmac.compare_digest(digest, manifest.chunk_sha256[index]):
            raise ValueError("chunk does not match authenticated manifest")
        plaintext_parts.append(
            decrypt_chunk(
                bytes(blob),
                keys.encryption,
                item_id,
                index,
                manifest.total_chunks,
                context,
            )
        )

    plaintext = b"".join(plaintext_parts)
    if len(plaintext) != manifest.plaintext_size:
        raise ValueError("reassembled data length does not match manifest")
    digest = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(digest, manifest.plaintext_sha256):
        raise ValueError("reassembled data does not match authenticated manifest")
    return plaintext
