"""Purpose-separated key derivation and authenticated transfer context."""

import json
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from simulation.config import settings


@dataclass(frozen=True)
class SessionKeys:
    """Keep independent per-session key purposes out of incidental repr/logging."""

    encryption: bytearray = field(repr=False)
    peer_auth: bytearray = field(repr=False)
    manifest_mac: bytearray = field(repr=False)

    def wipe(self) -> tuple[str, ...]:
        """Overwrite mutable key buffers before dropping their owner references."""
        wiped: list[str] = []
        for name in ("encryption", "peer_auth", "manifest_mac"):
            buffer = getattr(self, name)
            buffer[:] = b"\x00" * len(buffer)
            buffer.clear()
            wiped.append(name)
        return tuple(wiped)


@dataclass(frozen=True)
class TransferContext:
    """Context that must be authenticated for every encrypted chunk."""

    drone_id: str
    mission_id: str
    priority_class: str
    protocol_version: int = settings.hem.protocol_version


def hkdf_derive(
    master_secret: bytes | bytearray,
    salt: bytes | bytearray,
    info: bytes,
    length: int = settings.hem.hkdf_key_size_bytes,
) -> bytearray:
    """Derive a purpose-bound key so master material is never used directly."""
    if not master_secret:
        raise ValueError("master secret must not be empty")
    if not salt:
        raise ValueError("HKDF salt must not be empty")
    if not info:
        raise ValueError("HKDF info label must not be empty")
    return bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(bytes(master_secret))
    )


def derive_session_keys(
    master_secret: bytes | bytearray,
    salt: bytes | bytearray,
    dest_id: str,
    mission_id: str,
) -> SessionKeys:
    """Derive independent encryption, peer-auth, and manifest keys per session."""
    context = f"destination={dest_id};mission={mission_id}".encode("utf-8")
    prefix = b"SCOUT-X/HEM/v1/"
    return SessionKeys(
        encryption=hkdf_derive(master_secret, salt, prefix + b"encryption/" + context),
        peer_auth=hkdf_derive(master_secret, salt, prefix + b"peer-auth/" + context),
        manifest_mac=hkdf_derive(
            master_secret, salt, prefix + b"manifest-mac/" + context
        ),
    )


def canonical_json(value: object) -> bytes:
    """Serialize authenticated metadata deterministically across implementations."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def chunk_aad(
    item_id: str,
    chunk_index: int,
    total_chunks: int,
    context: TransferContext,
) -> bytes:
    """Bind the full transfer identity and ordering into AES-GCM authentication."""
    return canonical_json(
        {
            "drone_id": context.drone_id,
            "mission_id": context.mission_id,
            "item_id": item_id,
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
            "priority_class": context.priority_class,
            "protocol_version": context.protocol_version,
        }
    )
