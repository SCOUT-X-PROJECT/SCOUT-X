"""
exfil.py - moves one data item to a destination in encrypted, authenticated chunks.

Each chunk is AES-256-GCM with the item id, index and total count bound in as
associated data, so a reordered, swapped or tampered chunk fails verification
on the far side. Lost chunks are retried a few times before we give up.
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CHUNK = 1024
MAX_RETRIES = 3


def derive_session_key(shared_secret: bytes, salt: bytes, dest_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"scoutx-hem:" + dest_id.encode()
    ).derive(shared_secret)


def _aad(item_id, idx, total):
    return f"{item_id}|{idx}|{total}".encode()


def make_chunks(item_id, payload: bytes, key: bytes):
    aes = AESGCM(key)
    parts = [
        payload[i:i + CHUNK]
        for i in range(0, len(payload), CHUNK)
    ] or [b""]

    total = len(parts)
    out = []

    for idx, part in enumerate(parts):
        nonce = os.urandom(12)
        out.append(
            nonce + aes.encrypt(
                nonce,
                part,
                _aad(item_id, idx, total)
            )
        )

    return out


def send_item(item, key, send_fn):
    """
    send_fn(item_id, idx, blob) -> ack or None.
    Returns (ok, stats). Never raises on a lossy link; just reports failure.
    """
    chunks = make_chunks(item.item_id, item.plaintext, key)
    sent, retries = 0, 0

    for idx, blob in enumerate(chunks):
        for attempt in range(1 + MAX_RETRIES):
            if send_fn(item.item_id, idx, blob):
                sent += 1
                break
            retries += 1
        else:
            return False, {
                "chunks": len(chunks),
                "sent": sent,
                "retries": retries
            }

    return True, {
        "chunks": len(chunks),
        "sent": sent,
        "retries": retries,
        "sha256": item.digest()
    }


def receive_item(item_id, blobs: dict, key: bytes, expected_sha256=None):
    """Far-end helper (used by tests and by the base-station script)."""
    aes = AESGCM(key)
    total = len(blobs)
    data = b""

    for idx in range(total):
        blob = blobs[idx]
        data += aes.decrypt(
            blob[:12],
            blob[12:],
            _aad(item_id, idx, total)
        )

    if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("digest mismatch after reassembly")

    return data