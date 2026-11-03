import json
import os
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidTag

from simulation.config import settings
from simulation.hem.controller import HEMController
from simulation.hem.crypto import (
    SessionKeys,
    TransferContext,
    derive_session_keys,
    hkdf_derive,
)
from simulation.hem.exfil import (
    decrypt_chunk,
    encrypt_chunk,
    make_chunks,
    receive_item,
)
from simulation.hem.peers import (
    TOTPReplayGuard,
    build_authenticated_command,
    totp,
    verify_authenticated_command,
)
from simulation.hem.peers import PeerRegistry
from simulation.hem.transport import SimTransport
from simulation.hem.vault import CRITICAL, DataItem, DataVault


MASTER_SECRET = b"hem-crypto-test-master-secret"
SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CONTEXT = TransferContext(
    drone_id="test-drone",
    mission_id="mission-test",
    priority_class="CRITICAL",
)


def session_keys() -> SessionKeys:
    return derive_session_keys(
        MASTER_SECRET,
        SALT,
        "base",
        CONTEXT.mission_id,
    )


def test_hkdf_rfc5869_sha256_known_answer() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    derived = hkdf_derive(ikm, salt, info, length=42)

    assert derived.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1_111_111_109, "07081804"),
        (1_111_111_111, "14050471"),
        (1_234_567_890, "89005924"),
        (2_000_000_000, "69279037"),
        (20_000_000_000, "65353130"),
    ],
)
def test_totp_rfc6238_sha1_known_answers(timestamp: int, expected: str) -> None:
    assert totp(b"12345678901234567890", timestamp, step=30, digits=8) == expected


def test_session_keys_are_salt_and_purpose_separated() -> None:
    keys = session_keys()
    changed_salt = derive_session_keys(
        MASTER_SECRET,
        os.urandom(settings.hem.hkdf_salt_size_bytes),
        "base",
        CONTEXT.mission_id,
    )

    assert (
        len(
            {
                bytes(keys.encryption),
                bytes(keys.peer_auth),
                bytes(keys.manifest_mac),
            }
        )
        == 3
    )
    assert keys.encryption != changed_salt.encryption
    assert keys.encryption not in (MASTER_SECRET, keys.peer_auth, keys.manifest_mac)
    assert MASTER_SECRET.decode() not in repr(keys)


@pytest.mark.parametrize(
    ("item_id", "chunk_index", "total_chunks", "context"),
    [
        ("other-item", 0, 1, CONTEXT),
        ("asset", 1, 1, CONTEXT),
        ("asset", 0, 2, CONTEXT),
        ("asset", 0, 1, replace(CONTEXT, drone_id="other-drone")),
        ("asset", 0, 1, replace(CONTEXT, mission_id="other-mission")),
        ("asset", 0, 1, replace(CONTEXT, priority_class="ROUTINE")),
        ("asset", 0, 1, replace(CONTEXT, protocol_version=2)),
    ],
)
def test_aad_context_tampering_fails_decryption(
    item_id: str,
    chunk_index: int,
    total_chunks: int,
    context: TransferContext,
) -> None:
    blob = encrypt_chunk(
        b"confidential",
        session_keys().encryption,
        "asset",
        0,
        1,
        CONTEXT,
    )

    with pytest.raises(InvalidTag):
        decrypt_chunk(
            blob,
            session_keys().encryption,
            item_id,
            chunk_index,
            total_chunks,
            context,
        )


def test_nonce_is_unique_across_one_hundred_thousand_encryptions() -> None:
    key = session_keys().encryption
    nonces = {
        encrypt_chunk(b"x", key, "asset", 0, 1, CONTEXT)[
            : settings.hem.nonce_size_bytes
        ]
        for _ in range(100_000)
    }

    assert len(nonces) == 100_000


def test_wrong_encryption_key_fails_authentication() -> None:
    blob = encrypt_chunk(b"payload", session_keys().encryption, "asset", 0, 1, CONTEXT)
    wrong_key = (
        bytes([session_keys().encryption[0] ^ 1]) + session_keys().encryption[1:]
    )

    with pytest.raises(InvalidTag):
        decrypt_chunk(blob, wrong_key, "asset", 0, 1, CONTEXT)


def test_manifest_detects_missing_reordered_duplicate_and_truncated_chunks() -> None:
    item = DataItem("asset", CRITICAL, b"A" * (settings.hem.chunk_size * 2 + 17))
    keys = session_keys()
    chunks, manifest = make_chunks(item, keys, CONTEXT)

    assert (
        receive_item(
            item.item_id,
            list(enumerate(chunks)),
            keys,
            manifest,
            CONTEXT,
        )
        == item.plaintext
    )
    with pytest.raises(ValueError, match="incomplete"):
        receive_item(item.item_id, list(enumerate(chunks[:-1])), keys, manifest)
    with pytest.raises(ValueError, match="duplicate"):
        receive_item(
            item.item_id,
            [*enumerate(chunks), (0, chunks[0])],
            keys,
            manifest,
        )
    with pytest.raises(ValueError, match="order"):
        receive_item(
            item.item_id,
            list(reversed(list(enumerate(chunks)))),
            keys,
            manifest,
        )

    reordered = list(enumerate(chunks))
    reordered[0] = (0, chunks[1])
    reordered[1] = (1, chunks[0])
    with pytest.raises(ValueError, match="manifest"):
        receive_item(item.item_id, reordered, keys, manifest)

    truncated = list(enumerate(chunks))
    truncated[0] = (0, chunks[0][:-1])
    with pytest.raises(ValueError, match="manifest"):
        receive_item(item.item_id, truncated, keys, manifest)


def test_manifest_tampering_and_wrong_key_are_rejected() -> None:
    item = DataItem("asset", CRITICAL, b"authenticated contents")
    keys = session_keys()
    chunks, manifest = make_chunks(item, keys, CONTEXT)

    with pytest.raises(ValueError, match="manifest authentication"):
        receive_item(
            item.item_id,
            list(enumerate(chunks)),
            keys,
            replace(manifest, mission_id="forged-mission"),
        )

    wrong_keys = replace(keys, manifest_mac=b"\x00" * 32)
    with pytest.raises(ValueError, match="manifest authentication"):
        receive_item(
            item.item_id,
            list(enumerate(chunks)),
            wrong_keys,
            manifest,
        )


def test_command_mac_binds_command_and_timestamp_and_rejects_replay() -> None:
    secret = b"standalone-demo-shared-secret"
    now = 1_800_000_000
    guard = TOTPReplayGuard()
    payload = build_authenticated_command("MOVE_FORWARD", secret, now)

    assert verify_authenticated_command(payload, secret, now, guard) == "MOVE_FORWARD"
    assert verify_authenticated_command(payload, secret, now, guard) is None

    tampered_command = json.loads(payload)
    tampered_command["command"] = "DISABLE_SAFETY"
    assert (
        verify_authenticated_command(
            json.dumps(tampered_command).encode(),
            secret,
            now,
            TOTPReplayGuard(),
        )
        is None
    )

    tampered_time = json.loads(payload)
    tampered_time["timestamp"] += 1
    assert (
        verify_authenticated_command(
            json.dumps(tampered_time).encode(),
            secret,
            now,
            TOTPReplayGuard(),
        )
        is None
    )


def test_totp_drift_is_limited_and_codes_are_consumed_once() -> None:
    secret = b"drift-window-secret"
    now = 1_800_000_000
    future_code = totp(secret, now + settings.hem.totp_step_seconds)

    assert TOTPReplayGuard().verify(
        secret,
        future_code,
        now,
        settings.hem.totp_step_seconds,
        1,
        settings.hem.totp_digits,
    )
    assert not TOTPReplayGuard().verify(
        secret,
        future_code,
        now,
        settings.hem.totp_step_seconds,
        0,
        settings.hem.totp_digits,
    )

    guard = TOTPReplayGuard()
    current_code = totp(secret, now)
    assert guard.verify(
        secret,
        current_code,
        now,
        settings.hem.totp_step_seconds,
        1,
        settings.hem.totp_digits,
    )
    assert not guard.verify(
        secret,
        current_code,
        now,
        settings.hem.totp_step_seconds,
        1,
        settings.hem.totp_digits,
    )


def test_hem_event_logging_scrubs_key_material(tmp_path) -> None:
    secret_text = "must-never-appear-in-a-log"
    log_path = tmp_path / "hem.jsonl"
    controller = HEMController(
        DataVault(),
        PeerRegistry(),
        SimTransport(),
        base_secret=secret_text.encode(),
        log_path=log_path,
    )

    controller._log(
        {
            "event": "TEST",
            "encryption_key": secret_text,
            "nested": {"master_secret": secret_text, "api-token": secret_text},
            "key_bytes": secret_text.encode(),
            "privateKey": secret_text,
        }
    )

    logged = log_path.read_text(encoding="utf-8")
    assert secret_text not in logged
    assert secret_text not in repr(controller.events)
    assert logged.count("[REDACTED]") == 5
