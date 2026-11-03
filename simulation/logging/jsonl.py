"""Thread-safe structured JSON Lines persistence with a verifiable hash chain."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic import SecretStr

from simulation.config import settings


GENESIS_HASH = "0" * 64
_LOCKS: dict[Path, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_SENSITIVE_PARTS = {
    "api",
    "auth",
    "credential",
    "key",
    "nonce",
    "otp",
    "password",
    "secret",
    "seed",
    "signature",
    "token",
}
_ANCHOR_SIZE_RESERVE = 256


class LogEvent(BaseModel):
    """Validate the stable event contract before anything reaches disk."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    event_id: str = Field(min_length=1, max_length=64)
    drone_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    severity: str = Field(min_length=1, max_length=32)
    trust: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    state: str | None = Field(default=None, max_length=128)
    details: dict[str, Any]

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc(cls, value: str) -> str:
        """Require UTC timestamps so ordering and report durations are comparable."""
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 datetime") from exc
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("timestamp must include a UTC timezone")
        return value


class JsonLogEntry(LogEvent):
    """Add integrity fields to a validated event without weakening its schema."""

    previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerificationResult(BaseModel):
    """Describe whether the retained log segment matches its integrity anchor."""

    valid: bool
    entries: int
    message: str
    line: int | None = None


def redact(value: Any, key: str = "") -> Any:
    """Remove secret-bearing values recursively before they enter the audit trail."""
    normalized_key = re.sub(r"(?<!^)(?=[A-Z])", "_", key)
    parts = set(re.sub(r"[^a-zA-Z0-9]+", "_", normalized_key).lower().split("_"))
    if parts & _SENSITIVE_PARTS or isinstance(value, (bytes, bytearray, SecretStr)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): redact(child_value, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(child) for child in value]
    if isinstance(value, str):
        for secret in _configured_secrets():
            if secret:
                value = value.replace(secret, "[REDACTED]")
        # Preserve one log record per line and prevent terminal/control injection.
        return "".join(
            character if character >= " " and character != "\x7f" else "?"
            for character in value
        )
    return value


def _configured_secrets() -> tuple[str, ...]:
    """Include configured credentials so accidental message copies are scrubbed."""
    secrets = (
        settings.network.telemetry_shared_secret,
        settings.trust.reset_token,
        settings.hem.base_secret,
        settings.hem.totp_demo_secret,
        settings.dashboard.api_key,
    )
    return tuple(
        secret.get_secret_value() for secret in secrets if secret.get_secret_value()
    )


def _canonical_bytes(entry: dict[str, Any]) -> bytes:
    return json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _entry_hash(entry_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(entry_without_hash)).hexdigest()


def _lock_for(path: Path) -> threading.RLock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(path.resolve(), threading.RLock())


def _rotation_paths(path: Path) -> list[Path]:
    backups: list[tuple[int, Path]] = []
    for candidate in path.parent.glob(f"{path.name}.*"):
        suffix = candidate.name.removeprefix(f"{path.name}.")
        if suffix.isdigit():
            backups.append((int(suffix), candidate))
    return [candidate for _, candidate in sorted(backups, reverse=True)] + [path]


def _first_previous_hash(paths: list[Path]) -> str | None:
    for candidate in paths:
        if not candidate.is_file() or candidate.stat().st_size == 0:
            continue
        with candidate.open("r", encoding="utf-8") as file:
            first_line = file.readline()
        try:
            record = json.loads(first_line)
            return str(record["previous_hash"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
    return None


def _line_count(path: Path) -> int:
    with path.open("rb") as file:
        return sum(chunk.count(b"\n") for chunk in iter(lambda: file.read(65536), b""))


class JsonlEventWriter:
    """Append validated events, rotating bounded files while preserving chain links."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_file_bytes: int | None = None,
        max_total_bytes: int | None = None,
        backup_count: int | None = None,
        rotate_interval_seconds: float | None = None,
    ) -> None:
        """Bind retention policy to a path so all producers share the same lock."""
        self.path = Path(path)
        self.max_file_bytes = (
            settings.logging.max_file_bytes
            if max_file_bytes is None
            else max_file_bytes
        )
        self.max_total_bytes = (
            settings.logging.max_total_bytes
            if max_total_bytes is None
            else max_total_bytes
        )
        self.backup_count = (
            settings.logging.backup_count if backup_count is None else backup_count
        )
        self.rotate_interval_seconds = (
            settings.logging.rotate_interval_seconds
            if rotate_interval_seconds is None
            else rotate_interval_seconds
        )
        if (
            self.max_file_bytes <= 0
            or self.max_total_bytes < self.max_file_bytes + _ANCHOR_SIZE_RESERVE
        ):
            raise ValueError(
                "max_total_bytes must exceed max_file_bytes by at least "
                f"{_ANCHOR_SIZE_RESERVE} bytes"
            )
        if self.backup_count < 0 or self.rotate_interval_seconds <= 0:
            raise ValueError("log rotation limits must be non-negative and positive")
        self.anchor_path = self.path.with_name(self.path.name + ".integrity.json")
        self._lock = _lock_for(self.path)

    def append(
        self,
        *,
        event_type: str,
        severity: str,
        details: dict[str, Any],
        drone_id: str | None = None,
        trust: float | None = None,
        state: str | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        """Validate, redact, hash, and append one complete event atomically per thread."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            anchor = self._load_or_initialize_anchor()
            instant = timestamp or datetime.now(timezone.utc)
            if instant.tzinfo is None or instant.utcoffset() != timezone.utc.utcoffset(
                instant
            ):
                raise ValueError("log timestamps must be timezone-aware UTC")
            event = LogEvent.model_validate(
                {
                    "timestamp": instant.astimezone(timezone.utc).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "drone_id": drone_id or settings.network.drone_id,
                    "event_type": event_type,
                    "severity": severity,
                    "trust": trust,
                    "state": state,
                    "details": redact(details),
                }
            ).model_dump(mode="json")
            chained = {**event, "previous_hash": anchor["head_hash"]}
            entry = {**chained, "entry_hash": _entry_hash(chained)}
            JsonLogEntry.model_validate(entry)
            encoded = _canonical_bytes(entry) + b"\n"
            if len(encoded) > self.max_file_bytes:
                raise ValueError("log event exceeds configured per-file size limit")

            if self._should_rotate(len(encoded)):
                self._rotate(anchor)
            self._prune(anchor, reserve_bytes=len(encoded))
            self._write_anchor(anchor)
            previous_size = self.path.stat().st_size if self.path.exists() else 0
            try:
                with self.path.open("ab") as file:
                    file.write(encoded)
                    file.flush()

                if anchor["entry_count"] == 0:
                    anchor["first_previous_hash"] = entry["previous_hash"]
                anchor["head_hash"] = entry["entry_hash"]
                anchor["entry_count"] = int(anchor["entry_count"]) + 1
                self._write_anchor(anchor)
            except Exception:
                if self.path.exists():
                    with self.path.open("r+b") as file:
                        file.truncate(previous_size)
                raise
            return entry

    def _anchor(self) -> dict[str, str | int]:
        return {
            "format_version": 1,
            "first_previous_hash": GENESIS_HASH,
            "head_hash": GENESIS_HASH,
            "entry_count": 0,
        }

    def _load_or_initialize_anchor(self) -> dict[str, str | int]:
        if self.anchor_path.exists():
            try:
                anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
                if (
                    anchor.get("format_version") != 1
                    or not isinstance(anchor.get("head_hash"), str)
                    or not isinstance(anchor.get("first_previous_hash"), str)
                    or not isinstance(anchor.get("entry_count"), int)
                    or anchor["entry_count"] < 0
                    or not re.fullmatch(r"[0-9a-f]{64}", anchor["head_hash"])
                    or not re.fullmatch(
                        r"[0-9a-f]{64}",
                        anchor["first_previous_hash"],
                    )
                ):
                    raise ValueError("invalid log integrity anchor")
                return anchor
            except (
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                AttributeError,
            ) as exc:
                raise ValueError("unable to read log integrity anchor") from exc

        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = [
            candidate for candidate in _rotation_paths(self.path) if candidate.exists()
        ]
        if any(candidate.stat().st_size for candidate in existing):
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            for candidate in existing:
                archived = candidate.with_name(candidate.name + f".legacy.{stamp}")
                os.replace(candidate, archived)
        anchor = self._anchor()
        self._write_anchor(anchor)
        return anchor

    def _should_rotate(self, incoming_bytes: int) -> bool:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return False
        if self.path.stat().st_size + incoming_bytes > self.max_file_bytes:
            return True
        age_seconds = datetime.now(timezone.utc).timestamp() - self.path.stat().st_mtime
        return age_seconds >= self.rotate_interval_seconds

    def _rotate(self, anchor: dict[str, str | int]) -> None:
        oldest = self.path.with_name(f"{self.path.name}.{self.backup_count}")
        if self.backup_count == 0:
            if self.path.exists():
                anchor["entry_count"] = max(
                    0,
                    int(anchor["entry_count"]) - _line_count(self.path),
                )
                self.path.unlink()
        else:
            if oldest.exists():
                anchor["entry_count"] = max(
                    0,
                    int(anchor["entry_count"]) - _line_count(oldest),
                )
                oldest.unlink()
            for index in range(self.backup_count - 1, 0, -1):
                source = self.path.with_name(f"{self.path.name}.{index}")
                if source.exists():
                    os.replace(
                        source, self.path.with_name(f"{self.path.name}.{index + 1}")
                    )
            if self.path.exists():
                os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

        self._prune(anchor)

    def _prune(
        self,
        anchor: dict[str, str | int],
        *,
        reserve_bytes: int = 0,
    ) -> None:
        retained = [
            candidate for candidate in _rotation_paths(self.path) if candidate.exists()
        ]
        total_size = sum(candidate.stat().st_size for candidate in retained)
        while (
            total_size + reserve_bytes + _ANCHOR_SIZE_RESERVE > self.max_total_bytes
            and retained
        ):
            oldest_retained = retained[0]
            anchor["entry_count"] = max(
                0,
                int(anchor["entry_count"]) - _line_count(oldest_retained),
            )
            total_size -= oldest_retained.stat().st_size
            oldest_retained.unlink()
            retained = [
                candidate
                for candidate in _rotation_paths(self.path)
                if candidate.exists()
            ]

        first_hash = _first_previous_hash(retained)
        anchor["first_previous_hash"] = (
            first_hash if first_hash is not None else str(anchor["head_hash"])
        )

    def _write_anchor(self, anchor: dict[str, str | int]) -> None:
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.anchor_path.parent,
            prefix=self.anchor_path.name,
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(anchor, file, sort_keys=True)
            file.write("\n")
            file.flush()
        try:
            for attempt in range(5):
                try:
                    os.replace(temporary_path, self.anchor_path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.01 * (2**attempt))
        finally:
            if temporary_path.exists():
                temporary_path.unlink()


def verify_log(path: str | Path) -> VerificationResult:
    """Check every retained link and its local anchor to find edits or gaps."""
    log_path = Path(path)
    anchor_path = log_path.with_name(log_path.name + ".integrity.json")
    try:
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return VerificationResult(
            valid=False,
            entries=0,
            message="integrity anchor is missing",
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return VerificationResult(
            valid=False, entries=0, message="integrity anchor is unreadable"
        )
    if not isinstance(anchor, dict):
        return VerificationResult(
            valid=False,
            entries=0,
            message="integrity anchor has an invalid structure",
        )
    if (
        anchor.get("format_version") != 1
        or type(anchor.get("entry_count")) is not int
        or anchor["entry_count"] < 0
        or not isinstance(anchor.get("head_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", anchor["head_hash"])
        or not isinstance(anchor.get("first_previous_hash"), str)
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            anchor["first_previous_hash"],
        )
    ):
        return VerificationResult(
            valid=False,
            entries=0,
            message="integrity anchor has invalid fields",
        )

    paths = [candidate for candidate in _rotation_paths(log_path) if candidate.exists()]
    if not paths:
        valid_empty = (
            anchor["entry_count"] == 0
            and anchor["head_hash"] == anchor["first_previous_hash"]
        )
        return VerificationResult(
            valid=valid_empty,
            entries=0,
            message="empty log verified" if valid_empty else "log files are missing",
        )

    expected_previous = anchor.get("first_previous_hash")
    if not isinstance(expected_previous, str) or not re.fullmatch(
        r"[0-9a-f]{64}",
        expected_previous,
    ):
        return VerificationResult(
            valid=False,
            entries=0,
            message="integrity anchor has an invalid starting hash",
        )
    entries = 0
    for candidate in paths:
        try:
            with candidate.open("r", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        continue
                    entries += 1
                    try:
                        raw = json.loads(line)
                        parsed = JsonLogEntry.model_validate(raw)
                    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
                        return VerificationResult(
                            valid=False,
                            entries=entries - 1,
                            line=entries,
                            message=f"invalid event: {exc}",
                        )
                    if parsed.previous_hash != expected_previous:
                        return VerificationResult(
                            valid=False,
                            entries=entries - 1,
                            line=entries,
                            message="previous hash does not match; an entry may be missing or reordered",
                        )
                    without_hash = parsed.model_dump(
                        mode="json", exclude={"entry_hash"}
                    )
                    calculated = _entry_hash(without_hash)
                    if calculated != parsed.entry_hash:
                        return VerificationResult(
                            valid=False,
                            entries=entries - 1,
                            line=entries,
                            message="entry hash mismatch; event content was edited",
                        )
                    expected_previous = parsed.entry_hash
        except (OSError, UnicodeError) as exc:
            return VerificationResult(
                valid=False,
                entries=entries,
                message=f"unable to read {candidate.name}: {exc}",
            )

    if entries != anchor.get("entry_count"):
        return VerificationResult(
            valid=False,
            entries=entries,
            message="entry count differs from the integrity anchor",
        )
    if expected_previous != anchor.get("head_hash"):
        return VerificationResult(
            valid=False,
            entries=entries,
            message="final hash differs from the integrity anchor",
        )
    return VerificationResult(valid=True, entries=entries, message="log chain verified")


def iter_log_paths(path: str | Path) -> list[Path]:
    """Return rotated log files in chronological order for consumers."""
    return [
        candidate for candidate in _rotation_paths(Path(path)) if candidate.exists()
    ]
