"""
SCOUT-X Handoff and Exfiltration Module (HEM).

Responsibilities:
- Move through STANDBY, PREPARE, EVACUATE, and PROTECT.
- Select authenticated destinations for protected data transfer.
- Seal data during elevated threat states.
- Zeroize the vault during PROTECT.
- Preserve an auditable final result after zeroization.

This is a simulation component, not a certified flight-safety system.
"""

import gc
import os
import re
import time
from pathlib import Path
from collections.abc import Callable
from typing import Any

from simulation.config import PROJECT_ROOT, settings
from simulation.security.trust_engine import TrustPolicy, TrustState
from simulation.hem.crypto import derive_session_keys
from simulation.logging.jsonl import JsonlEventWriter

from . import exfil
from .exfil import (
    SessionKeys,
    TransferContext,
    TransferProgress,
    TransferState,
)
from .peers import (
    PeerDecision,
    PeerRegistry,
    TOTPReplayGuard,
    verify_authenticated_command,
)
from .transport import SimTransport
from .vault import DataItem, DataVault, PRIORITY_NAMES


PHASES = [
    "STANDBY",
    "PREPARE",
    "EVACUATE",
    "PROTECT",
]


def _scrub_log_value(value: object, key: str = "") -> object:
    """Redact secret-bearing fields before they enter memory or JSON logs."""
    normalized_key = re.sub(r"(?<!^)(?=[A-Z])", "_", key)
    normalized_key = re.sub(r"[^a-zA-Z0-9]+", "_", normalized_key).lower()
    key_parts = normalized_key.split("_")
    sensitive_names = {"key", "secret", "token", "otp", "signature", "nonce"}
    if any(part in sensitive_names for part in key_parts):
        return "[REDACTED]"
    if isinstance(value, bytes):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): _scrub_log_value(child_value, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub_log_value(child) for child in value]
    return value


class HEMController:
    def __init__(
        self,
        vault: DataVault,
        peers: PeerRegistry,
        transport: SimTransport,
        base_secret: bytes | bytearray,
        peer_secrets: dict[str, bytes] | None = None,
        log_path: str | Path | None = None,
        per_cycle_budget: int | None = None,
        trust_policy: TrustPolicy | None = None,
    ) -> None:
        """Bind policy and resources once so every packet shares the same phase rules."""
        self.vault = vault
        self.peers = peers
        self.transport = transport
        self.base_secret: bytearray | None = (
            base_secret
            if isinstance(base_secret, bytearray)
            else bytearray(base_secret)
        )
        self.log_path = (
            log_path
            if log_path is not None
            else PROJECT_ROOT / settings.logging.directory / settings.logging.hem_log
        )
        self._log_writer = JsonlEventWriter(self.log_path)
        self.budget = (
            settings.hem.transfer_budget
            if per_cycle_budget is None
            else per_cycle_budget
        )
        self.trust_policy = trust_policy or TrustPolicy()
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)

        self.phase = "STANDBY"
        self._recovery_streak = 0
        self.session_keys: dict[str, tuple[SessionKeys, bytes]] = {}
        self.transfer_progress: dict[str, TransferProgress] = {}
        self.transfer_states: dict[str, TransferState] = {}
        self.peer_decision = PeerDecision(None, None, (), ())
        self._totp_replay_guard = TOTPReplayGuard()
        self.events: list[dict[str, Any]] = []

        # Preserve the final protection result after zeroization.
        self._terminal_result: dict[str, Any] | None = None

    # ---------- phase logic ----------

    def _target_phase(self, trust: float, response: str | None) -> str:
        if response in ("FORCE_LAND", "ISOLATE_DRONE") or self.trust_policy.is_protect(
            trust
        ):
            return "PROTECT"

        if trust < self.trust_policy.evacuate_threshold:
            return "EVACUATE"

        if trust < self.trust_policy.prepare_threshold:
            return "PREPARE"

        if trust >= self.trust_policy.standby_threshold:
            return "STANDBY"

        return "PREPARE"

    def _next_phase(
        self,
        trust: float,
        response: str | None,
        target_phase: str | None = None,
        clean_packet: bool = True,
    ) -> str:
        want = (
            self._target_phase(trust, response)
            if target_phase not in PHASES
            else target_phase
        )
        if response in ("FORCE_LAND", "ISOLATE_DRONE"):
            want = "PROTECT"

        cur_i = PHASES.index(self.phase)
        want_i = PHASES.index(want)

        # Escalation is immediate.
        if want_i > cur_i:
            self._recovery_streak = 0
            return want

        # PROTECT is terminal for this vault instance.
        if self.phase == "PROTECT":
            return "PROTECT"

        # A supplied trust-engine state has already passed its clean-packet gate.
        if target_phase in PHASES and want_i < cur_i:
            self._recovery_streak = 0
            return want

        # Recovery requires a margin above the current threshold.
        if want_i < cur_i:
            floor = (
                self.trust_policy.recovery_threshold(TrustState(self.phase))
                or settings.validation.minimum_score
            )

            if clean_packet and trust > floor + settings.trust.hysteresis_margin:
                self._recovery_streak += 1
            else:
                self._recovery_streak = 0

            if self._recovery_streak >= settings.trust.recovery_clean_packets:
                self._recovery_streak = 0
                return want
        else:
            self._recovery_streak = 0

        return self.phase

    # ---------- destinations ----------

    def _session(
        self,
        dest_id: str,
        secret: bytes | bytearray | None,
        now: float,
    ) -> SessionKeys | None:
        if dest_id in self.session_keys:
            return self.session_keys[dest_id][0]
        if not secret:
            return None

        challenge = os.urandom(settings.hem.session_challenge_size_bytes).hex()
        proof = self.transport.request_authentication_proof(
            dest_id,
            challenge,
            bytes(secret),
            int(now),
        )
        if proof is None:
            return None
        command = verify_authenticated_command(
            proof,
            bytes(secret),
            now,
            self._totp_replay_guard,
        )
        if command != f"HEM_SESSION:{dest_id}:{challenge}":
            return None

        salt = os.urandom(settings.hem.hkdf_salt_size_bytes)
        keys = derive_session_keys(
            secret,
            salt,
            dest_id,
            settings.hem.mission_id,
        )

        self.session_keys[dest_id] = (keys, salt)
        return keys

    def _pick_destination(
        self,
        my_lat: float,
        my_lon: float,
        now: float,
    ) -> tuple[str | None, str | None, SessionKeys | None]:
        self.peer_decision = PeerDecision(None, None, (), ())
        if self.transport.base_up and self.base_secret is not None:
            keys = self._session("base", self.base_secret, now)
            if keys is not None:
                return "BASE", "base", keys

        decision = self.peers.select(
            my_lat,
            my_lon,
            now,
            lambda peer: self._session(peer.peer_id, peer.secret, now) is not None,
        )
        self.peer_decision = decision
        if decision.chosen_peer is not None:
            keys = self._session(
                decision.chosen_peer.peer_id, decision.chosen_peer.secret, now
            )
            if keys is not None:
                return "PEER", decision.chosen_peer.peer_id, keys

        return None, None, None

    def zeroize(self) -> dict[str, list[str]]:
        """Overwrite owned mutable keys and data, then report unverifiable copies."""
        vault_result = self.vault.zeroize()
        wiped: list[str] = list(vault_result["wiped"])
        wiped_session_keys = 0
        for keys, _salt in self.session_keys.values():
            wiped_session_keys += len(keys.wipe())
        wiped.append(f"session_key_buffers:{wiped_session_keys}")
        self.session_keys.clear()

        if self.base_secret is not None:
            self.base_secret[:] = b"\x00" * len(self.base_secret)
            self.base_secret.clear()
            self.base_secret = None
        wiped.append("base_secret_buffer")

        wiped_peer_secrets = 0
        for peer in self.peers.peers.values():
            if isinstance(peer.secret, bytearray):
                peer.secret[:] = b"\x00" * len(peer.secret)
                peer.secret.clear()
                wiped_peer_secrets += 1
                peer.secret = None
        wiped.append(f"peer_secret_buffers:{wiped_peer_secrets}")
        replay_entries = self._totp_replay_guard.clear()
        wiped.append(f"totp_replay_entries:{replay_entries}")
        self.transfer_progress.clear()
        transport_result = self.transport.zeroize()
        wiped.append(
            f"transport_ciphertext_buffers:{transport_result['ciphertext_buffers']}"
        )
        gc.collect()
        return {
            "wiped": wiped,
            "could_not_verify": [
                *vault_result["could_not_verify"],
                "immutable copies supplied by callers",
                "configured secrets retained in Settings",
                "copies retained by the cryptography backend",
                "physical or forensic erasure",
            ],
        }

    # ---------- GPS handling ----------

    @staticmethod
    def _gps_coordinates(gps: Any) -> tuple[float, float]:
        """Accept dictionary or list/tuple GPS coordinates."""
        try:
            if isinstance(gps, dict):
                return (
                    float(gps.get("lat", 0.0)),
                    float(gps.get("lon", 0.0)),
                )

            if isinstance(gps, (list, tuple)) and len(gps) >= 2:
                return float(gps[0]), float(gps[1])
        except (TypeError, ValueError):
            pass

        return 0.0, 0.0

    # ---------- terminal result handling ----------

    def _remember_terminal_result(self, result: dict[str, Any]) -> None:
        """Cache the final result so later packets retain the outcome."""
        self._terminal_result = dict(result)

    def _terminal_result_for_packet(
        self,
        packet: dict[str, Any],
        trust: float,
    ) -> dict[str, Any]:
        """Return the cached result with current packet metadata."""
        if self._terminal_result is None:
            # Handles a vault that was already zeroized before this
            # controller received its first packet.
            result: dict[str, Any] = {
                "hem_phase": self.phase,
                "destination": None,
                "kind": None,
                "moved": 0,
                "moved_ids": [],
                "zeroized": True,
                "items_lost_to_zeroize": 0,
                "vault": self.vault.summary(),
            }
            self._remember_terminal_result(result)

        cached_result = self._terminal_result
        if cached_result is None:
            raise RuntimeError("Terminal HEM result was not initialized.")
        result = dict(cached_result)
        result["seq"] = packet.get("seq")
        result["trust"] = round(trust, settings.logging.decimal_precision)
        result["hem_phase"] = "PROTECT"
        result["zeroized"] = True

        return result

    # ---------- main entry ----------

    def on_packet(
        self,
        packet: dict[str, Any],
        now: float | None = None,
    ) -> dict[str, Any]:
        """Advance HEM once per telemetry packet so protection stays auditable."""
        now = time.time() if now is None else now

        try:
            trust = float(packet.get("trust_score", settings.trust.default_score))
        except (TypeError, ValueError):
            trust = settings.trust.default_score

        # Fail closed for invalid trust values.
        if not (
            settings.validation.minimum_score
            <= trust
            <= settings.validation.maximum_score
        ):
            trust = settings.validation.minimum_score

        response = packet.get("response")

        # Once the vault is destroyed, never process it as a new
        # mission or imply that the data can be recovered.
        if self.vault.zeroized:
            self.phase = "PROTECT"
            return self._terminal_result_for_packet(packet, trust)

        validation = packet.get("validation", {})
        clean_packet = not validation.get("is_anomalous", False)
        target_phase = packet.get("trust_state")
        new_phase = self._next_phase(
            trust,
            response,
            target_phase=target_phase,
            clean_packet=clean_packet,
        )
        changed = new_phase != self.phase
        self.phase = new_phase

        result = {
            "seq": packet.get("seq"),
            "hem_phase": self.phase,
            "trust": round(trust, settings.logging.decimal_precision),
        }

        if changed:
            self._log(
                {
                    "event": "PHASE_CHANGE",
                    **result,
                }
            )

        if self.phase in ("PREPARE", "EVACUATE", "PROTECT"):
            self.vault.seal_all()

        if self.phase in ("EVACUATE", "PROTECT"):
            lat, lon = self._gps_coordinates(packet.get("gps", [0.0, 0.0]))

            result.update(self._evacuate(lat, lon, now))

        if self.phase == "PROTECT":
            purged_transferred = self.vault.purge_transferred()
            unsent_items = len(self.vault.pending())
            zeroization = self.zeroize()
            zeroization["wiped"].append(
                "transferred_plaintext_buffers:"
                f"{purged_transferred['plaintext_buffers']}"
            )
            zeroization["wiped"].append(
                f"transferred_sealed_buffers:{purged_transferred['sealed_buffers']}"
            )

            result["zeroized"] = True
            result["items_lost_to_zeroize"] = unsent_items
            result["zeroization"] = zeroization

            self._log(
                {
                    "event": "ZEROIZE",
                    "seq": packet.get("seq"),
                    "unsent_items": unsent_items,
                }
            )

        result["vault"] = self.vault.summary()

        if self.phase == "PROTECT":
            self._remember_terminal_result(result)

        return result

    # ---------- evacuation ----------

    def _evacuate(
        self,
        lat: float,
        lon: float,
        now: float,
    ) -> dict[str, Any]:
        kind, dest_id, keys = self._pick_destination(
            lat,
            lon,
            now,
        )

        if kind is None or dest_id is None or keys is None:
            self._log(
                {
                    "event": "NO_DESTINATION",
                }
            )

            return {
                "destination": None,
                "kind": None,
                "moved": 0,
                "moved_ids": [],
                "peer_decision": self.peer_decision.to_dict(),
                "transfer_status": self._priority_transfer_status(),
                "chunk_loss_count": 0,
                "retransmissions": 0,
            }

        spent = 0
        moved = []
        dropped_chunks_before = self.transport.dropped_chunks
        retransmissions = 0
        final_destination = dest_id
        final_kind = kind

        for item in self.vault.pending():
            context = TransferContext(
                drone_id=settings.network.drone_id,
                mission_id=settings.hem.mission_id,
                priority_class=PRIORITY_NAMES.get(
                    item.priority,
                    str(item.priority),
                ),
                protocol_version=settings.hem.protocol_version,
            )
            byte_budget = max(0, self.budget - spent)
            progress = self.transfer_progress.get(item.item_id)
            ok, progress, stats = self._send_to_destination(
                item,
                keys,
                kind,
                dest_id,
                context,
                progress,
                byte_budget,
            )
            self.transfer_progress[item.item_id] = progress
            state = TransferState(str(stats["transfer_state"]))
            self.transfer_states[item.item_id] = state

            if (
                not ok
                and kind == "BASE"
                and stats["failure_reason"]
                in ("chunk_ack_timeout", "manifest_ack_timeout")
            ):
                peer_decision = self._select_peer(lat, lon, now)
                if peer_decision.chosen_peer is not None:
                    peer = peer_decision.chosen_peer
                    peer_id = peer.peer_id
                    peer_keys = self._session(peer_id, peer.secret, now)
                    if peer_keys is not None:
                        base_stats = stats
                        final_destination = peer_id
                        final_kind = "PEER"
                        kind = "PEER"
                        dest_id = peer_id
                        keys = peer_keys
                        self.transport.resume_to_peer(
                            peer_id,
                            item.item_id,
                            progress.acknowledged,
                        )
                        ok, progress, peer_stats = self._send_to_destination(
                            item,
                            peer_keys,
                            "PEER",
                            peer_id,
                            context,
                            progress,
                            (
                                None
                                if byte_budget is None
                                else max(
                                    0,
                                    byte_budget - int(stats["bytes_sent"]),
                                )
                            ),
                        )
                        stats = {
                            **peer_stats,
                            "sent": int(base_stats["sent"]) + int(peer_stats["sent"]),
                            "bytes_sent": int(base_stats["bytes_sent"])
                            + int(peer_stats["bytes_sent"]),
                            "retries": int(base_stats["retries"])
                            + int(peer_stats["retries"]),
                        }
                        self.transfer_progress[item.item_id] = progress
                        state = TransferState(str(stats["transfer_state"]))
                        self.transfer_states[item.item_id] = state

            spent += int(stats["bytes_sent"])
            retransmissions += int(stats["retries"])

            if ok:
                self.vault.mark_transferred(item.item_id)
                moved.append(item.item_id)

                if final_kind == "PEER" and final_destination in self.peers.peers:
                    self.peers.peers[final_destination].accepted_bytes += item.size

                self._log(
                    {
                        "event": "TRANSFERRED",
                        "item": item.item_id,
                        "dest": final_destination,
                        "kind": final_kind,
                        **stats,
                    }
                )
            else:
                self._log(
                    {
                        "event": (
                            "TRANSFER_PARTIAL"
                            if stats["transfer_state"] == TransferState.PARTIAL.value
                            else "TRANSFER_FAILED"
                        ),
                        "item": item.item_id,
                        "dest": final_destination,
                        **stats,
                    }
                )
                break

            if stats["failure_reason"] == "budget_exhausted":
                break

            if spent >= self.budget:
                break

        return {
            "destination": final_destination,
            "kind": final_kind,
            "moved": len(moved),
            "moved_ids": moved,
            "peer_decision": self.peer_decision.to_dict(),
            "transfer_status": self._priority_transfer_status(),
            "chunk_loss_count": (self.transport.dropped_chunks - dropped_chunks_before),
            "retransmissions": retransmissions,
        }

    def _select_peer(self, lat: float, lon: float, now: float) -> PeerDecision:
        """Return the deterministic scored peer decision after validating TOTP."""
        decision = self.peers.select(
            lat,
            lon,
            now,
            lambda peer: self._session(peer.peer_id, peer.secret, now) is not None,
        )
        self.peer_decision = decision
        return decision

    def _send_to_destination(
        self,
        item: DataItem,
        keys: SessionKeys,
        kind: str,
        dest_id: str,
        context: TransferContext,
        progress: TransferProgress | None,
        byte_budget: int | None,
    ) -> tuple[bool, TransferProgress, dict[str, int | str]]:
        send: Callable[[str, int, bytes], object | None]
        send_manifest: Callable[[str, exfil.ChunkManifest], object | None]
        if kind == "BASE":
            send = self.transport.send_to_base
            send_manifest = self.transport.send_manifest_to_base
        else:
            send = lambda item_id, index, blob: self.transport.send_to_peer(
                dest_id,
                item_id,
                index,
                blob,
            )
            send_manifest = lambda item_id, manifest: (
                self.transport.send_manifest_to_peer(
                    dest_id,
                    item_id,
                    manifest,
                )
            )
        plaintext = (
            self.vault.open_for_transfer(item.item_id) if progress is None else None
        )
        try:
            ok, new_progress, stats = exfil.send_item(
                item,
                keys,
                send,
                send_manifest,
                context,
                progress=progress,
                byte_budget=byte_budget,
                destination_id=dest_id,
                retry_delay=self.transport.retry_delay,
                sleep=self.transport.sleep_fn,
                plaintext=plaintext,
            )
        finally:
            if plaintext is not None:
                plaintext[:] = b"\x00" * len(plaintext)
                plaintext.clear()
        return ok, new_progress, stats

    def _priority_transfer_status(self) -> dict[str, str]:
        """Summarize every configured priority using explicit terminal states."""
        status_by_priority: dict[str, str] = {}
        items_by_priority: dict[int, list[DataItem]] = {}
        for item in self.vault.items:
            items_by_priority.setdefault(item.priority, []).append(item)

        for priority, items in items_by_priority.items():
            priority_name = PRIORITY_NAMES.get(priority, str(priority))
            states = [
                self.transfer_states.get(
                    item.item_id,
                    TransferState.PARTIAL,
                )
                for item in items
            ]
            if all(state is TransferState.DELIVERED for state in states):
                status = TransferState.DELIVERED
            elif any(
                state in (TransferState.DELIVERED, TransferState.PARTIAL)
                for state in states
            ):
                status = TransferState.PARTIAL
            else:
                status = TransferState.FAILED
            status_by_priority[priority_name] = status.value
        return status_by_priority

    # ---------- audit logging ----------

    def _log(self, event: dict[str, Any]) -> None:
        safe_event = _scrub_log_value(event)
        if not isinstance(safe_event, dict):
            raise TypeError("HEM audit events must be dictionaries")
        self.events.append(safe_event)
        self._log_writer.append(
            event_type=str(safe_event.get("event") or "HEM_EVENT").upper(),
            severity=str(safe_event.get("severity") or "INFO"),
            details=safe_event,
            trust=safe_event.get("trust"),
            state=safe_event.get("phase") or safe_event.get("hem_phase"),
        )

    def session_salt(self, dest_id: str) -> bytes:
        return self.session_keys[dest_id][1]
