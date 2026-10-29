
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

import json
import time

from . import exfil
from .peers import totp, verify_totp, PeerRegistry


PHASES = [
    "STANDBY",
    "PREPARE",
    "EVACUATE",
    "PROTECT",
]

RECOVER_MARGIN = 0.1


class HEMController:
    def __init__(
        self,
        vault,
        peers: PeerRegistry,
        transport,
        base_secret: bytes,
        peer_secrets=None,
        log_path="hem_log.json",
        per_cycle_budget=20_000,
    ):
        self.vault = vault
        self.peers = peers
        self.transport = transport
        self.base_secret = base_secret
        self.log_path = log_path
        self.budget = per_cycle_budget

        self.phase = "STANDBY"
        self.session_keys = {}
        self.events = []

        # Preserve the final protection result after zeroization.
        self._terminal_result = None

    # ---------- phase logic ----------

    def _target_phase(self, trust, response):
        if (
            response in ("FORCE_LAND", "ISOLATE_DRONE")
            or trust <= 0.2
        ):
            return "PROTECT"

        if trust < 0.5:
            return "EVACUATE"

        if trust < 0.8:
            return "PREPARE"

        return "STANDBY"

    def _next_phase(self, trust, response):
        want = self._target_phase(trust, response)

        cur_i = PHASES.index(self.phase)
        want_i = PHASES.index(want)

        # Escalation is immediate.
        if want_i > cur_i:
            return want

        # PROTECT is terminal for this vault instance.
        if self.phase == "PROTECT":
            return "PROTECT"

        # Recovery requires a margin above the current threshold.
        if want_i < cur_i:
            floor = {
                "PREPARE": 0.8,
                "EVACUATE": 0.5,
            }.get(self.phase, 0.0)

            if trust >= floor + RECOVER_MARGIN:
                return want

        return self.phase

    # ---------- destinations ----------

    def _session(self, dest_id, secret):
        if dest_id not in self.session_keys:
            import os

            salt = os.urandom(16)

            self.session_keys[dest_id] = (
                exfil.derive_session_key(
                    secret,
                    salt,
                    dest_id,
                ),
                salt,
            )

        return self.session_keys[dest_id][0]

    def _pick_destination(self, my_lat, my_lon, now):
        if (
            self.transport.base_up
            and verify_totp(
                self.base_secret,
                totp(self.base_secret, now),
                now,
            )
        ):
            return "BASE", "base", self.base_secret

        for peer, dist in self.peers.eligible(
            my_lat,
            my_lon,
            now,
        ):
            if verify_totp(
                peer.secret,
                totp(peer.secret, now),
                now,
            ):
                return "PEER", peer.peer_id, peer.secret

        return None, None, None

    # ---------- GPS handling ----------

    @staticmethod
    def _gps_coordinates(gps):
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

    def _remember_terminal_result(self, result):
        """Cache the final result so later packets retain the outcome."""
        self._terminal_result = dict(result)

    def _terminal_result_for_packet(self, packet, trust):
        """Return the cached result with current packet metadata."""
        if self._terminal_result is None:
            # Handles a vault that was already zeroized before this
            # controller received its first packet.
            result = {
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

        result = dict(self._terminal_result)
        result["seq"] = packet.get("seq")
        result["trust"] = round(trust, 2)
        result["hem_phase"] = "PROTECT"
        result["zeroized"] = True

        return result

    # ---------- main entry ----------

    def on_packet(self, packet, now=None):
        now = time.time() if now is None else now

        try:
            trust = float(packet.get("trust_score", 1.0))
        except (TypeError, ValueError):
            trust = 1.0

        # Fail closed for invalid trust values.
        if not 0.0 <= trust <= 1.0:
            trust = 0.0

        response = packet.get("response")

        # Once the vault is destroyed, never process it as a new
        # mission or imply that the data can be recovered.
        if self.vault.zeroized:
            self.phase = "PROTECT"
            return self._terminal_result_for_packet(packet, trust)

        new_phase = self._next_phase(trust, response)
        changed = new_phase != self.phase
        self.phase = new_phase

        result = {
            "seq": packet.get("seq"),
            "hem_phase": self.phase,
            "trust": round(trust, 2),
        }

        if changed:
            self._log({
                "event": "PHASE_CHANGE",
                **result,
            })

        if self.phase in ("PREPARE", "EVACUATE", "PROTECT"):
            self.vault.seal_all()

        if self.phase in ("EVACUATE", "PROTECT"):
            lat, lon = self._gps_coordinates(
                packet.get("gps", [0.0, 0.0])
            )

            result.update(
                self._evacuate(lat, lon, now)
            )

        if self.phase == "PROTECT":
            self.vault.purge_transferred()

            unsent_items = len(self.vault.pending())
            self.vault.zeroize()

            result["zeroized"] = True
            result["items_lost_to_zeroize"] = unsent_items

            self._log({
                "event": "ZEROIZE",
                "seq": packet.get("seq"),
                "unsent_items": unsent_items,
            })

        result["vault"] = self.vault.summary()

        if self.phase == "PROTECT":
            self._remember_terminal_result(result)

        return result

    # ---------- evacuation ----------

    def _evacuate(self, lat, lon, now):
        kind, dest_id, secret = self._pick_destination(
            lat,
            lon,
            now,
        )

        if kind is None:
            self._log({
                "event": "NO_DESTINATION",
            })

            return {
                "destination": None,
                "kind": None,
                "moved": 0,
                "moved_ids": [],
            }

        key = self._session(dest_id, secret)

        if kind == "BASE":
            send = self.transport.send_to_base
        else:
            send = (
                lambda item_id, nonce, blob:
                self.transport.send_to_peer(
                    dest_id,
                    item_id,
                    nonce,
                    blob,
                )
            )

        spent = 0
        moved = []

        # PROTECT prioritizes transfer attempts, but it cannot
        # guarantee delivery when transport or authentication fails.
        unlimited = self.phase == "PROTECT"

        for item in self.vault.pending():
            if (
                not unlimited
                and spent + item.size > self.budget
            ):
                break

            ok, stats = exfil.send_item(
                item,
                key,
                send,
            )

            if ok:
                self.vault.mark_transferred(item.item_id)
                spent += item.size
                moved.append(item.item_id)

                if kind == "PEER":
                    self.peers.peers[
                        dest_id
                    ].accepted_bytes += item.size

                self._log({
                    "event": "TRANSFERRED",
                    "item": item.item_id,
                    "dest": dest_id,
                    "kind": kind,
                    **stats,
                })
            else:
                self._log({
                    "event": "TRANSFER_FAILED",
                    "item": item.item_id,
                    "dest": dest_id,
                    **stats,
                })
                break

        return {
            "destination": dest_id,
            "kind": kind,
            "moved": len(moved),
            "moved_ids": moved,
        }

    # ---------- audit logging ----------

    def _log(self, event):
        self.events.append(event)

        try:
            with open(
                self.log_path,
                "a",
                encoding="utf-8",
            ) as file:
                file.write(json.dumps(event) + "\n")
        except OSError:
            # HEM operation should not crash solely because the
            # optional local audit file cannot be written.
            pass

    def session_salt(self, dest_id):
        return self.session_keys[dest_id][1]
