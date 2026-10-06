"""
controller.py - the decision brain of the Handoff and Exfiltration Module (HEM).

It watches the trust score that the rest of SCOUT-X already computes and walks
through four phases.

    STANDBY  (T >= 0.8)
    PREPARE  (T < 0.8)
    EVACUATE (T < 0.5)
    PROTECT  (T <= 0.2 or FORCE_LAND/ISOLATE)

Destination rule:
base first if available and authenticated, otherwise the best eligible peer.
If neither exists, data remains sealed. PROTECT still zeroizes.
"""

import json
import time

from . import exfil
from .peers import totp, verify_totp, PeerRegistry


PHASES = [
    "STANDBY",
    "PREPARE",
    "EVACUATE",
    "PROTECT"
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
        per_cycle_budget=20_000
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

    # ---------- phase logic ----------

    def _target_phase(self, trust, response):

        if response in ("FORCE_LAND", "ISOLATE_DRONE") or trust <= 0.2:
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

        if want_i > cur_i:
            return want

        if want_i < cur_i and self.phase != "PROTECT":

            floor = {
                "PREPARE": 0.8,
                "EVACUATE": 0.5
            }.get(self.phase, 0.0)

            if trust >= floor + RECOVER_MARGIN:
                return want

        return self.phase

    # ---------- destinations ----------

    def _session(self, dest_id, secret):

        if dest_id not in self.session_keys:

            salt = __import__("os").urandom(16)

            self.session_keys[dest_id] = (
                exfil.derive_session_key(
                    secret,
                    salt,
                    dest_id
                ),
                salt
            )

        return self.session_keys[dest_id][0]

    def _pick_destination(self, my_lat, my_lon, now):

        if (
            self.transport.base_up
            and verify_totp(
                self.base_secret,
                totp(self.base_secret, now),
                now
            )
        ):
            return (
                "BASE",
                "base",
                self.base_secret
            )

        for peer, dist in self.peers.eligible(
            my_lat,
            my_lon,
            now
        ):

            if verify_totp(
                peer.secret,
                totp(peer.secret, now),
                now
            ):
                return (
                    "PEER",
                    peer.peer_id,
                    peer.secret
                )

        return (
            None,
            None,
            None
        )

    # ---------- GPS handling ----------

    @staticmethod
    def _gps_coordinates(gps):
        """
        Accept both SCOUT-X packet formats:

        Dictionary:
            {"lat": 12.9716, "lon": 77.5946}

        List:
            [12.9716, 77.5946]
        """

        if isinstance(gps, dict):

            return (
                float(gps.get("lat", 0.0)),
                float(gps.get("lon", 0.0))
            )

        if isinstance(gps, (list, tuple)):

            if len(gps) >= 2:

                return (
                    float(gps[0]),
                    float(gps[1])
                )

        return 0.0, 0.0

    # ---------- main entry ----------

    def on_packet(self, packet, now=None):

        now = now if now is not None else time.time()

        trust = float(
            packet.get(
                "trust_score",
                1.0
            )
        )

        response = packet.get("response")

        new_phase = self._next_phase(
            trust,
            response
        )

        changed = new_phase != self.phase

        self.phase = new_phase

        result = {
            "seq": packet.get("seq"),
            "hem_phase": self.phase,
            "trust": round(trust, 2)
        }

        if changed:

            self._log({
                "event": "PHASE_CHANGE",
                **result
            })

        if self.vault.zeroized:

            result["vault"] = self.vault.summary()

            return result

        if self.phase in (
            "PREPARE",
            "EVACUATE",
            "PROTECT"
        ):

            self.vault.seal_all()

        if self.phase in (
            "EVACUATE",
            "PROTECT"
        ):

            gps = packet.get(
                "gps",
                [0.0, 0.0]
            )

            lat, lon = self._gps_coordinates(gps)

            result.update(
                self._evacuate(
                    lat,
                    lon,
                    now
                )
            )

        if self.phase == "PROTECT":

            self.vault.purge_transferred()

            left = len(
                self.vault.pending()
            )

            self.vault.zeroize()

            result["zeroized"] = True

            result["items_lost_to_zeroize"] = left

            self._log({
                "event": "ZEROIZE",
                "seq": packet.get("seq"),
                "unsent_items": left
            })

        result["vault"] = self.vault.summary()

        return result

    # ---------- evacuation ----------

    def _evacuate(self, lat, lon, now):

        kind, dest_id, secret = self._pick_destination(
            lat,
            lon,
            now
        )

        if kind is None:

            self._log({
                "event": "NO_DESTINATION"
            })

            return {
                "destination": None,
                "moved": 0
            }

        key = self._session(
            dest_id,
            secret
        )

        send = (
            self.transport.send_to_base
            if kind == "BASE"
            else (
                lambda i, n, b:
                self.transport.send_to_peer(
                    dest_id,
                    i,
                    n,
                    b
                )
            )
        )

        spent = 0
        moved = []

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
                send
            )

            if ok:

                self.vault.mark_transferred(
                    item.item_id
                )

                spent += item.size

                moved.append(
                    item.item_id
                )

                if kind == "PEER":

                    self.peers.peers[
                        dest_id
                    ].accepted_bytes += item.size

                self._log({
                    "event": "TRANSFERRED",
                    "item": item.item_id,
                    "dest": dest_id,
                    "kind": kind,
                    **stats
                })

            else:

                self._log({
                    "event": "TRANSFER_FAILED",
                    "item": item.item_id,
                    "dest": dest_id,
                    **stats
                })

                break

        return {
            "destination": dest_id,
            "kind": kind,
            "moved": len(moved),
            "moved_ids": moved
        }

    def _log(self, event):

        self.events.append(event)

        try:

            with open(
                self.log_path,
                "a",
                encoding="utf-8"
            ) as file:

                file.write(
                    json.dumps(event)
                    + "\n"
                )

        except OSError:
            pass

    def session_salt(self, dest_id):

        return self.session_keys[
            dest_id
        ][1]