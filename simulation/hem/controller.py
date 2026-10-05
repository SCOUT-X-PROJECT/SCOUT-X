"""
controller.py - the decision brain of the Handoff and Exfiltration Module (HEM).

It watches the trust score that the rest of SCOUT-X already computes and walks
through four phases. Phases only escalate while trust is falling; going back
down needs trust to recover past a margin, so a noisy score can't flip us around.

    STANDBY  (T >= 0.8)   nothing to do
    PREPARE  (T <  0.8)   seal everything at rest, take a peer/base snapshot
    EVACUATE (T <  0.5)   move data out: base first, else best peer, most important first
    PROTECT  (T <= 0.2 or FORCE_LAND/ISOLATE)  last pass, then purge + zeroize

Destination rule: base is preferred only if its link is up AND the authenticated
handshake passes. Otherwise the best eligible peer. If neither exists we stay
sealed and wait; PROTECT still zeroizes so nothing readable falls into hostile hands.
"""
import json
import time
from . import exfil
from .peers import totp, verify_totp, PeerRegistry

PHASES = ["STANDBY", "PREPARE", "EVACUATE", "PROTECT"]
RECOVER_MARGIN = 0.1


class HEMController:
    def __init__(self, vault, peers: PeerRegistry, transport, base_secret: bytes,
                 peer_secrets=None, log_path="hem_log.json", per_cycle_budget=20_000):
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
        cur_i, want_i = PHASES.index(self.phase), PHASES.index(want)

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
                exfil.derive_session_key(secret, salt, dest_id),
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
            return ("BASE", "base", self.base_secret)

        for peer, dist in self.peers.eligible(my_lat, my_lon, now):
            if verify_totp(
                peer.secret,
                totp(peer.secret, now),
                now
            ):
                return ("PEER", peer.peer_id, peer.secret)

        return (None, None, None)

    # ---------- main entry ----------
    def on_packet(self, packet, now=None):
        """Call once per telemetry cycle with the enriched packet from receiver.py."""
        now = now if now is not None else time.time()

        trust = float(packet.get("trust_score", 1.0))
        response = packet.get("response")

        new_phase = self._next_phase(trust, response)
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

        if self.phase in ("PREPARE", "EVACUATE", "PROTECT"):
            self.vault.seal_all()

        if self.phase in ("EVACUATE", "PROTECT"):
            gps = packet.get("gps", {})
            result.update(
                self._evacuate(
                    gps.get("lat", 0.0),
                    gps.get("lon", 0.0),
                    now
                )
            )

        if self.phase == "PROTECT":
            self.vault.purge_transferred()

            left = len(self.vault.pending())

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

        key = self._session(dest_id, secret)

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

        spent, moved = 0, []

        # In PROTECT we ignore the budget: it's now or never.
        unlimited = self.phase == "PROTECT"

        for item in self.vault.pending():
            if not unlimited and spent + item.size > self.budget:
                break

            ok, stats = exfil.send_item(
                item,
                key,
                send
            )

            if ok:
                self.vault.mark_transferred(item.item_id)
                spent += item.size
                moved.append(item.item_id)

                if kind == "PEER":
                    self.peers.peers[dest_id].accepted_bytes += item.size

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

    def session_salt(self, dest_id):
        return self.session_keys[dest_id][1]

    def _log(self, entry):
        entry["t"] = time.time()
        self.events.append(entry)

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass