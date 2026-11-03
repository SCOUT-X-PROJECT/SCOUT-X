import os
import sys
import time
from pathlib import Path
from typing import Iterable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from simulation.config import PROJECT_ROOT, settings
from simulation.hem import (
    HEMController,
    DataVault,
    PeerRegistry,
    Peer,
    SimTransport,
)
from simulation.hem import exfil
from simulation.hem.vault import CRITICAL, SENSITIVE, ROUTINE


BASE_SECRET = os.urandom(settings.hem.hkdf_key_size_bytes)

LAT, LON = 12.9716, 77.5946


def fresh(
    loss: float = 0.0,
    base_up: bool = True,
    peers: Iterable[Peer] = (),
    seed: int = 17,
) -> tuple[DataVault, PeerRegistry, SimTransport, HEMController]:
    v = DataVault()

    v.add(
        "target_photo_01",
        CRITICAL,
        os.urandom(3000),
    )

    v.add(
        "route_log",
        SENSITIVE,
        os.urandom(2500),
    )

    v.add(
        "weather_scan",
        ROUTINE,
        os.urandom(4000),
    )

    reg = PeerRegistry()

    for p in peers:
        reg.update(p)

    t = SimTransport(
        loss_rate=loss,
        base_up=base_up,
        seed=seed,
        sleep_fn=lambda _delay: None,
    )

    c = HEMController(
        v,
        reg,
        t,
        BASE_SECRET,
        log_path=(
            PROJECT_ROOT / settings.logging.directory / settings.logging.hem_test_log
        ),
    )

    return v, reg, t, c


def pkt(seq: int, trust: float, response: str = "MONITOR") -> dict[str, object]:
    return {
        "seq": seq,
        "trust_score": trust,
        "response": response,
        "gps": {
            "lat": LAT,
            "lon": LON,
        },
    }


def good_peer(
    pid: str = "drone-B",
    trust: float = 0.9,
    link: float = 0.8,
    dlat: float = 0.005,
) -> Peer:
    return Peer(
        pid,
        LAT + dlat,
        LON,
        trust,
        link,
        os.urandom(settings.hem.hkdf_key_size_bytes),
        last_seen=time.time(),
    )


def test_standby_does_nothing() -> None:
    v, _, _, c = fresh()

    r = c.on_packet(pkt(1, 1.0))

    assert r["hem_phase"] == "STANDBY"
    assert v.summary() == {"STORED": 3}


def test_hem_phase_boundaries_match_readme() -> None:
    _, _, _, c = fresh()

    assert c._target_phase(0.80, None) == "STANDBY"
    assert c._target_phase(0.799999, None) == "PREPARE"
    assert c._target_phase(0.50, None) == "PREPARE"
    assert c._target_phase(0.499999, None) == "EVACUATE"
    assert c._target_phase(0.20, None) == "PROTECT"


def test_prepare_seals_but_doesnt_send() -> None:
    v, _, t, c = fresh()
    plaintext_before = bytes(v.get("target_photo_01").plaintext or b"")

    r = c.on_packet(pkt(2, 0.7))

    assert r["hem_phase"] == "PREPARE"
    assert v.summary() == {"SEALED": 3}
    assert v.get("target_photo_01").plaintext is None
    transfer_buffer = v.open_for_transfer("target_photo_01")
    assert bytes(transfer_buffer) == plaintext_before
    transfer_buffer[:] = b"\x00" * len(transfer_buffer)
    transfer_buffer.clear()
    assert not t.base_inbox


def test_vault_rejects_duplicate_ids_and_does_not_expose_sealed_plaintext() -> None:
    vault = DataVault()
    vault.add("protected", CRITICAL, b"private mission data")
    vault.seal("protected")

    assert vault.get("protected").plaintext is None
    with pytest.raises(ValueError, match="duplicate vault item id"):
        vault.add("protected", CRITICAL, b"replacement")

    vault.mark_transferred("protected")
    with pytest.raises(RuntimeError, match="not available"):
        vault.open_for_transfer("protected")


def test_hem_session_requires_destination_bound_transport_proof() -> None:
    class ReplayProofTransport(SimTransport):
        proof: bytes | None = None

        def request_authentication_proof(
            self,
            principal_id: str,
            challenge: str,
            secret: bytes,
            timestamp: int,
        ) -> bytes | None:
            if self.proof is None:
                self.proof = super().request_authentication_proof(
                    principal_id,
                    challenge,
                    secret,
                    timestamp,
                )
            return self.proof

    secret = os.urandom(settings.hem.hkdf_key_size_bytes)
    transport = ReplayProofTransport(seed=3)
    first = HEMController(DataVault(), PeerRegistry(), transport, secret)
    assert first._session("base", secret, time.time()) is not None

    restarted = HEMController(DataVault(), PeerRegistry(), transport, secret)
    assert restarted._session("base", secret, time.time()) is None


def test_evacuate_to_base_in_priority_order() -> None:
    v, _, t, c = fresh()
    plaintext_before = bytes(v.get("target_photo_01").plaintext or b"")

    result = c.on_packet(pkt(3, 0.45))

    assert result["transfer_status"] == {
        "CRITICAL": "DELIVERED",
        "SENSITIVE": "DELIVERED",
        "ROUTINE": "DELIVERED",
    }

    first = [e["item"] for e in c.events if e["event"] == "TRANSFERRED"]

    assert first[0] == "target_photo_01"

    keys = c.session_keys["base"][0]

    got = exfil.receive_item(
        "target_photo_01",
        t.base_inbox["target_photo_01"],
        keys,
        t.base_manifests["target_photo_01"],
    )

    assert got == plaintext_before


def test_budget_limits_per_cycle() -> None:
    v, _, _, c = fresh()

    c.budget = 6000

    r = c.on_packet(pkt(4, 0.4))

    assert 0 < r["moved"] < 3


def test_chunk_budget_does_not_allow_lower_priority_preemption() -> None:
    _, _, transport, controller = fresh()
    controller.budget = settings.hem.chunk_size

    result = controller.on_packet(pkt(40, 0.4))

    assert result["transfer_status"]["CRITICAL"] == "PARTIAL"
    assert result["transfer_status"]["SENSITIVE"] == "PARTIAL"
    assert transport.acknowledgements
    assert {
        item_id for _destination, item_id, _index in transport.acknowledgements
    } == {"target_photo_01"}


def test_lower_priority_waits_until_critical_chunks_are_delivered() -> None:
    _, _, transport, controller = fresh()
    controller.budget = settings.hem.chunk_size

    for sequence in range(3):
        controller.on_packet(pkt(44 + sequence, 0.4))

    assert {
        item_id for _destination, item_id, _index in transport.acknowledgements
    } == {"target_photo_01"}
    assert controller.transfer_states["target_photo_01"].value == "DELIVERED"

    controller.on_packet(pkt(47, 0.4))

    assert transport.acknowledgements[-1][1] == "route_log"


def test_priority_transfer_status_is_reported_for_every_class() -> None:
    _, _, _, controller = fresh()
    controller.budget = 1

    result = controller.on_packet(pkt(41, 0.4))

    assert result["transfer_status"] == {
        "CRITICAL": "PARTIAL",
        "SENSITIVE": "PARTIAL",
        "ROUTINE": "PARTIAL",
    }


def test_base_down_falls_back_to_peer() -> None:
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer()],
    )

    r = c.on_packet(pkt(5, 0.4))

    assert r["kind"] == "PEER"
    assert r["destination"] == "drone-B"
    assert r["moved"] >= 1


def test_base_mid_transfer_fallback_resumes_acknowledged_chunks() -> None:
    class BaseFailsAfterOneChunk(SimTransport):
        acknowledged_base_chunks = 0

        def send_to_base(self, item_id: str, idx: int, blob: bytes):
            if not self.base_up:
                return None
            ack = super().send_to_base(item_id, idx, blob)
            if ack is not None:
                self.acknowledged_base_chunks += 1
                if self.acknowledged_base_chunks == 1:
                    self.base_up = False
            return ack

    vault = DataVault()
    vault.add("critical", CRITICAL, os.urandom(settings.hem.chunk_size * 2 + 5))
    peer = good_peer()
    registry = PeerRegistry()
    registry.update(peer)
    transport = BaseFailsAfterOneChunk(
        seed=29,
        sleep_fn=lambda _delay: None,
    )
    controller = HEMController(
        vault,
        registry,
        transport,
        BASE_SECRET,
        log_path=PROJECT_ROOT
        / settings.logging.directory
        / settings.logging.hem_test_log,
    )

    expected_plaintext = bytes(vault.get("critical").plaintext or b"")
    result = controller.on_packet(pkt(42, 0.4))

    assert result["destination"] == peer.peer_id
    assert result["transfer_status"]["CRITICAL"] == "DELIVERED"
    peer_chunks = transport.peer_inboxes[peer.peer_id]["critical"]
    assert {index for index, _blob in peer_chunks} == {0, 1, 2}
    peer_send_indices = [
        index
        for destination, item_id, index in transport.acknowledgements
        if destination == peer.peer_id and item_id == "critical"
    ]
    assert peer_send_indices == [1, 2]
    restored = exfil.receive_item(
        "critical",
        peer_chunks,
        controller.session_keys["base"][0],
        transport.peer_manifests[peer.peer_id]["critical"],
    )
    assert restored == expected_plaintext


def test_untrusted_peer_refused() -> None:
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer(trust=0.4)],
    )

    r = c.on_packet(pkt(6, 0.4))

    assert r["destination"] is None
    assert r["moved"] == 0
    rejected = r["peer_decision"]["rejected_peers"]
    assert rejected[0]["peer_id"] == "drone-B"
    assert "below_trust_floor" in rejected[0]["reasons"]


def test_far_peer_refused() -> None:
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer(dlat=0.5)],
    )

    r = c.on_packet(pkt(7, 0.4))

    assert r["destination"] is None
    assert "above_max_distance" in r["peer_decision"]["rejected_peers"][0]["reasons"]


def test_peer_score_is_explained_and_ties_break_by_peer_id() -> None:
    last_seen = time.time()
    first = good_peer(pid="drone-A")
    second = good_peer(pid="drone-B")
    first.last_seen = last_seen
    second.last_seen = last_seen
    registry = PeerRegistry()
    registry.update(second)
    registry.update(first)
    decision = registry.select(
        LAT,
        LON,
        time.time(),
        lambda _peer: True,
    )

    assert decision.chosen_peer is first
    assert decision.chosen_score is not None
    assert decision.scored_peers[0].factors["totp_validated"] == 1.0
    assert decision.to_dict()["chosen_peer"] == "drone-A"


def test_peer_decision_explains_link_recency_and_totp_rejections() -> None:
    registry = PeerRegistry()
    registry.update(good_peer(pid="weak-link", link=0.1))
    stale = good_peer(pid="stale")
    stale.last_seen -= settings.hem.peer_stale_limit_seconds + 1
    registry.update(stale)
    registry.update(good_peer(pid="bad-totp"))

    decision = registry.select(
        LAT,
        LON,
        time.time(),
        lambda peer: peer.peer_id != "bad-totp",
    )
    reasons = {peer.peer_id: peer.reasons for peer in decision.rejected_peers}

    assert "below_link_quality_floor" in reasons["weak-link"]
    assert "stale_peer" in reasons["stale"]
    assert "totp_not_validated" in reasons["bad-totp"]


def test_lossy_link_retransmits() -> None:
    v, _, t, c = fresh(loss=0.3)

    result = c.on_packet(pkt(8, 0.4))

    assert any(e["event"] == "TRANSFERRED" and e["retries"] > 0 for e in c.events)
    assert c.events[-1]["transfer_state"] == "DELIVERED"
    assert result["chunk_loss_count"] > 0
    assert result["retransmissions"] > 0


def test_exhausted_retries_report_failed_priority_state() -> None:
    _, _, _, controller = fresh(loss=1.0, seed=3)

    result = controller.on_packet(pkt(43, 0.4))

    assert result["transfer_status"]["CRITICAL"] == "FAILED"
    assert (
        controller.transfer_progress["target_photo_01"].attempts[0]
        == settings.hem.retry_limit + 1
    )


def test_transport_loss_tamper_and_backoff_are_seed_reproducible() -> None:
    first = SimTransport(loss_rate=0.5, tamper_rate=0.25, seed=99)
    second = SimTransport(loss_rate=0.5, tamper_rate=0.25, seed=99)

    assert [first._drop() for _ in range(10)] == [second._drop() for _ in range(10)]
    first_delays = [first.retry_delay(index) for index in range(5)]
    second_delays = [second.retry_delay(index) for index in range(5)]
    assert first_delays == second_delays
    for attempt, delay in enumerate(first_delays):
        base = min(
            settings.hem.retry_backoff_base_seconds * (2**attempt),
            settings.hem.retry_backoff_max_seconds,
        )
        spread = base * settings.hem.retry_jitter_fraction
        assert base - spread <= delay <= base + spread
    assert first._maybe_tamper(b"chunk") == second._maybe_tamper(b"chunk")


def test_tampered_chunk_rejected_by_receiver() -> None:
    v, _, t, c = fresh()

    t.tampering = True

    c.on_packet(pkt(9, 0.4))

    from cryptography.exceptions import InvalidTag

    with pytest.raises((InvalidTag, ValueError)):
        exfil.receive_item(
            "target_photo_01",
            t.base_inbox["target_photo_01"],
            c.session_keys["base"][0],
            t.base_manifests["target_photo_01"],
        )


def test_protect_zeroizes_after_final_pass() -> None:
    v, _, t, c = fresh()

    r = c.on_packet(
        pkt(
            10,
            0.15,
            "ISOLATE_DRONE",
        )
    )

    assert r["hem_phase"] == "PROTECT"
    assert r["zeroized"]
    assert v.zeroized
    assert set(v.summary()) == {"PURGED"}
    assert len([e for e in c.events if e["event"] == "TRANSFERRED"]) == 3
    assert r["zeroization"]["wiped"]
    assert "physical or forensic erasure" in r["zeroization"]["could_not_verify"]
    assert c.base_secret is None


def test_zeroize_overwrites_owned_mutable_secrets_and_reports_limits() -> None:
    peer = good_peer()
    vault, registry, _, controller = fresh(base_up=False, peers=[peer])
    controller._session(peer.peer_id, peer.secret, time.time())
    vault.add("extra", CRITICAL, b"secret payload")
    plaintext_ref = vault.get("extra").plaintext
    vault_key_ref = vault._key
    peer_secret_ref = peer.secret
    session_keys_ref = controller.session_keys[peer.peer_id][0]
    base_secret_ref = controller.base_secret

    result = controller.zeroize()

    assert plaintext_ref == bytearray()
    assert vault_key_ref == bytearray()
    assert peer_secret_ref == bytearray()
    assert base_secret_ref == bytearray()
    assert peer.secret is None
    assert controller.base_secret is None
    assert session_keys_ref.encryption == bytearray()
    assert controller.session_keys == {}
    assert controller._totp_replay_guard._used_codes == {}
    assert "vault_key_buffer" in result["wiped"]
    assert "base_secret_buffer" in result["wiped"]
    assert result["could_not_verify"]


def test_protect_with_no_destination_still_burns_data() -> None:
    v, _, t, c = fresh(base_up=False)

    r = c.on_packet(
        pkt(
            11,
            0.1,
            "FORCE_LAND",
        )
    )

    assert r["zeroized"]
    assert r["items_lost_to_zeroize"] == 3
    assert set(v.summary()) == {"PURGED"}


def test_protect_still_obeys_strict_transfer_budget() -> None:
    vault = DataVault()
    vault.add(
        "critical",
        CRITICAL,
        os.urandom(settings.hem.chunk_size * 3),
    )
    transport = SimTransport(seed=12, sleep_fn=lambda _delay: None)
    controller = HEMController(
        vault,
        PeerRegistry(),
        transport,
        BASE_SECRET,
        per_cycle_budget=settings.hem.chunk_size,
        log_path=PROJECT_ROOT
        / settings.logging.directory
        / settings.logging.hem_test_log,
    )

    result = controller.on_packet(pkt(48, 0.1, "ISOLATE_DRONE"))

    assert result["zeroized"]
    transfer_event = next(
        event
        for event in controller.events
        if event["event"] in ("TRANSFER_FAILED", "TRANSFER_PARTIAL")
    )
    assert transfer_event["bytes_sent"] <= settings.hem.chunk_size
    assert result["zeroization"]["wiped"]
    assert result["transfer_status"]["CRITICAL"] == "PARTIAL"


def test_hysteresis_no_flapping() -> None:
    v, _, _, c = fresh()

    c.on_packet(pkt(12, 0.45))

    assert c.on_packet(pkt(13, 0.55))["hem_phase"] == "EVACUATE"

    assert c.on_packet(pkt(14, 0.75))["hem_phase"] == "EVACUATE"
    assert c.on_packet(pkt(15, 0.75))["hem_phase"] == "EVACUATE"
    assert c.on_packet(pkt(16, 0.75))["hem_phase"] == "PREPARE"


def test_protect_is_one_way() -> None:
    v, _, _, c = fresh()

    c.on_packet(pkt(15, 0.1))

    assert c.on_packet(pkt(16, 1.0))["hem_phase"] == "PROTECT"


if __name__ == "__main__":
    tests = [
        value
        for name, value in globals().items()
        if name.startswith("test_") and callable(value)
    ]

    failures = 0

    for test in tests:
        try:
            test()
            print("PASS", test.__name__)

        except Exception as e:
            failures += 1
            print("FAIL", test.__name__, repr(e))

    if failures:
        sys.exit(1)

    print(f"\nALL TESTS PASSED: {len(tests)}")
