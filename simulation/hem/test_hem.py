import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from simulation.hem import (
    HEMController,
    DataVault,
    PeerRegistry,
    Peer,
    SimTransport,
)
from simulation.hem import exfil
from simulation.hem.vault import CRITICAL, SENSITIVE, ROUTINE


BASE_SECRET = b"base-shared-secret-demo"

LAT, LON = 12.9716, 77.5946


def fresh(loss=0.0, base_up=True, peers=()):
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
    )

    c = HEMController(
        v,
        reg,
        t,
        BASE_SECRET,
        log_path="hem_test_log.json",
    )

    return v, reg, t, c


def pkt(seq, trust, response="MONITOR"):
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
    pid="drone-B",
    trust=0.9,
    link=0.8,
    dlat=0.005,
):
    return Peer(
        pid,
        LAT + dlat,
        LON,
        trust,
        link,
        b"peer-secret-" + pid.encode(),
        last_seen=time.time(),
    )


def test_standby_does_nothing():
    v, _, _, c = fresh()

    r = c.on_packet(pkt(1, 1.0))

    assert r["hem_phase"] == "STANDBY"
    assert v.summary() == {"STORED": 3}


def test_prepare_seals_but_doesnt_send():
    v, _, t, c = fresh()

    r = c.on_packet(pkt(2, 0.7))

    assert r["hem_phase"] == "PREPARE"
    assert v.summary() == {"SEALED": 3}
    assert not t.base_inbox


def test_evacuate_to_base_in_priority_order():
    v, _, t, c = fresh()

    c.on_packet(pkt(3, 0.45))

    first = [
        e["item"]
        for e in c.events
        if e["event"] == "TRANSFERRED"
    ]

    assert first[0] == "target_photo_01"

    key = exfil.derive_session_key(
        BASE_SECRET,
        c.session_salt("base"),
        "base",
    )

    got = exfil.receive_item(
        "target_photo_01",
        t.base_inbox["target_photo_01"],
        key,
    )

    assert got == v.get("target_photo_01").plaintext


def test_budget_limits_per_cycle():
    v, _, _, c = fresh()

    c.budget = 6000

    r = c.on_packet(pkt(4, 0.4))

    assert 0 < r["moved"] < 3


def test_base_down_falls_back_to_peer():
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer()],
    )

    r = c.on_packet(pkt(5, 0.4))

    assert r["kind"] == "PEER"
    assert r["destination"] == "drone-B"
    assert r["moved"] >= 1


def test_untrusted_peer_refused():
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer(trust=0.4)],
    )

    r = c.on_packet(pkt(6, 0.4))

    assert r["destination"] is None
    assert r["moved"] == 0


def test_far_peer_refused():
    v, _, t, c = fresh(
        base_up=False,
        peers=[good_peer(dlat=0.5)],
    )

    r = c.on_packet(pkt(7, 0.4))

    assert r["destination"] is None


def test_lossy_link_retransmits():
    v, _, t, c = fresh(loss=0.3)

    c.on_packet(pkt(8, 0.4))

    assert any(
        e["event"] == "TRANSFERRED"
        and e["retries"] > 0
        for e in c.events
    )


def test_tampered_chunk_rejected_by_receiver():
    v, _, t, c = fresh()

    t.tampering = True

    c.on_packet(pkt(9, 0.4))

    key = exfil.derive_session_key(
        BASE_SECRET,
        c.session_salt("base"),
        "base",
    )

    from cryptography.exceptions import InvalidTag

    try:
        exfil.receive_item(
            "target_photo_01",
            t.base_inbox["target_photo_01"],
            key,
        )

        assert False, "tampered data should not decrypt"

    except InvalidTag:
        pass


def test_protect_zeroizes_after_final_pass():
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
    assert len(t.base_inbox) == 3


def test_protect_with_no_destination_still_burns_data():
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


def test_hysteresis_no_flapping():
    v, _, _, c = fresh()

    c.on_packet(pkt(12, 0.45))

    assert c.on_packet(
        pkt(13, 0.55)
    )["hem_phase"] == "EVACUATE"

    assert c.on_packet(
        pkt(14, 0.75)
    )["hem_phase"] == "PREPARE"


def test_protect_is_one_way():
    v, _, _, c = fresh()

    c.on_packet(pkt(15, 0.1))

    assert c.on_packet(
        pkt(16, 1.0)
    )["hem_phase"] == "PROTECT"


if __name__ == "__main__":
    tests = [
        value
        for name, value in globals().items()
        if name.startswith("test_")
        and callable(value)
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