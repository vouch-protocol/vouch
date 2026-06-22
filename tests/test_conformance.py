"""Conformance runner: the L1 level must fully pass against the reference SDK."""

from vouch.conformance import Status, run_conformance


def test_l1_fully_passes():
    report = run_conformance()
    l1 = report.results["L1"]
    failures = [(r.name, r.detail) for r in l1 if r.status is not Status.PASS]
    assert not failures, f"L1 checks did not all pass: {failures}"
    assert report.achieved == "L1"


def test_validity_window_rejects_expired():
    from vouch.conformance import check_validity_window

    assert check_validity_window().status is Status.PASS


def test_nonce_replay_detects_reuse():
    from vouch.conformance import check_nonce_replay

    assert check_nonce_replay().status is Status.PASS
