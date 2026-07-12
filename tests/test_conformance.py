"""Conformance runner: L1 through L3 must fully pass against the reference SDK."""

from vouch import conformance
from vouch.conformance import Status, run_conformance


def test_all_levels_pass():
    report = run_conformance()
    failures = [
        (level, r.name, r.status.value, r.detail)
        for level, results in report.results.items()
        for r in results
        if r.status is not Status.PASS
    ]
    assert not failures, f"conformance checks did not all pass: {failures}"
    assert report.achieved == "L3"


def test_each_check_passes():
    checks = [
        conformance.check_canonicalization,
        conformance.check_sign_verify,
        conformance.check_validity_window,
        conformance.check_nonce_replay,
        conformance.check_revocation,
        conformance.check_delegation_narrowing,
        conformance.check_sidecar_allow_deny,
        conformance.check_audit_trail,
        conformance.check_hybrid_pq,
        conformance.check_heartbeat,
        conformance.check_validator_quorum,
    ]
    for check in checks:
        result = check()
        assert result.status is Status.PASS, f"{result.name}: {result.detail}"
