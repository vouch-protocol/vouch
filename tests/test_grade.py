"""Tests for the single-agent self-check grader."""

from vouch import grade as g


def _signals(**overrides):
    s = g.empty_signals()
    s.update(overrides)
    return s


def test_full_identity_is_grade_a():
    report = g.grade_signals(_signals(has_did=True, has_verification_method=True), domain="a.com")
    assert report.grade == "A"
    assert report.score == 100


def test_did_without_key_is_grade_c():
    # Resolvable DID (60) but no usable verification method.
    report = g.grade_signals(_signals(has_did=True, has_verification_method=False))
    assert report.score == 60
    assert report.grade == "C"


def test_nothing_is_grade_f():
    report = g.grade_signals(_signals())
    assert report.score == 0
    assert report.grade == "F"


def test_fixes_target_missing_pieces():
    report = g.grade_signals(_signals())
    blob = " ".join(report.fixes).lower()
    assert "did:web" in blob
    assert "verificationmethod" in blob
    assert "ml-dsa" in blob


def test_grade_a_still_suggests_pq_and_revocation():
    # Even an A agent gets pointers for the extra signals it lacks.
    report = g.grade_signals(_signals(has_did=True, has_verification_method=True))
    blob = " ".join(report.fixes).lower()
    assert "ml-dsa" in blob  # post-quantum suggestion
    assert "revocation" in blob


def test_badge_svg_reflects_grade():
    report = g.grade_signals(_signals(has_did=True, has_verification_method=True), domain="a.com")
    svg = g.badge_svg(report)
    assert svg.startswith("<svg")
    assert "A (100)" in svg
    assert g.GRADE_COLORS["A"] in svg


def test_badge_svg_f_is_red():
    report = g.grade_signals(_signals())
    svg = g.badge_svg(report)
    assert g.GRADE_COLORS["F"] in svg


def test_report_to_dict_round_trips():
    report = g.grade_signals(_signals(has_did=True, has_verification_method=True), domain="a.com")
    d = report.to_dict()
    assert d["grade"] == "A"
    assert d["domain"] == "a.com"
    assert d["breakdown"]["resolvable_did"] == 60
